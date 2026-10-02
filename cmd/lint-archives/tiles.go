package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"math/rand/v2"

	"filippo.io/sunlight"
	"filippo.io/torchwood"
	"github.com/google/certificate-transparency-go/x509"
	"golang.org/x/mod/sumdb/tlog"
)

// lintTileSamples checks against the archive's own checkpoint, not an
// independently trusted tree. Sample one random non-last DATA tile and the
// (possibly partial) last tile, with no duplicate and no DATA prefetching.
func lintTileSamples(openZip func(int64) (fileReader, error), tree tlog.Tree, allowMissingIssuers bool) []string {
	// The archiver caps archives at 1,000 ZIPs. This also bounds the number
	// of replicated high-level HASH members checked in each sampled ZIP.
	if tree.N < 0 || tree.N > 1000*archiveWidth {
		return []string{fmt.Sprintf("Invalid tree size for tile checks: %d", tree.N)}
	}
	if tree.N == 0 {
		if tree.Hash != tlog.Hash(sha256.Sum256(nil)) {
			return []string{"Empty tree has an incorrect root hash"}
		}
		return nil
	}
	last := (tree.N - 1) / sunlight.TileWidth
	samples := []int64{last}
	if last > 0 {
		samples = []int64{rand.Int64N(last), last}
	}
	var diagnostics []string
	readers := make(map[int64]*sampleTileFS)
	for _, n := range samples {
		tile := tlog.Tile{H: sunlight.TileHeight, L: -1, N: n,
			W: int(min(sunlight.TileWidth, tree.N-n*sunlight.TileWidth))}
		// Partial DATA tiles are only in their owner ZIP, unlike the
		// replicated partial HASH tiles and level 3+ proof tiles.
		zipIndex := n / (sunlight.TileWidth * sunlight.TileWidth)
		label := fmt.Sprintf("ZIP %03d tile %s", zipIndex, sunlight.TilePath(tile))
		files := readers[zipIndex]
		if files == nil {
			read, err := openZip(zipIndex)
			if err != nil {
				diagnostics = append(diagnostics, fmt.Sprintf("%s: open ZIP: %v", label, err))
				continue
			}
			if read == nil {
				diagnostics = append(diagnostics, label+": ZIP has no member reader")
				continue
			}
			files = &sampleTileFS{read: read, treeSize: tree.N, cache: make(map[string][]byte)}
			readers[zipIndex] = files
			if readme, err := files.ReadFile("README.txt"); err != nil {
				diagnostics = append(diagnostics, fmt.Sprintf("%s: read README.txt: %v", label, err))
			} else if len(readme) == 0 {
				diagnostics = append(diagnostics, label+": README.txt is empty")
			}
		}
		for _, diagnostic := range lintTileSample(tile, files, tree, allowMissingIssuers) {
			diagnostics = append(diagnostics, label+": "+diagnostic)
		}
	}
	return diagnostics
}

func lintTileSample(tile tlog.Tile, files *sampleTileFS, tree tlog.Tree, allowMissingIssuers bool) []string {
	tr, err := torchwood.NewTileFS(files, torchwood.WithTileFSTilePath(sunlight.TilePath))
	if err != nil {
		return []string{err.Error()}
	}
	ctx := context.Background()
	hr := torchwood.TileHashReaderWithContext(ctx, tree, tr)
	// Every ZIP must replicate these members, even ones a sampled leaf's
	// proof would never request. The library authenticates all their hashes.
	for _, global := range archiveGlobalTiles(tree.N) {
		if _, err := tlog.ReadTileData(global, hr); err != nil {
			return []string{fmt.Sprintf("authenticate global HASH tile %s: %v", sunlight.TilePath(global), err)}
		}
	}
	// Entry needs no proof hashes for a one-leaf tree. Independently ask the
	// library to authenticate the corresponding HASH member in all cases,
	// so its existence and exact width are checked even for that empty proof.
	hashTile := tile
	hashTile.L = 0
	if _, err := tlog.ReadTileData(hashTile, hr); err != nil {
		return []string{fmt.Sprintf("authenticate HASH tile: %v", err)}
	}
	sampleIndex := rand.IntN(tile.W)
	var sample *sunlight.LogEntry
	var offset int
	client, err := torchwood.NewClient(tr, torchwood.WithCutEntry(func(data []byte) ([]byte, tlog.Hash, []byte, error) {
		index := tile.N*sunlight.TileWidth + int64(offset)
		e, rest, err := sunlight.ReadTileLeafMaybeArchival(data)
		if err != nil {
			return nil, tlog.Hash{}, nil, fmt.Errorf("parse leaf %d: %w", index, err)
		}
		if !e.RFC6962ArchivalLeaf && e.LeafIndex != index {
			return nil, tlog.Hash{}, nil, fmt.Errorf("leaf %d has Static CT leaf index %d", index, e.LeafIndex)
		}
		if offset == tile.W-1 && len(rest) != 0 {
			return nil, tlog.Hash{}, nil, fmt.Errorf("%d trailing bytes after %d leaves", len(rest), tile.W)
		}
		if offset == sampleIndex {
			sample = e
		}
		offset++
		return data[:len(data)-len(rest)], tlog.RecordHash(e.MerkleTreeLeaf()), rest, nil
	}))
	if err != nil {
		return []string{err.Error()}
	}
	// Entries prefetches up to 50 DATA tiles. Entry fetches exactly this tile
	// and authenticates its requested leaf through a Merkle proof to tree.Hash.
	// Check every leaf; cache member reads so there is no repeated ZIP traffic.
	for i := range tile.W {
		index := tile.N*sunlight.TileWidth + int64(i)
		offset = 0
		if _, _, err := client.Entry(ctx, tree, index); err != nil {
			return []string{fmt.Sprintf("check leaf %d: %v", index, err)}
		}
	}
	if allowMissingIssuers {
		// README's dagger marks archives made without issuer/. Never skip
		// DATA parsing or HASH authentication for these archives.
		return nil
	}
	return lintSampleIssuers(files.ReadFile, sample, tile.N*sunlight.TileWidth+int64(sampleIndex))
}

// Check one entry's issuer references per tile, with a bounded fetch count.
// This checks content addressing and DER syntax, not PKI trust or validity.
func lintSampleIssuers(read fileReader, e *sunlight.LogEntry, leafIndex int64) []string {
	const maxIssuers = 16
	var diagnostics []string
	for _, fingerprint := range e.ChainFingerprints[:min(len(e.ChainFingerprints), maxIssuers)] {
		path := fmt.Sprintf("issuer/%x", fingerprint)
		data, err := read(path)
		if err != nil {
			diagnostics = append(diagnostics, fmt.Sprintf("leaf %d: read %s: %v", leafIndex, path, err))
			continue
		}
		if sha256.Sum256(data) != fingerprint {
			diagnostics = append(diagnostics, fmt.Sprintf("leaf %d: %s content SHA-256 does not match filename", leafIndex, path))
			continue
		}
		// The CT parser accepts historical certificates, returning non-fatal
		// errors alongside a usable certificate.
		if cert, err := x509.ParseCertificate(data); cert == nil {
			diagnostics = append(diagnostics, fmt.Sprintf("leaf %d: parse %s as DER X.509: %v", leafIndex, path, err))
		}
	}
	return diagnostics
}

// sampleTileFS adapts a bounded ZIP-member reader to NewTileFS. The archiver
// stores canonical HASH widths, while proofs can request narrower widths.
// NewTileFS does not handle this fallback, so resolve the canonical member,
// enforce its exact length, and trim it here. This is not a proof verifier:
// authentication is entirely delegated to torchwood.Client.
// Cached bytes stay untrusted and are authenticated by the client on each use.
type sampleTileFS struct {
	read     fileReader
	treeSize int64
	cache    map[string][]byte
}

func (*sampleTileFS) Open(name string) (fs.File, error) {
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
}

func (f *sampleTileFS) ReadFile(name string) ([]byte, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "read", Path: name, Err: fs.ErrInvalid}
	}
	tile, err := sunlight.ParseTilePath(name)
	isHash := err == nil && tile.L >= 0
	canonical := tile
	if isHash {
		if tile.L > 7 {
			return nil, fmt.Errorf("HASH tile %s is outside tree size %d", name, f.treeSize)
		}
		levelHashes := f.treeSize >> uint(tile.L*sunlight.TileHeight)
		if tile.N < 0 || tile.N > levelHashes/sunlight.TileWidth {
			return nil, fmt.Errorf("HASH tile %s is outside tree size %d", name, f.treeSize)
		}
		canonical.W = int(min(sunlight.TileWidth, levelHashes-tile.N*sunlight.TileWidth))
		if tile.W > canonical.W {
			return nil, fmt.Errorf("HASH tile %s exceeds canonical width %d", name, canonical.W)
		}
		name = sunlight.TilePath(canonical)
	}
	data, ok := f.cache[name]
	if !ok {
		data, err = f.read(name)
		if err != nil {
			return nil, err
		}
		if isHash && len(data) != canonical.W*tlog.HashSize {
			return nil, fmt.Errorf("HASH tile %s has %d bytes, want exactly %d", name, len(data), canonical.W*tlog.HashSize)
		}
		f.cache[name] = data
	}
	if isHash {
		data = data[:tile.W*tlog.HashSize]
	}
	return data, nil
}
