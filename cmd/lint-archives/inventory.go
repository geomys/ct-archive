package main

import (
	"archive/zip"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"filippo.io/sunlight"
	"golang.org/x/mod/sumdb/tlog"
)

const archiveWidth = 256 * 256 * 256

// ZIP directory checks don't read tile bodies. Only Range-backed archives expose
// a directory; IA's extraction API is checked by reading the sampled members.
func lintZipInventory(files []*zip.File, index, size int64, allowMissingIssuers bool) []string {
	expected := map[string]bool{"README.txt": true, "checkpoint": true, "log.v3.json": true}
	add := func(t tlog.Tile) { expected[sunlight.TilePath(t)] = true }
	for _, tile := range tlog.NewTiles(sunlight.TileHeight, index*archiveWidth, min((index+1)*archiveWidth, size)) {
		if tile.L > 2 || tile.W != sunlight.TileWidth {
			continue
		}
		add(tile)
		if tile.L == 0 {
			tile.L = -1
			add(tile)
		}
	}
	for _, tile := range archiveGlobalTiles(size) {
		add(tile)
	}
	// Unlike partial hash tiles, the final partial DATA tile is only in its owner.
	if size%sunlight.TileWidth != 0 && index == (size-1)/archiveWidth {
		add(tlog.Tile{H: sunlight.TileHeight, L: -1, N: size / sunlight.TileWidth, W: int(size % sunlight.TileWidth)})
	}
	seen := make(map[string]bool, len(files))
	var unexpected, duplicates []string
	issuers := 0
	for _, file := range files {
		name := file.Name
		if file.FileInfo().IsDir() {
			continue
		}
		if seen[name] {
			duplicates = append(duplicates, name)
			continue
		}
		seen[name] = true
		if expected[name] {
			delete(expected, name)
			continue
		}
		if strings.HasPrefix(name, "tile/") {
			unexpected = append(unexpected, name)
		}
		if hash, ok := strings.CutPrefix(name, "issuer/"); ok {
			decoded, err := hex.DecodeString(hash)
			if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != hash {
				unexpected = append(unexpected, name)
			} else {
				issuers++
			}
		}
	}
	var missing []string
	for name := range expected {
		missing = append(missing, name)
	}
	var diagnostics []string
	for _, group := range []struct {
		label string
		names []string
	}{{"missing members", missing}, {"unexpected members", unexpected}, {"duplicate members", duplicates}} {
		if len(group.names) == 0 {
			continue
		}
		slices.Sort(group.names)
		diagnostics = append(diagnostics, fmt.Sprintf("ZIP directory has %d %s: %s", len(group.names), group.label, strings.Join(group.names[:min(5, len(group.names))], ", ")))
	}
	if !allowMissingIssuers && issuers == 0 {
		diagnostics = append(diagnostics, "ZIP directory has no issuer certificates")
	}
	return diagnostics
}

// Each ZIP replicates these few HASH tiles, including ones not needed for a
// particular sample's proof. Callers bound size to the 1,000-ZIP archive limit.
func archiveGlobalTiles(size int64) []tlog.Tile {
	var tiles []tlog.Tile
	for level := 0; level <= 5; level++ {
		hashes := size >> (sunlight.TileHeight * level)
		if level >= 3 {
			for n := int64(0); n*sunlight.TileWidth < hashes; n++ {
				tiles = append(tiles, tlog.Tile{H: sunlight.TileHeight, L: level, N: n, W: int(min(sunlight.TileWidth, hashes-n*sunlight.TileWidth))})
			}
		} else if width := int(hashes % sunlight.TileWidth); width != 0 {
			tiles = append(tiles, tlog.Tile{H: sunlight.TileHeight, L: level, N: hashes / sunlight.TileWidth, W: width})
		}
	}
	return tiles
}
