package main

import (
	"archive/zip"
	"bufio"
	"compress/flate"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"net/http"
	"regexp"
	"strconv"
	"sync"
)

var errRangeUnsupported = errors.New("HTTP Range requests are unsupported")

const (
	rangeZipWindowSize  = 1 << 20
	rangeZipFetchLimit  = 64 << 20
	rangeZipMemberLimit = 16 << 20
)

var rangeZipContentRange = regexp.MustCompile(`^bytes ([0-9]+)-([0-9]+)/([0-9]+)$`)

// openRangeZip probes Range support before using archive/zip. Only an initial
// 200 permits the caller to fall back; it is closed without reading its body.
// The caller owns the client's timeout and transport.
func openRangeZip(client *http.Client, url string) (*zip.Reader, error) {
	r := &rangeZipReaderAt{client: client, url: url, readAhead: true, windows: make(map[int64][]byte)}
	if _, err := r.fetchRange(0, 1, true); err != nil {
		return nil, err
	}
	z, err := zip.NewReader(r, r.size)
	if err != nil {
		return nil, fmt.Errorf("read ZIP directory: %w", err)
	}
	// Prefetch only while parsing the directory. Member reads request exactly
	// what archive/zip needs, without fetching unrelated member payloads.
	// This flag is finalized before publishing the reader to concurrent callers.
	r.readAhead = false
	return z, nil
}

func smallZipFiles(z *zip.Reader) fileReader {
	// archive/zip confines this reader to the compressed member. Buffer only
	// that member, not adjacent ZIP data, to avoid a GET per 4 KiB flate refill.
	z.RegisterDecompressor(zip.Deflate, func(r io.Reader) io.ReadCloser {
		return flate.NewReader(bufio.NewReaderSize(r, 64<<10))
	})
	return func(name string) ([]byte, error) {
		for _, f := range z.File {
			if f.Name != name {
				continue
			}
			if f.FileInfo().IsDir() {
				return nil, fmt.Errorf("ZIP member %q is a directory", name)
			}
			if f.UncompressedSize64 > rangeZipMemberLimit {
				return nil, fmt.Errorf("ZIP member %q exceeds %d bytes", name, rangeZipMemberLimit)
			}
			if f.CompressedSize64 > rangeZipFetchLimit {
				return nil, fmt.Errorf("ZIP member %q exceeds the compressed byte budget", name)
			}
			member, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("open ZIP member %q: %w", name, err)
			}
			defer member.Close()
			// The validated size lets stored members be read in one request.
			// Read one extra byte to reach EOF/checksum validation, or catch a
			// member that decompresses beyond its declared bounded size.
			data := make([]byte, int(f.UncompressedSize64)+1)
			n, err := io.ReadFull(member, data)
			if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
				return nil, fmt.Errorf("read ZIP member %q: %w", name, err)
			}
			if uint64(n) != f.UncompressedSize64 {
				return nil, fmt.Errorf("ZIP member %q has %d bytes, expected %d", name, n, f.UncompressedSize64)
			}
			data = data[:n]

			// archive/zip can skip checking a zero CRC without a descriptor.
			if crc32.ChecksumIEEE(data) != f.CRC32 {
				return nil, fmt.Errorf("read ZIP member %q: %w", name, zip.ErrChecksum)
			}
			return data, nil
		}
		return nil, fmt.Errorf("ZIP member %q: %w", name, fs.ErrNotExist)
	}
}

// Cached windows bound both network traffic and memory. Holding mu during fetches
// also prevents concurrent misses from consuming the budget more than once.
type rangeZipReaderAt struct {
	client    *http.Client
	url       string
	size      int64
	etag      string
	readAhead bool

	mu      sync.Mutex
	windows map[int64][]byte
	fetched int64
}

func (r *rangeZipReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative ZIP read offset: %d", off)
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= r.size {
		return 0, io.EOF
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for n < len(p) && off < r.size {
		var window []byte
		for start, data := range r.windows {
			if off >= start && off-start < int64(len(data)) {
				window = data[off-start:]
				break
			}
		}
		if window == nil {
			var err error
			length := int64(len(p) - n)
			if r.readAhead {
				length = rangeZipWindowSize
			}
			// Start at the requested offset, not a block boundary: metadata
			// reads need not fetch earlier, unrelated ZIP member data.
			window, err = r.fetchRange(off, min(length, r.size-off), false)
			if err != nil {
				return n, err
			}
			r.windows[off] = window
		}
		copied := copy(p[n:], window)
		n += copied
		off += int64(copied)
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// fetchRange is called either during the initial probe or with mu held.
func (r *rangeZipReaderAt) fetchRange(off, length int64, probe bool) ([]byte, error) {
	// Allow one extra byte to detect overlong bodies, even on failed requests.
	if length+1 > rangeZipFetchLimit-r.fetched {
		return nil, fmt.Errorf("ZIP exceeds %d fetched bytes", rangeZipFetchLimit)
	}
	req, err := http.NewRequest(http.MethodGet, r.url, nil)
	if err != nil {
		return nil, err
	}
	if probe {
		// A suffix probe learns the size without reading unrelated byte zero.
		req.Header.Set("Range", "bytes=-1")
	} else {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", off, off+length-1))
	}
	req.Header.Set("Accept-Encoding", "identity")
	if r.etag != "" {
		req.Header.Set("If-Match", r.etag)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if probe && resp.StatusCode == http.StatusOK {
		return nil, errRangeUnsupported
	}
	if resp.StatusCode != http.StatusPartialContent {
		return nil, fmt.Errorf("ZIP Range request: HTTP %d (expected 206)", resp.StatusCode)
	}
	if resp.Uncompressed {
		return nil, errors.New("ZIP Range response was transparently decompressed")
	}
	for _, encoding := range resp.Header.Values("Content-Encoding") {
		if encoding != "" {
			return nil, fmt.Errorf("ZIP Range response has Content-Encoding %q", encoding)
		}
	}
	values := resp.Header.Values("Content-Range")
	if len(values) != 1 {
		return nil, errors.New("ZIP Range response needs exactly one Content-Range")
	}
	m := rangeZipContentRange.FindStringSubmatch(values[0])
	if m == nil {
		return nil, fmt.Errorf("invalid ZIP Content-Range %q", values[0])
	}
	start, errStart := strconv.ParseInt(m[1], 10, 64)
	end, errEnd := strconv.ParseInt(m[2], 10, 64)
	total, errTotal := strconv.ParseInt(m[3], 10, 64)
	if probe {
		off = total - 1
	}
	if errStart != nil || errEnd != nil || errTotal != nil ||
		start != off || end != off+length-1 || total <= end {
		return nil, fmt.Errorf("invalid ZIP Content-Range %q for requested range", values[0])
	}
	if !probe && total != r.size {
		return nil, fmt.Errorf("ZIP size changed from %d to %d", r.size, total)
	}
	etag := resp.Header.Get("ETag")
	if r.etag != "" && etag != "" && etag != r.etag {
		return nil, errors.New("ZIP ETag changed")
	}
	if resp.ContentLength >= 0 && resp.ContentLength != length {
		return nil, fmt.Errorf("ZIP Range Content-Length is %d, expected %d", resp.ContentLength, length)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, length+1))
	r.fetched += int64(len(data))
	if err != nil {
		return nil, fmt.Errorf("read ZIP Range response: %w", err)
	}
	if int64(len(data)) != length {
		return nil, fmt.Errorf("ZIP Range body is %d bytes, expected %d", len(data), length)
	}
	if probe {
		r.size = total
		// Weak validators cannot pin a byte representation with If-Match.
		if len(etag) >= 2 && etag[0] == '"' && etag[len(etag)-1] == '"' {
			for i := 1; i < len(etag)-1; i++ {
				if etag[i] < 0x21 || etag[i] == '"' || etag[i] == 0x7f {
					return nil, errors.New("invalid strong ZIP ETag")
				}
			}
			r.etag = etag
		}
	}
	return data, nil
}
