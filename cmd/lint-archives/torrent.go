package main

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/anacrolix/torrent/bencode"
	"github.com/anacrolix/torrent/metainfo"
)

// Compare torrent metadata with inventory sizes (-1 means unknown), without
// downloading ZIP pieces or validating the unread torrent suffix.
func lintTorrentObjects(client *http.Client, url string, sizes map[string]int64) []string {
	if url == "" {
		return nil
	}
	info, pieceBytes, err := fetchTorrentPrefix(client, url)
	if err != nil {
		return []string{fmt.Sprintf("Failed to read torrent metadata prefix: %v", err)}
	}

	var diagnostics []string
	if !torrentSafePath([]string{info.Name}) ||
		(info.NameUtf8 != "" && !torrentSafePath([]string{info.NameUtf8})) {
		diagnostics = append(diagnostics, "Torrent has an unsafe or empty name")
	}
	if info.Length < 0 || (info.Files != nil && info.Length != 0) {
		diagnostics = append(diagnostics, "Torrent has an invalid single-file length or mixed single/multi-file layout")
	}
	if info.Files != nil && len(info.Files) == 0 {
		diagnostics = append(diagnostics, "Torrent has an empty multi-file layout")
	}
	if info.PieceLength <= 0 {
		diagnostics = append(diagnostics, "Torrent piece length must be positive")
	}
	if pieceBytes%20 != 0 {
		diagnostics = append(diagnostics, "Torrent piece hashes are not a multiple of 20 bytes")
	}

	files := info.Files
	if files == nil {
		files = []metainfo.FileInfo{{Path: []string{info.BestName()}, Length: info.Length}}
	}
	seen := make(map[string]bool)
	var total int64
	layoutValid := true
	for _, file := range files {
		name := strings.Join(file.BestPath(), "/")
		if !torrentSafePath(file.Path) ||
			(len(file.PathUtf8) != 0 && !torrentSafePath(file.PathUtf8)) {
			diagnostics = append(diagnostics, fmt.Sprintf("Torrent has unsafe file path %q", name))
		}
		if seen[name] {
			diagnostics = append(diagnostics, fmt.Sprintf("Torrent repeats file %q", name))
		}
		seen[name] = true
		size, listed := sizes[name]
		if listed && size < -1 {
			diagnostics = append(diagnostics, fmt.Sprintf("%s: invalid expected object size %d", name, size))
		} else if listed && size >= 0 && file.Length != size {
			diagnostics = append(diagnostics, fmt.Sprintf(
				"%s: torrent length %d differs from object size %d", name, file.Length, size))
		}
		if file.Length < 0 || file.Length > math.MaxInt64-total {
			diagnostics = append(diagnostics, fmt.Sprintf("%s: negative torrent length or total length overflow", name))
			layoutValid = false
			continue
		}
		total += file.Length
	}
	if layoutValid && info.PieceLength > 0 {
		count := total / info.PieceLength
		if total%info.PieceLength != 0 {
			count++
		}
		if count != pieceBytes/20 {
			diagnostics = append(diagnostics, fmt.Sprintf(
				"Torrent has %d piece hashes, expected %d for %d bytes", pieceBytes/20, count, total))
		}
	}
	var missing []string
	for name := range sizes {
		if !seen[name] {
			missing = append(missing, name)
		}
	}
	slices.Sort(missing)
	if len(missing) != 0 {
		suffix := ""
		if len(missing) > 5 {
			suffix = " ..."
		}
		diagnostics = append(diagnostics, fmt.Sprintf("Torrent is missing %d files: %s%s",
			len(missing), strings.Join(missing[:min(5, len(missing))], ", "), suffix))
	}
	return diagnostics
}

func torrentSafePath(parts []string) bool {
	if len(parts) == 0 {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, "/\\:\x00") {
			return false
		}
		for _, c := range part {
			if c < 0x20 || c == 0x7f {
				return false
			}
		}
	}
	return true
}

const torrentPrefixLimit = 1 << 20

// Stop at info.pieces instead of downloading its potentially huge hash array
// or any ZIP payloads. Bencoded dictionary keys are sorted, so the v1 file list, names,
// lengths, and piece length all precede pieces. The unread suffix is not
// validated: only its declared piece count is checked against the file sizes.
func fetchTorrentPrefix(client *http.Client, url string) (metainfo.Info, int64, error) {
	var info metainfo.Info
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return info, 0, err
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", torrentPrefixLimit-1))
	req.Header.Set("Accept-Encoding", "identity")
	response, err := client.Do(req)
	if err != nil {
		return info, 0, err
	}
	defer response.Body.Close()
	total := response.ContentLength
	switch response.StatusCode {
	case http.StatusOK: // Range ignored: still stop reading at pieces or the cap.
	case http.StatusPartialContent:
		ranges := response.Header.Values("Content-Range")
		if len(ranges) != 1 {
			return info, 0, fmt.Errorf("expected one Content-Range")
		}
		m := rangeZipContentRange.FindStringSubmatch(ranges[0])
		if m == nil {
			return info, 0, fmt.Errorf("invalid Content-Range %q", ranges[0])
		}
		start, e1 := strconv.ParseInt(m[1], 10, 64)
		end, e2 := strconv.ParseInt(m[2], 10, 64)
		size, e3 := strconv.ParseInt(m[3], 10, 64)
		if e1 != nil || e2 != nil || e3 != nil || start != 0 || size <= 0 || end != min(size, torrentPrefixLimit)-1 ||
			(response.ContentLength >= 0 && response.ContentLength != end+1) {
			return info, 0, fmt.Errorf("invalid Content-Range or length for torrent prefix")
		}
		total = size
	default:
		return info, 0, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	if response.Uncompressed || response.Header.Get("Content-Encoding") != "" {
		return info, 0, fmt.Errorf("expected an unencoded torrent prefix")
	}
	limited := &io.LimitedReader{R: response.Body, N: torrentPrefixLimit}
	r := bufio.NewReader(limited)
	if _, err := torrentDictionaryPrefix(r, "info"); err != nil {
		return info, 0, err
	}
	fields, err := torrentDictionaryPrefix(r, "pieces")
	if err != nil {
		return info, 0, err
	}
	_, files := fields["files"]
	_, length := fields["length"]
	if files == length {
		return info, 0, fmt.Errorf("torrent needs exactly one of files or length")
	}
	// Keep field/type decoding in the existing bencode/metainfo library. No
	// piece-hash string is fabricated or allocated, regardless of its size.
	encoded, err := bencode.Marshal(fields)
	if err != nil {
		return info, 0, err
	}
	if err := bencode.Unmarshal(encoded, &info); err != nil {
		return info, 0, err
	}
	var digits []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			return info, 0, fmt.Errorf("read pieces length: %w", err)
		}
		if b == ':' {
			break
		}
		if b < '0' || b > '9' || len(digits) == 19 {
			return info, 0, fmt.Errorf("invalid pieces string length")
		}
		digits = append(digits, b)
	}
	pieceBytes, err := strconv.ParseInt(string(digits), 10, 64)
	if err != nil || (len(digits) > 1 && digits[0] == '0') {
		return info, 0, fmt.Errorf("invalid pieces string length")
	}
	consumed := torrentPrefixLimit - limited.N - int64(r.Buffered())
	if total >= 0 && (consumed > total-2 || pieceBytes > total-consumed-2) {
		return info, 0, fmt.Errorf("declared pieces string does not fit in torrent")
	}
	return info, pieceBytes, nil
}

// Read complete key/value pairs up to stop, leaving its value unread. This is
// a dictionary boundary walk, not a byte search: comments and other strings can
// themselves contain "info" or "pieces". The library decodes keys and values.
func torrentDictionaryPrefix(r *bufio.Reader, stop string) (map[string]bencode.Bytes, error) {
	if marker, err := r.ReadByte(); err != nil || marker != 'd' {
		return nil, fmt.Errorf("expected dictionary containing %q", stop)
	}
	decoder := bencode.NewDecoder(r)
	decoder.MaxStrLen = torrentPrefixLimit
	fields := make(map[string]bencode.Bytes)
	previous := ""
	for {
		var key string
		if err := decoder.Decode(&key); err != nil {
			return nil, fmt.Errorf("torrent prefix (limit %d bytes): %w", torrentPrefixLimit, err)
		}
		if len(fields) > 0 && key <= previous {
			return nil, fmt.Errorf("unsorted or duplicate torrent key %q", key)
		}
		if key == stop {
			return fields, nil
		}
		if key > stop {
			return nil, fmt.Errorf("missing torrent key %q before %q", stop, key)
		}
		var value bencode.Bytes
		if err := decoder.Decode(&value); err != nil {
			return nil, fmt.Errorf("torrent prefix (limit %d bytes): %w", torrentPrefixLimit, err)
		}
		fields[key] = value
		previous = key
	}
}
