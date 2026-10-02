package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

// fileReader fetches a small file by name, independent of how it is served.
type fileReader func(name string) ([]byte, error)

// httpFiles handles both direct prefixes and IA's ZIP-member extraction URLs.
func httpFiles(client *http.Client, prefix string) fileReader {
	prefix = strings.TrimRight(prefix, "/") + "/"
	return func(name string) ([]byte, error) {
		return fetchLimited(client, prefix+name, rangeZipMemberLimit)
	}
}

func zipCount(size int64) int64 {
	const entriesPerZip = 256 * 256 * 256
	n := size / entriesPerZip
	if size%entriesPerZip > 0 {
		n++
	}
	return n
}

// fetch is for metadata and torrents, never ZIPs. Bound reads in case a
// misconfigured endpoint serves a ZIP (including one without Content-Length).
func fetch(client *http.Client, url string) ([]byte, error) {
	return fetchLimited(client, url, 64<<20)
}

func fetchLimited(client *http.Client, url string, limit int64) ([]byte, error) {
	response, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	if response.ContentLength > limit {
		return nil, fmt.Errorf("response exceeds %d bytes", limit)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response exceeds %d bytes", limit)
	}
	return data, nil
}
