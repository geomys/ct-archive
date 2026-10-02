package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/mod/sumdb/tlog"
)

// Non-IA archives expose metadata and numbered ZIPs directly under a URL prefix.
func lintPrefix(client *http.Client, e entry) []string {
	u, err := url.Parse(e.location)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") ||
		u.RawQuery != "" || u.Fragment != "" || len(strings.Fields(e.location)) != 1 {
		return []string{"Expected a single HTTP(S) URL prefix without a query or fragment"}
	}
	baseURL := strings.TrimRight(e.location, "/") + "/"
	info, cp, diagnostics := readArchiveMetadata(httpFiles(client, baseURL), e.origin)
	if len(diagnostics) != 0 {
		return diagnostics
	}
	n := zipCount(cp.Size)
	if n > 1000 {
		return []string{fmt.Sprintf("checkpoint implies %d ZIPs; at most 1000 supported", n)}
	}
	objects := make(map[string]int64)
	for i := int64(0); i < n; i++ {
		name := fmt.Sprintf("%03d.zip", i)
		size, err := headZip(client, baseURL+name)
		if err != nil {
			diagnostics = append(diagnostics, fmt.Sprintf("%s: %v", name, err))
		}
		objects[name] = size
	}
	readers := make(map[int64]fileReader)
	openZip := func(index int64) (fileReader, error) {
		if read := readers[index]; read != nil {
			return read, nil
		}
		name := fmt.Sprintf("%03d.zip", index)
		z, err := openRangeZip(client, baseURL+name)
		if err != nil {
			return nil, err
		}
		read := smallZipFiles(z)
		zi, zc, issues := readArchiveMetadata(read, e.origin)
		issues = append(issues, compareArchiveMetadata(zi, zc, info, cp)...)
		issues = append(issues, lintZipInventory(z.File, index, cp.Size, e.allowMissingIssuers)...)
		if len(issues) != 0 {
			return nil, fmt.Errorf("%s", strings.Join(issues, "; "))
		}
		readers[index] = read
		return read, nil
	}
	if n > 0 {
		// A server ignoring Range keeps standalone signature/metadata and HEAD
		// checks. Never fall back to consuming its full ZIP response.
		if _, err := openZip(0); err == nil {
			diagnostics = append(diagnostics, e.checkStage("tiles", func() []string {
				return lintTileSamples(openZip, tlog.Tree{N: cp.Size, Hash: cp.Hash}, e.allowMissingIssuers)
			})...)
		} else if err != errRangeUnsupported {
			diagnostics = append(diagnostics, fmt.Sprintf("000.zip: %v", err))
		}
	}
	// Without a directory listing, HEAD cannot establish absence of extra ZIPs.
	return append(diagnostics, e.checkStage("torrent metadata", func() []string { return lintTorrentObjects(client, e.torrentURL, objects) })...)
}

func headZip(client *http.Client, url string) (int64, error) {
	response, err := client.Head(url)
	if err != nil {
		return -1, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return -1, fmt.Errorf("HEAD returned HTTP %d", response.StatusCode)
	}
	if response.ContentLength == 0 {
		return 0, fmt.Errorf("ZIP is empty")
	}
	return response.ContentLength, nil
}
