// Command lint-archives checks a single archived Certificate Transparency log.
// It supports Internet Archive items and direct HTTP(S) archive prefixes.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

type entry struct {
	origin              string
	location            string
	torrentURL          string
	allowMissingIssuers bool
	logf                func(string, ...any)
}

func main() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: lint-archives -origin ORIGIN -url URL [-torrent URL] [-allow-missing-issuers]")
		flag.PrintDefaults()
	}
	var e entry
	flag.StringVar(&e.origin, "origin", "", "log origin")
	flag.StringVar(&e.location, "url", "", "archive URL or space-separated URLs")
	flag.StringVar(&e.torrentURL, "torrent", "", "torrent URL (optional)")
	flag.BoolVar(&e.allowMissingIssuers, "allow-missing-issuers", false, "allow documented legacy archives without issuer certificates")
	flag.Parse()
	if flag.NArg() != 0 || e.origin == "" || e.location == "" {
		flag.Usage()
		os.Exit(2)
	}
	errors, supported := lintArchive(&http.Client{Timeout: 30 * time.Second}, e)
	if !supported {
		fmt.Printf("SKIP %s: archive host not yet supported\n", e.origin)
		return
	}
	if len(errors) != 0 {
		fmt.Printf("FAIL %s\n", e.origin)
		for _, err := range errors {
			fmt.Printf("  %s\n", err)
		}
		os.Exit(1)
	}
	fmt.Printf("OK   %s\n", e.origin)
}

func lintArchive(client *http.Client, e entry) (diagnostics []string, supported bool) {
	switch {
	// Match anywhere so malformed formatting around IA links still gets checked.
	case strings.Contains(e.location, "https://archive.org/details/"):
		return lintIA(client, e), true
	case strings.HasPrefix(e.location, "https://"), strings.HasPrefix(e.location, "http://"):
		return lintPrefix(client, e), true
	default:
		return nil, false
	}
}

// Tests report expensive stages separately from admission-queue wait time.
func (e entry) checkStage(name string, check func() []string) []string {
	start := time.Now()
	defer func() {
		if e.logf != nil {
			e.logf("%s: %s", name, time.Since(start).Round(time.Millisecond))
		}
	}()
	return check()
}
