package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"

	"filippo.io/sunlight"
	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

type logInfo struct {
	LogID         *string `json:"log_id"`
	Key           []byte  `json:"key"`
	URL           string  `json:"url"`
	SubmissionURL string  `json:"submission_url"`
	MonitoringURL string  `json:"monitoring_url"`

	// object preserves all metadata fields for complete-copy comparisons.
	// Numbers remain json.Number so large integers do not lose precision.
	object map[string]any
}

type checkpoint struct {
	Origin string
	Size   int64
	Hash   tlog.Hash
	// Text includes all checkpoint extensions but excludes the signatures.
	Text string
	Raw  []byte
}

func fetchLogInfo(read fileReader) (logInfo, error) {
	var info logInfo
	data, err := read("log.v3.json")
	if err != nil {
		return info, fmt.Errorf("Failed to fetch log.v3.json: %w", err)
	}
	if err := json.Unmarshal(data, &info); err != nil {
		return logInfo{}, fmt.Errorf("Invalid JSON in log.v3.json: %w", err)
	}
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return logInfo{}, fmt.Errorf("Invalid JSON in log.v3.json: expected an object")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&info.object); err != nil {
		return logInfo{}, fmt.Errorf("Invalid JSON object in log.v3.json: %w", err)
	}
	return info, nil
}

func fetchCheckpoint(read fileReader) (checkpoint, error) {
	data, err := read("checkpoint")
	if err != nil {
		return checkpoint{}, fmt.Errorf("Failed to fetch checkpoint: %w", err)
	}
	// Open without verifiers validates the entire signed-note envelope, but
	// deliberately does not establish authenticity. Verification follows once
	// the archive's own public key is available.
	n, err := note.Open(data, note.VerifierList())
	var unverified *note.UnverifiedNoteError
	if errors.As(err, &unverified) {
		n, err = unverified.Note, nil
	}
	if err != nil {
		return checkpoint{}, fmt.Errorf("Invalid checkpoint note: %w", err)
	}
	c, err := torchwood.ParseCheckpoint(n.Text)
	if err != nil {
		return checkpoint{}, fmt.Errorf("Invalid checkpoint: %w", err)
	}
	if c.Origin == "" {
		return checkpoint{}, fmt.Errorf("Invalid checkpoint: empty origin")
	}
	if c.String() != n.Text {
		return checkpoint{}, fmt.Errorf("Invalid checkpoint: non-canonical checkpoint text")
	}
	return checkpoint{Origin: c.Origin, Size: c.N, Hash: c.Hash, Text: n.Text, Raw: data}, nil
}

func originFromURL(rawURL string) string {
	return strings.TrimRight(strings.TrimPrefix(strings.TrimPrefix(rawURL, "https://"), "http://"), "/")
}

func logOrigin(info logInfo) string {
	if info.URL != "" {
		return originFromURL(info.URL)
	}
	return originFromURL(info.SubmissionURL)
}

// readArchiveMetadata reads each member exactly once. Returned values can be
// used for cross-copy comparisons and tile sampling; diagnostics must not be
// ignored before treating their checkpoint as internally verified.
func readArchiveMetadata(read fileReader, origin string) (logInfo, checkpoint, []string) {
	var diagnostics []string
	info, infoErr := fetchLogInfo(read)
	if infoErr != nil {
		diagnostics = append(diagnostics, infoErr.Error())
	}
	cp, cpErr := fetchCheckpoint(read)
	if cpErr != nil {
		diagnostics = append(diagnostics, cpErr.Error())
	}
	if infoErr == nil {
		diagnostics = append(diagnostics, verifyArchiveMetadata(origin, info, cp)...)
	} else if cpErr == nil && origin != "" && cp.Origin != origin {
		diagnostics = append(diagnostics, fmt.Sprintf(
			"checkpoint origin '%s' does not match expected origin '%s'", cp.Origin, origin))
	}
	return info, cp, diagnostics
}

// verifyArchiveMetadata checks self-consistency with the archive's public key,
// not trust against an independent key list or checkpoint.
// A zero checkpoint (no Raw) denotes an earlier fetch/parse failure.
func verifyArchiveMetadata(origin string, info logInfo, cp checkpoint) []string {
	var diagnostics []string
	if info.URL == "" && (info.SubmissionURL == "" || info.MonitoringURL == "") {
		diagnostics = append(diagnostics,
			"Missing URLs in log.v3.json: expected either url or both submission_url and monitoring_url")
	}
	for _, field := range []struct{ name, value string }{
		{"url", info.URL}, {"submission_url", info.SubmissionURL}, {"monitoring_url", info.MonitoringURL},
	} {
		if field.value == "" {
			continue
		}
		u, err := url.ParseRequestURI(field.value)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") ||
			u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(field.value, "#") {
			diagnostics = append(diagnostics, fmt.Sprintf(
				"Invalid log.v3.json %s URL '%s': expected an absolute HTTP(S) log URL", field.name, field.value))
		}
	}
	expectedOrigin := logOrigin(info)
	if origin != "" && expectedOrigin != "" && expectedOrigin != origin {
		diagnostics = append(diagnostics, fmt.Sprintf(
			"log.v3.json URL origin '%s' does not match expected origin '%s'", expectedOrigin, origin))
	}
	if info.LogID == nil || *info.LogID == "" {
		diagnostics = append(diagnostics, "Missing log_id in log.v3.json")
	} else {
		id, err := base64.StdEncoding.DecodeString(*info.LogID)
		if err != nil || len(id) != sha256.Size || base64.StdEncoding.EncodeToString(id) != *info.LogID {
			diagnostics = append(diagnostics, "Invalid log.v3.json log_id: expected canonical base64 SHA-256")
		} else if digest := sha256.Sum256(info.Key); !bytes.Equal(id, digest[:]) {
			diagnostics = append(diagnostics, "log.v3.json log_id does not match SHA-256 of its public key")
		}
	}
	key, keyErr := x509.ParsePKIXPublicKey(info.Key)
	if keyErr != nil {
		diagnostics = append(diagnostics, fmt.Sprintf("Invalid log.v3.json public key: %v", keyErr))
	}
	if len(cp.Raw) == 0 {
		return diagnostics
	}
	if expectedOrigin != "" && cp.Origin != expectedOrigin {
		diagnostics = append(diagnostics, fmt.Sprintf(
			"checkpoint origin '%s' does not match log.v3.json URL origin '%s'", cp.Origin, expectedOrigin))
	}
	if origin != "" && cp.Origin != origin {
		diagnostics = append(diagnostics, fmt.Sprintf(
			"checkpoint origin '%s' does not match expected origin '%s'", cp.Origin, origin))
	}
	if cp.Size == 0 && cp.Hash != tlog.Hash(sha256.Sum256(nil)) {
		diagnostics = append(diagnostics, "Empty checkpoint tree has an incorrect root hash")
	}
	if keyErr == nil {
		// Bind the verifier to the metadata-derived origin, not to an arbitrary
		// signer name chosen by the checkpoint.
		v, err := sunlight.NewRFC6962Verifier(expectedOrigin, key)
		if err != nil {
			diagnostics = append(diagnostics, fmt.Sprintf("Invalid checkpoint verifier: %v", err))
		} else if n, err := note.Open(cp.Raw, note.VerifierList(v)); err != nil {
			diagnostics = append(diagnostics, fmt.Sprintf(
				"checkpoint signature does not verify with archive public key: %v", err))
		} else if n.Text != cp.Text {
			diagnostics = append(diagnostics, "Verified checkpoint text differs from parsed checkpoint")
		}
	}
	return diagnostics
}

// compareArchiveMetadata compares complete metadata copies. Signed-note bytes
// may differ (e.g. a different valid signature timestamp); the entire parsed
// checkpoint text, including extensions and root hash, must agree.
func compareArchiveMetadata(info logInfo, cp checkpoint, expectedInfo logInfo, expectedCheckpoint checkpoint) []string {
	diagnostics := compareLogInfo(info, expectedInfo, false)
	if info.object != nil && expectedInfo.object != nil && !reflect.DeepEqual(info.object, expectedInfo.object) {
		diagnostics = append(diagnostics, "log.v3.json complete metadata does not match reference metadata")
	}
	if cp.Origin != expectedCheckpoint.Origin || cp.Size != expectedCheckpoint.Size ||
		cp.Hash != expectedCheckpoint.Hash || cp.Text != expectedCheckpoint.Text {
		diagnostics = append(diagnostics, "checkpoint text (origin, size, root hash, or extensions) does not match reference checkpoint")
	}
	return diagnostics
}

// partial preserves the legacy IA metadata comparison, where unspecified
// expected fields are not evidence of absence. Cross-copy checks are complete.
func compareLogInfo(info, expected logInfo, partial bool) []string {
	var diagnostics []string
	actualID, expectedID := "", ""
	if info.LogID != nil {
		actualID = *info.LogID
	}
	if expected.LogID != nil {
		expectedID = *expected.LogID
	}
	if (!partial || expectedID != "") && (actualID != expectedID || (!partial && (info.LogID == nil) != (expected.LogID == nil))) {
		diagnostics = append(diagnostics, fmt.Sprintf(
			"log.v3.json log_id '%s' does not match expected log_id '%s'", actualID, expectedID))
	}
	if (!partial || expected.Key != nil) && !bytes.Equal(info.Key, expected.Key) {
		diagnostics = append(diagnostics, "log.v3.json public key does not match reference public key")
	}
	for _, field := range []struct{ name, actual, expected string }{
		{"url", info.URL, expected.URL},
		{"submission_url", info.SubmissionURL, expected.SubmissionURL},
		{"monitoring_url", info.MonitoringURL, expected.MonitoringURL},
	} {
		if partial && field.expected == "" {
			continue
		}
		if strings.TrimRight(field.actual, "/") != strings.TrimRight(field.expected, "/") {
			diagnostics = append(diagnostics, fmt.Sprintf(
				"log.v3.json %s '%s' does not match expected %s '%s'",
				field.name, field.actual, field.name, field.expected))
		}
	}
	return diagnostics
}
