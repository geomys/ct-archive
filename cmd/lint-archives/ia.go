package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"golang.org/x/mod/sumdb/tlog"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var (
	iaIDPattern        = regexp.MustCompile(`https://archive\.org/details/([^\s|]+)`)
	iaExtensionPattern = regexp.MustCompile(`_ext[1-9]\d*$`)
)

// IA metadata fields can be either a string or a list of strings.
type iaStrings []string

func (s *iaStrings) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		*s = nil
		return nil
	}
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*s = []string{single}
		return nil
	}
	var list []string
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("expected a string or list of strings: %w", err)
	}
	*s = list
	return nil
}

func (s iaStrings) first() string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

type iaFile struct {
	Name   string          `json:"name"`
	Source string          `json:"source"`
	Size   json.RawMessage `json:"size"`
}

type iaItem struct {
	Server   string          `json:"server"`
	Dir      string          `json:"dir"`
	Metadata json.RawMessage `json:"metadata"`
	Files    []iaFile        `json:"files"`
}

type iaMetadata struct {
	Subject       iaStrings       `json:"subject"`
	Collection    iaStrings       `json:"collection"`
	LogID         iaStrings       `json:"ctlogid"`
	URL           iaStrings       `json:"cturl"`
	SubmissionURL iaStrings       `json:"ctsubmissionurl"`
	MonitoringURL iaStrings       `json:"ctmonitoringurl"`
	LogSize       json.RawMessage `json:"ctlogsize"`
}

// lintIA checks an archive, including its extension items. The
// caller owns the client's timeout and transport; every request uses it.
func lintIA(client *http.Client, e entry) []string {
	matches := iaIDPattern.FindAllStringSubmatch(e.location, -1)
	if len(matches) == 0 {
		return []string{"No Internet Archive item identifier found in URL"}
	}
	ids := make([]string, len(matches))
	locations := make([]string, len(matches))
	for i, match := range matches {
		ids[i] = match[1]
		locations[i] = "https://archive.org/details/" + ids[i]
	}

	var errors []string
	expectedLocation := strings.Join(locations, " ")
	if e.location != expectedLocation {
		errors = append(errors, fmt.Sprintf("Archive location should be '%s'", expectedLocation))
	}
	expectedExtensions := make([]string, len(ids)-1)
	for i := range expectedExtensions {
		expectedExtensions[i] = fmt.Sprintf("%s_ext%d", ids[0], i+1)
	}
	if !slices.Equal(ids[1:], expectedExtensions) {
		errors = append(errors, fmt.Sprintf(
			"Extension items must be named consecutively: expected %v, found %v",
			expectedExtensions, ids[1:]))
	}

	items := make([]iaItem, len(ids))
	fetchErrors := make([]error, len(ids))
	totalZips := 0
	for i, id := range ids {
		data, err := fetch(client, "https://archive.org/metadata/"+id)
		if err != nil {
			fetchErrors[i] = fmt.Errorf("Failed to fetch metadata: %w", err)
			continue
		}
		if err := json.Unmarshal(data, &items[i]); err != nil {
			fetchErrors[i] = fmt.Errorf("Invalid JSON in metadata: %w", err)
			continue
		}
		for _, file := range items[i].Files {
			if strings.HasSuffix(file.Name, ".zip") {
				totalZips++
			}
		}
	}
	missingInventory := false
	for i, id := range ids {
		if fetchErrors[i] != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", id, fetchErrors[i]))
			missingInventory = true
		}
	}
	// An unavailable inventory is not evidence that its ZIPs are missing.
	if missingInventory {
		return errors
	}
	for i, id := range ids {
		for _, diagnostic := range lintIAPart(id, items[i], totalZips) {
			errors = append(errors, id+": "+diagnostic)
		}
	}

	// Resolve numbered ZIPs across all parts and require exact, unique names.
	zipOwners := make(map[string]int)
	for i, item := range items {
		for _, file := range item.Files {
			if !strings.HasSuffix(file.Name, ".zip") {
				continue
			}
			if _, exists := zipOwners[file.Name]; exists {
				errors = append(errors, "Duplicate ZIP across IA items: "+file.Name)
			}
			zipOwners[file.Name] = i
		}
	}
	rootOwner, ok := zipOwners["000.zip"]
	if !ok || rootOwner != 0 {
		return append(errors, "No 000.zip found in base item")
	}
	rootRead := iaFiles(client, items[0], ids[0], "000.zip")
	info, cp, issues := readArchiveMetadata(rootRead, e.origin)
	if len(issues) != 0 {
		return append(errors, issues...)
	}
	n := zipCount(cp.Size)
	if n > 1000 {
		return append(errors, fmt.Sprintf("checkpoint implies %d ZIPs; at most 1000 supported", n))
	}
	for i := int64(0); i < n; i++ {
		name := fmt.Sprintf("%03d.zip", i)
		if _, ok := zipOwners[name]; !ok {
			errors = append(errors, "Missing ZIP: "+name)
		}
	}
	for name := range zipOwners {
		index, err := strconv.ParseInt(strings.TrimSuffix(name, ".zip"), 10, 64)
		if err != nil || index < 0 || index >= n || name != fmt.Sprintf("%03d.zip", index) {
			errors = append(errors, "Unexpected ZIP: "+name)
		}
	}
	readers := make(map[int64]fileReader)
	openZip := func(index int64) (fileReader, error) {
		if read := readers[index]; read != nil {
			return read, nil
		}
		name := fmt.Sprintf("%03d.zip", index)
		owner, ok := zipOwners[name]
		if !ok {
			return nil, fmt.Errorf("missing %s", name)
		}
		read := iaFiles(client, items[owner], ids[owner], name)
		zi, zc := info, cp
		var issues []string
		if index != 0 {
			zi, zc, issues = readArchiveMetadata(read, e.origin)
			issues = append(issues, compareArchiveMetadata(zi, zc, info, cp)...)
		}
		var metadata iaMetadata
		if err := json.Unmarshal(items[owner].Metadata, &metadata); err != nil {
			return nil, err
		}
		id := metadata.LogID.first()
		expected := logInfo{LogID: &id, URL: metadata.URL.first(), SubmissionURL: metadata.SubmissionURL.first(), MonitoringURL: metadata.MonitoringURL.first()}
		issues = append(issues, compareLogInfo(zi, expected, true)...)
		if size, present, err := iaLogSize(metadata.LogSize); err == nil && present && size != zc.Size {
			issues = append(issues, fmt.Sprintf("checkpoint size %d does not match IA ctlogsize %d", zc.Size, size))
		}
		if len(issues) != 0 {
			return nil, fmt.Errorf("%s: %s", ids[owner], strings.Join(issues, "; "))
		}
		readers[index] = read
		return read, nil
	}
	// Check the first ZIP in every IA part, plus the ZIPs selected by the tile
	// samples. Full checkpoints and log metadata must agree across copies.
	for i, item := range items {
		var names []string
		for _, file := range item.Files {
			if strings.HasSuffix(file.Name, ".zip") {
				names = append(names, file.Name)
			}
		}
		slices.Sort(names)
		if len(names) == 0 {
			errors = append(errors, ids[i]+": No zip files found in item")
			continue
		}
		index, err := strconv.ParseInt(strings.TrimSuffix(names[0], ".zip"), 10, 64)
		if err != nil || index < 0 || index >= n {
			continue
		}
		if _, err := openZip(index); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", names[0], err))
		}
	}
	errors = append(errors, e.checkStage("tiles", func() []string {
		return lintTileSamples(openZip, tlog.Tree{N: cp.Size, Hash: cp.Hash}, e.allowMissingIssuers)
	})...)
	// IA's torrent covers originals in the base item, not its extensions.
	objects := make(map[string]int64)
	for _, file := range items[0].Files {
		if file.Source != "original" || file.Name == "" || strings.HasSuffix(file.Name, "_files.xml") {
			continue
		}
		var number json.Number
		err := json.Unmarshal(file.Size, &number)
		size, sizeErr := number.Int64()
		if err != nil || sizeErr != nil || size < 0 {
			errors = append(errors, "Invalid IA file size for "+file.Name)
			size = -1
		}
		objects[file.Name] = size
	}
	errors = append(errors, e.checkStage("torrent metadata", func() []string { return lintTorrentObjects(client, e.torrentURL, objects) })...)

	return errors
}

func lintIAPart(id string, item iaItem, totalZips int) []string {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(item.Metadata, &fields); err != nil && len(item.Metadata) != 0 {
		return []string{fmt.Sprintf("Invalid JSON in metadata: %v", err)}
	}
	if len(fields) == 0 {
		return []string{fmt.Sprintf("Item %s not found or has no metadata", id)}
	}
	var metadata iaMetadata
	if err := json.Unmarshal(item.Metadata, &metadata); err != nil {
		return []string{fmt.Sprintf("Invalid JSON in metadata: %v", err)}
	}

	var errors []string
	if !slices.Contains(metadata.Subject, "certificate transparency log") {
		errors = append(errors, fmt.Sprintf("Missing 'certificate transparency log' topic (has: %v)", metadata.Subject))
	}
	logID := metadata.LogID.first()
	ctURL := metadata.URL.first()
	submissionURL := metadata.SubmissionURL.first()
	monitoringURL := metadata.MonitoringURL.first()
	if logID == "" {
		errors = append(errors, "Missing 'ctlogid' metadata")
	}
	if ctURL == "" && (submissionURL == "" || monitoringURL == "") {
		errors = append(errors, "Missing URL metadata: expected either 'cturl' or both 'ctsubmissionurl' and 'ctmonitoringurl'")
	}
	allowedCollection := false
	for _, collection := range metadata.Collection {
		if collection == "opensource_media" || collection == "datasets" || collection == "datasets_unsorted" {
			allowedCollection = true
			break
		}
	}
	if !allowedCollection {
		errors = append(errors, fmt.Sprintf(
			"Collection should be one of {'opensource_media', 'datasets', 'datasets_unsorted'} (has: %v)",
			metadata.Collection))
	}

	logSize, present, sizeErr := iaLogSize(metadata.LogSize)
	switch {
	case sizeErr != nil:
		errors = append(errors, fmt.Sprintf("Invalid ctlogsize value: %s", metadata.LogSize))
	case !present:
		errors = append(errors, "Missing 'ctlogsize' metadata")
	default:
		expectedZips := zipCount(logSize)
		if int64(totalZips) != expectedZips {
			errors = append(errors, fmt.Sprintf(
				"Expected %d zip files across all items based on ctlogsize %d, found %d",
				expectedZips, logSize, totalZips))
		}
	}

	return errors
}

// iaLogSize preserves integer precision for both JSON integers and strings.
// A JSON number may also be a float, which Python's int() truncates.
func iaLogSize(raw json.RawMessage) (size int64, present bool, err error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return 0, false, nil
	}
	if raw[0] == '"' {
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return 0, true, err
		}
		if value == "" {
			return 0, false, nil
		}
		size, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		return size, true, err
	}
	var number json.Number
	if err := json.Unmarshal(raw, &number); err != nil {
		return 0, true, err
	}
	size, err = number.Int64()
	if err != nil {
		value, floatErr := number.Float64()
		if floatErr != nil || math.IsNaN(value) || math.IsInf(value, 0) || value >= 1<<63 || value < -(1<<63) {
			return 0, true, fmt.Errorf("ctlogsize is not an int64")
		}
		return int64(value), value != 0, nil
	}
	// Zero as a number is false in Python, while the string "0" is true.
	return size, size != 0, nil
}

// The metadata API identifies the item's serving host and directory. Use its
// extraction endpoint directly instead of asking archive.org to redirect every
// small member request. Retain the public download URL if those fields are absent.
func iaFiles(client *http.Client, item iaItem, id, zipName string) fileReader {
	if !strings.HasSuffix(item.Server, ".archive.org") || strings.ContainsAny(item.Server, "/:@?# \t\r\n") ||
		!strings.HasPrefix(item.Dir, "/") || !strings.HasSuffix(item.Dir, "/items/"+id) {
		return httpFiles(client, "https://archive.org/download/"+id+"/"+zipName)
	}
	return func(name string) ([]byte, error) {
		query := url.Values{"archive": {item.Dir + "/" + zipName}, "file": {name}}
		return fetchLimited(client, "https://"+item.Server+"/view_archive.php?"+query.Encode(), rangeZipMemberLimit)
	}
}
