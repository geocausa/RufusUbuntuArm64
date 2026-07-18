package runtimeintegrity

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	ManifestName         = "md5sum.txt"
	MaximumManifestSize  = 64 * 1024 * 1024
	MaximumManifestLines = 100000
	MaximumPathBytes     = 512
	DefaultMaximumFiles  = 100000
)

// Entry is one path and MD5 digest referenced by a uefi-md5sum manifest.
type Entry struct {
	Path string `json:"path"`
	MD5  string `json:"md5"`
	Size uint64 `json:"size,omitempty"`
}

// Manifest is the deterministic root md5sum.txt representation used by
// uefi-md5sum. TotalBytes is the sum of all referenced file sizes.
type Manifest struct {
	TotalBytes uint64  `json:"total_bytes"`
	Entries    []Entry `json:"entries"`
}

// MarshalText renders the strict subset accepted by upstream uefi-md5sum.
func (m Manifest) MarshalText() ([]byte, error) {
	entries := append([]Entry(nil), m.Entries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	seen := make(map[string]struct{}, len(entries))
	var total uint64
	var out bytes.Buffer
	fmt.Fprintf(&out, "# md5sum_totalbytes = 0x%x\n", m.TotalBytes)
	for _, entry := range entries {
		path, key, err := validateManifestPath(entry.Path)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("duplicate or case-equivalent manifest path %q", path)
		}
		seen[key] = struct{}{}
		digest, err := normalizeMD5(entry.MD5)
		if err != nil {
			return nil, fmt.Errorf("path %s: %w", path, err)
		}
		if ^uint64(0)-total < entry.Size {
			return nil, errors.New("manifest total byte count overflows uint64")
		}
		total += entry.Size
		fmt.Fprintf(&out, "%s  %s\n", digest, path)
		if out.Len() > MaximumManifestSize {
			return nil, fmt.Errorf("manifest exceeds the %d-byte safety limit", MaximumManifestSize)
		}
	}
	if len(entries) > MaximumManifestLines {
		return nil, fmt.Errorf("manifest exceeds the %d-entry safety limit", MaximumManifestLines)
	}
	if total != m.TotalBytes {
		return nil, fmt.Errorf("manifest total byte count is 0x%x but entries total 0x%x", m.TotalBytes, total)
	}
	return out.Bytes(), nil
}

// Parse validates and parses a bounded uefi-md5sum manifest. It accepts LF or
// CRLF line endings, uppercase or lowercase hashes, and unrelated comments.
func Parse(data []byte) (Manifest, error) {
	if len(data) == 0 {
		return Manifest{}, errors.New("manifest is empty")
	}
	if len(data) > MaximumManifestSize {
		return Manifest{}, fmt.Errorf("manifest exceeds the %d-byte safety limit", MaximumManifestSize)
	}
	if !utf8.Valid(data) {
		return Manifest{}, errors.New("manifest is not valid UTF-8")
	}
	if bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf}) {
		return Manifest{}, errors.New("manifest must not contain a UTF-8 byte-order mark")
	}
	for _, value := range data {
		if value == 0 || (value < 0x20 && value != '\n' && value != '\r' && value != '\t') {
			return Manifest{}, errors.New("manifest contains a forbidden control character")
		}
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	if strings.ContainsRune(text, '\r') {
		return Manifest{}, errors.New("manifest contains a bare carriage return")
	}
	lines := strings.Split(text, "\n")
	if len(lines) > MaximumManifestLines+2 {
		return Manifest{}, fmt.Errorf("manifest exceeds the %d-entry safety limit", MaximumManifestLines)
	}

	var result Manifest
	var totalSeen bool
	seen := make(map[string]struct{})
	for lineNumber, line := range lines {
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			trimmed := strings.TrimSpace(strings.TrimPrefix(line, "#"))
			if !strings.HasPrefix(trimmed, "md5sum_totalbytes") {
				continue
			}
			if totalSeen {
				return Manifest{}, errors.New("manifest contains multiple md5sum_totalbytes declarations")
			}
			parts := strings.Split(trimmed, "=")
			if len(parts) != 2 || strings.TrimSpace(parts[0]) != "md5sum_totalbytes" {
				return Manifest{}, fmt.Errorf("line %d has an invalid md5sum_totalbytes declaration", lineNumber+1)
			}
			value := strings.TrimSpace(parts[1])
			if !strings.HasPrefix(value, "0x") || len(value) <= 2 || len(value) > 18 {
				return Manifest{}, fmt.Errorf("line %d has an invalid md5sum_totalbytes value", lineNumber+1)
			}
			parsed, err := strconv.ParseUint(value[2:], 16, 64)
			if err != nil {
				return Manifest{}, fmt.Errorf("line %d has an invalid md5sum_totalbytes value", lineNumber+1)
			}
			result.TotalBytes = parsed
			totalSeen = true
			continue
		}
		if len(line) < 35 || line[32] != ' ' || line[33] != ' ' {
			return Manifest{}, fmt.Errorf("line %d is not a standard MD5 record", lineNumber+1)
		}
		digest, err := normalizeMD5(line[:32])
		if err != nil {
			return Manifest{}, fmt.Errorf("line %d: %w", lineNumber+1, err)
		}
		path, key, err := validateManifestPath(line[34:])
		if err != nil {
			return Manifest{}, fmt.Errorf("line %d: %w", lineNumber+1, err)
		}
		if _, exists := seen[key]; exists {
			return Manifest{}, fmt.Errorf("line %d duplicates or case-collides with path %q", lineNumber+1, path)
		}
		seen[key] = struct{}{}
		result.Entries = append(result.Entries, Entry{Path: path, MD5: digest})
		if len(result.Entries) > MaximumManifestLines {
			return Manifest{}, fmt.Errorf("manifest exceeds the %d-entry safety limit", MaximumManifestLines)
		}
	}
	if !totalSeen {
		return Manifest{}, errors.New("manifest is missing md5sum_totalbytes")
	}
	if len(result.Entries) == 0 {
		return Manifest{}, errors.New("manifest contains no file records")
	}
	return result, nil
}

func normalizeMD5(value string) (string, error) {
	if len(value) != 32 {
		return "", errors.New("MD5 digest must contain exactly 32 hexadecimal characters")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 16 {
		return "", errors.New("MD5 digest contains non-hexadecimal data")
	}
	return strings.ToLower(value), nil
}

func validateManifestPath(value string) (string, string, error) {
	if !utf8.ValidString(value) {
		return "", "", errors.New("manifest path is not valid UTF-8")
	}
	if len(value) == 0 || len(value) > MaximumPathBytes {
		return "", "", fmt.Errorf("manifest path must be between 1 and %d bytes", MaximumPathBytes)
	}
	if !strings.HasPrefix(value, "./") {
		return "", "", errors.New("manifest path must start with ./")
	}
	if strings.ContainsRune(value, '\\') {
		return "", "", errors.New("manifest path contains an ambiguous backslash")
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return "", "", errors.New("manifest path contains a control character")
		}
	}
	relative := strings.TrimPrefix(value, "./")
	if relative == "" || strings.HasPrefix(relative, "/") || strings.HasSuffix(relative, "/") {
		return "", "", errors.New("manifest path is empty or absolute")
	}
	parts := strings.Split(relative, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", "", errors.New("manifest path contains an empty, current, or parent component")
		}
	}
	if len(parts) == 1 && strings.EqualFold(parts[0], ManifestName) {
		return "", "", errors.New("manifest must not reference itself")
	}
	canonical := "./" + strings.Join(parts, "/")
	return canonical, strings.ToLower(canonical), nil
}
