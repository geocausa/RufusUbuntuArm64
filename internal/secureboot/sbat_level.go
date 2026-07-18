package secureboot

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const maximumSBATLevelFileSize = int64(1024 * 1024)

// SBATLevelEntry is one minimum component generation from a trusted SbatLevel payload.
type SBATLevelEntry struct {
	Component  string `json:"component"`
	Generation uint64 `json:"generation"`
	Datestamp  string `json:"datestamp,omitempty"`
}

// SBATLevel is a caller-supplied trusted shim-compatible revocation level.
// The trust decision belongs to the caller; parsing only validates its structure.
type SBATLevel struct {
	Source           string           `json:"source"`
	FormatGeneration uint64           `json:"format_generation"`
	Datestamp        string           `json:"datestamp"`
	Entries          []SBATLevelEntry `json:"entries"`
	minimums         map[string]uint64
}

// SBATRevocation reports one image component below its trusted minimum generation.
type SBATRevocation struct {
	Component         string `json:"component"`
	ImageGeneration   uint64 `json:"image_generation"`
	MinimumGeneration uint64 `json:"minimum_generation"`
}

// ParseSBATLevel validates a bounded ASCII SbatLevel CSV payload. The canonical
// first row is sbat,<format-generation>,<10-digit-datestamp>; following rows are
// component,<minimum-generation>.
func ParseSBATLevel(data []byte, source string) (*SBATLevel, error) {
	if len(data) == 0 {
		return nil, errors.New("SBAT level is empty")
	}
	if int64(len(data)) > maximumSBATLevelFileSize {
		return nil, fmt.Errorf("SBAT level exceeds the %d-byte safety limit", maximumSBATLevelFileSize)
	}
	for _, value := range data {
		if value == '\n' || value == '\r' {
			continue
		}
		if value < 0x20 || value > 0x7e {
			return nil, errors.New("SBAT level must contain printable ASCII CSV data")
		}
	}
	data = bytes.TrimRight(data, "\r\n")
	if len(data) == 0 {
		return nil, errors.New("SBAT level is empty")
	}
	for index, line := range strings.Split(string(data), "\n") {
		if strings.TrimSuffix(line, "\r") == "" {
			return nil, fmt.Errorf("SBAT level row %d is empty", index+1)
		}
	}
	reader := csv.NewReader(bytes.NewReader(data))
	reader.FieldsPerRecord = -1
	level := &SBATLevel{Source: strings.TrimSpace(source), minimums: make(map[string]uint64)}
	seen := make(map[string]struct{})
	row := 0
	for {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse SBAT level CSV: %w", err)
		}
		row++
		if row > maximumSBATRecords {
			return nil, fmt.Errorf("SBAT level exceeds the %d-record safety limit", maximumSBATRecords)
		}
		if len(record) == 1 && record[0] == "" {
			return nil, fmt.Errorf("SBAT level row %d is empty", row)
		}
		for index := range record {
			if record[index] != strings.TrimSpace(record[index]) || record[index] == "" {
				return nil, fmt.Errorf("SBAT level row %d has an empty or whitespace-padded field", row)
			}
		}
		if row == 1 {
			if len(record) != 3 || record[0] != "sbat" {
				return nil, errors.New("SBAT level must start with sbat,<generation>,<10-digit datestamp>")
			}
			if len(record[2]) != 10 || !decimalDigits(record[2]) {
				return nil, errors.New("SBAT level datestamp must contain exactly 10 decimal digits")
			}
			level.Datestamp = record[2]
		} else if len(record) != 2 {
			return nil, fmt.Errorf("SBAT level row %d must contain exactly component and generation", row)
		}
		generation, err := strconv.ParseUint(record[1], 10, 64)
		if err != nil || generation == 0 {
			return nil, fmt.Errorf("invalid SBAT level generation %q for %s", record[1], record[0])
		}
		key := strings.ToLower(record[0])
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("duplicate SBAT level component %q", record[0])
		}
		seen[key] = struct{}{}
		entry := SBATLevelEntry{Component: record[0], Generation: generation}
		if row == 1 {
			entry.Datestamp = record[2]
			level.FormatGeneration = generation
		}
		level.Entries = append(level.Entries, entry)
		level.minimums[record[0]] = generation
	}
	if row == 0 {
		return nil, errors.New("SBAT level contains no records")
	}
	return level, nil
}

func decimalDigits(value string) bool {
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

// LoadSBATLevelFile reads and parses one trusted local SbatLevel payload from a
// pinned regular-file descriptor. Symlinks are resolved once before the read.
func LoadSBATLevelFile(path string) (*SBATLevel, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("SBAT level path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("make SBAT level path absolute: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, fmt.Errorf("resolve SBAT level path: %w", err)
	}
	file, err := os.Open(resolved)
	if err != nil {
		return nil, fmt.Errorf("open SBAT level: %w", err)
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat SBAT level: %w", err)
	}
	if !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > maximumSBATLevelFileSize {
		return nil, fmt.Errorf("SBAT level must be a non-empty regular file no larger than %d bytes", maximumSBATLevelFileSize)
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumSBATLevelFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read SBAT level: %w", err)
	}
	if int64(len(data)) > maximumSBATLevelFileSize {
		return nil, fmt.Errorf("SBAT level exceeds the %d-byte safety limit", maximumSBATLevelFileSize)
	}
	after, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("restat SBAT level: %w", err)
	}
	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, errors.New("SBAT level changed while it was being read")
	}
	return ParseSBATLevel(data, resolved)
}

// Revocations compares image metadata using shim's rule: only a matching
// component with image generation lower than the trusted minimum is revoked.
func (level *SBATLevel) Revocations(components []SBATComponent) []SBATRevocation {
	if level == nil {
		return nil
	}
	minimums := level.minimums
	if minimums == nil {
		minimums = make(map[string]uint64, len(level.Entries))
		for _, entry := range level.Entries {
			minimums[entry.Component] = entry.Generation
		}
	}
	var result []SBATRevocation
	for _, component := range components {
		minimum, found := minimums[component.Component]
		if found && component.Generation < minimum {
			result = append(result, SBATRevocation{
				Component:         component.Component,
				ImageGeneration:   component.Generation,
				MinimumGeneration: minimum,
			})
		}
	}
	return result
}
