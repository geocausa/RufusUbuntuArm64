from pathlib import Path
import json


def replace_once(path, old, new):
    file_path = Path(path)
    source = file_path.read_text()
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one replacement target, found {count}: {old[:100]!r}")
    file_path.write_text(source.replace(old, new, 1))


sbat_level_go = r'''package secureboot

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
'''
Path("internal/secureboot/sbat_level.go").write_text(sbat_level_go)

sbat_level_test = r'''package secureboot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSBATLevelAndShimComparisonSemantics(t *testing.T) {
	level, err := ParseSBATLevel([]byte("sbat,1,2025051000\nshim,4\ngrub,5\n"), "test")
	if err != nil {
		t.Fatal(err)
	}
	if level.FormatGeneration != 1 || level.Datestamp != "2025051000" || len(level.Entries) != 3 {
		t.Fatalf("unexpected SBAT level: %#v", level)
	}
	revoked := level.Revocations([]SBATComponent{
		{Component: "sbat", Generation: 1},
		{Component: "shim", Generation: 3},
		{Component: "grub", Generation: 5},
		{Component: "grub.vendor", Generation: 1},
	})
	if len(revoked) != 1 || revoked[0].Component != "shim" || revoked[0].ImageGeneration != 3 || revoked[0].MinimumGeneration != 4 {
		t.Fatalf("unexpected revocations: %#v", revoked)
	}
}

func TestParseSBATLevelRejectsMalformedInputs(t *testing.T) {
	cases := map[string]string{
		"missing metadata":       "shim,4\n",
		"bad datestamp":          "sbat,1,2025\nshim,4\n",
		"zero generation":        "sbat,1,2025051000\nshim,0\n",
		"duplicate component":    "sbat,1,2025051000\nshim,4\nSHIM,5\n",
		"extra component field":  "sbat,1,2025051000\nshim,4,unexpected\n",
		"whitespace padded":      "sbat,1,2025051000\nshim, 4\n",
		"non ascii":              "sbat,1,2025051000\nshim,4\u00a0\n",
		"blank row":              "sbat,1,2025051000\n\nshim,4\n",
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseSBATLevel([]byte(input), "test"); err == nil {
				t.Fatalf("malformed SBAT level accepted: %q", input)
			}
		})
	}
}

func TestLoadSBATLevelFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "SbatLevel.csv")
	if err := os.WriteFile(path, []byte("sbat,1,2025051000\nshim,4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	level, err := LoadSBATLevelFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(level.Source, "SbatLevel.csv") || level.Datestamp != "2025051000" {
		t.Fatalf("unexpected loaded level: %#v", level)
	}
}
'''
Path("internal/secureboot/sbat_level_test.go").write_text(sbat_level_test)

replace_once(
    "internal/secureboot/uefi.go",
    '''\tDBX             *Database
\tRequireFallback bool
''',
    '''\tDBX             *Database
\tSBATLevel       *SBATLevel
\tRequireFallback bool
''',
)
replace_once(
    "internal/secureboot/uefi.go",
    '''\tEmbeddedCertificates   int             `json:"embedded_certificates"`
\tSBAT                   []SBATComponent `json:"sbat,omitempty"`
''',
    '''\tEmbeddedCertificates   int              `json:"embedded_certificates"`
\tSBAT                   []SBATComponent  `json:"sbat,omitempty"`
\tSBATRevoked            bool             `json:"sbat_revoked"`
\tSBATRevocations        []SBATRevocation `json:"sbat_revocations,omitempty"`
''',
)
replace_once(
    "internal/secureboot/uefi.go",
    '''\tDBXChecked    bool                 `json:"dbx_checked"`
\tValid         bool                 `json:"valid"`
\tRevoked       bool                 `json:"revoked"`
''',
    '''\tDBXChecked        bool                 `json:"dbx_checked"`
\tSBATLevelChecked  bool                 `json:"sbat_level_checked"`
\tSBATLevelSource   string               `json:"sbat_level_source,omitempty"`
\tSBATLevelDatestamp string              `json:"sbat_level_datestamp,omitempty"`
\tSBATRevoked       bool                 `json:"sbat_revoked"`
\tValid             bool                 `json:"valid"`
\tRevoked           bool                 `json:"revoked"`
''',
)
replace_once(
    "internal/secureboot/uefi.go",
    '''\tresult := UEFIMediaValidation{
\t\tRoot:         resolved,
\t\tArchitecture: architecture.name,
\t\tFallbackPath: architecture.fallbackPath,
\t\tDBXChecked:   opts.DBX != nil,
\t\tWarnings:     warnings,
\t}
''',
    '''\tresult := UEFIMediaValidation{
\t\tRoot:             resolved,
\t\tArchitecture:     architecture.name,
\t\tFallbackPath:     architecture.fallbackPath,
\t\tDBXChecked:       opts.DBX != nil,
\t\tSBATLevelChecked: opts.SBATLevel != nil,
\t\tWarnings:         warnings,
\t}
\tif opts.SBATLevel != nil {
\t\tresult.SBATLevelSource = opts.SBATLevel.Source
\t\tresult.SBATLevelDatestamp = opts.SBATLevel.Datestamp
\t}
''',
)
replace_once(
    "internal/secureboot/uefi.go",
    '''\tfor _, mediaFile := range mediaFiles {
''',
    '''\tvar dbxRevoked bool
\tfor _, mediaFile := range mediaFiles {
''',
)
replace_once(
    "internal/secureboot/uefi.go",
    '''\t\tfileResult := validateUEFIFile(mediaFile.data, relative, isFallback, architecture, opts.DBX)
''',
    '''\t\tfileResult := validateUEFIFile(mediaFile.data, relative, isFallback, architecture, opts.DBX, opts.SBATLevel)
''',
)
replace_once(
    "internal/secureboot/uefi.go",
    '''\t\tif fileResult.DirectHashRevoked || fileResult.X509CertificateRevoked {
\t\t\tresult.Revoked = true
\t\t}
''',
    '''\t\tif fileResult.DirectHashRevoked || fileResult.X509CertificateRevoked {
\t\t\tdbxRevoked = true
\t\t\tresult.Revoked = true
\t\t}
\t\tif fileResult.SBATRevoked {
\t\t\tresult.SBATRevoked = true
\t\t\tresult.Revoked = true
\t\t}
''',
)
replace_once(
    "internal/secureboot/uefi.go",
    '''\tif result.Revoked {
\t\tresult.Errors = append(result.Errors, "one or more EFI executables are revoked by the selected DBX")
\t}
''',
    '''\tif dbxRevoked {
\t\tresult.Errors = append(result.Errors, "one or more EFI executables are revoked by the selected DBX")
\t}
\tif result.SBATRevoked {
\t\tresult.Errors = append(result.Errors, "one or more EFI executables are revoked by the selected SBAT level")
\t}
''',
)
replace_once(
    "internal/secureboot/uefi.go",
    '''func validateUEFIFile(data []byte, relative string, fallback bool, architecture uefiArchitecture, dbx *Database) UEFIFileValidation {
''',
    '''func validateUEFIFile(data []byte, relative string, fallback bool, architecture uefiArchitecture, dbx *Database, sbatLevel *SBATLevel) UEFIFileValidation {
''',
)
replace_once(
    "internal/secureboot/uefi.go",
    '''\tif fallback && len(parsed.sbat) == 0 {
\t\tresult.Warnings = append(result.Warnings, "fallback loader has no .sbat metadata; generation-based revocation was not assessed")
\t}

\tif dbx != nil {
''',
    '''\tif len(parsed.sbat) == 0 {
\t\tif fallback {
\t\t\tresult.Warnings = append(result.Warnings, "fallback loader has no .sbat metadata; generation-based revocation was not assessed")
\t\t} else if sbatLevel != nil {
\t\t\tresult.Warnings = append(result.Warnings, "EFI executable has no .sbat metadata; the selected SBAT level was not assessed")
\t\t}
\t} else if sbatLevel != nil {
\t\tresult.SBATRevocations = sbatLevel.Revocations(parsed.sbat)
\t\tresult.SBATRevoked = len(result.SBATRevocations) > 0
\t}

\tif dbx != nil {
''',
)

uefi_tests = r'''

func TestValidateUEFIMediaAppliesTrustedSBATLevel(t *testing.T) {
	root := t.TempDir()
	writeSyntheticEFI(t, root, "EFI/BOOT/BOOTAA64.EFI", syntheticUEFIPE(
		imageFileMachineARM64,
		imageSubsystemEFIApp,
		syntheticUEFISection{name: ".text", data: []byte("fallback")},
		syntheticUEFISection{name: ".sbat", data: validSBAT()},
	))
	level, err := ParseSBATLevel([]byte("sbat,1,2025051000\nshim,5\n"), "test-level")
	if err != nil {
		t.Fatal(err)
	}
	result, err := ValidateUEFIMedia(context.Background(), root, UEFIValidationOptions{
		Architecture:    "arm64",
		RequireFallback: true,
		SBATLevel:       level,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid || !result.Revoked || !result.SBATRevoked || !result.SBATLevelChecked || result.SBATLevelDatestamp != "2025051000" {
		t.Fatalf("SBAT-revoked media was not rejected: %#v", result)
	}
	if len(result.Files) != 1 || !result.Files[0].SBATRevoked || len(result.Files[0].SBATRevocations) != 1 {
		t.Fatalf("per-file SBAT revocation was not reported: %#v", result.Files)
	}
	if revocation := result.Files[0].SBATRevocations[0]; revocation.Component != "shim" || revocation.ImageGeneration != 4 || revocation.MinimumGeneration != 5 {
		t.Fatalf("unexpected SBAT revocation: %#v", revocation)
	}
}

func TestValidateUEFIMediaAcceptsEqualTrustedSBATLevel(t *testing.T) {
	root := t.TempDir()
	writeSyntheticEFI(t, root, "EFI/BOOT/BOOTAA64.EFI", syntheticUEFIPE(
		imageFileMachineARM64,
		imageSubsystemEFIApp,
		syntheticUEFISection{name: ".sbat", data: validSBAT()},
	))
	level, err := ParseSBATLevel([]byte("sbat,1,2025051000\nshim,4\ngrub,99\n"), "test-level")
	if err != nil {
		t.Fatal(err)
	}
	result, err := ValidateUEFIMedia(context.Background(), root, UEFIValidationOptions{Architecture: "arm64", RequireFallback: true, SBATLevel: level})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid || result.SBATRevoked || result.Revoked {
		t.Fatalf("equal or absent SBAT generations should pass: %#v", result)
	}
}
'''
uefi_test_path = Path("internal/secureboot/uefi_test.go")
uefi_test_path.write_text(uefi_test_path.read_text() + uefi_tests)

replace_once(
    "cmd/rufus-linux/main.go",
    '''  rufusarm64-cli uefi validate --directory DIR [--arch ARCH] [--dbx FILE | --firmware] [--json]
''',
    '''  rufusarm64-cli uefi validate --directory DIR [--arch ARCH] [--dbx FILE | --firmware] [--sbat-level FILE] [--json]
''',
)
replace_once(
    "cmd/rufus-linux/main.go",
    '''\tfirmware := fs.Bool("firmware", false, "use the running firmware DBX variable")
\tasJSON := fs.Bool("json", false, "output JSON")
''',
    '''\tfirmware := fs.Bool("firmware", false, "use the running firmware DBX variable")
\tsbatLevelPath := fs.String("sbat-level", "", "optional trusted local shim-compatible SbatLevel CSV file")
\tasJSON := fs.Bool("json", false, "output JSON")
''',
)
replace_once(
    "cmd/rufus-linux/main.go",
    '''\tvar dbx *secureboot.Database
''',
    '''\tvar sbatLevel *secureboot.SBATLevel
\tif strings.TrimSpace(*sbatLevelPath) != "" {
\t\tsbatLevel, err = secureboot.LoadSBATLevelFile(*sbatLevelPath)
\t\tif err != nil {
\t\t\treturn err
\t\t}
\t}
\tvar dbx *secureboot.Database
''',
)
replace_once(
    "cmd/rufus-linux/main.go",
    '''\t\tDBX:             dbx,
\t\tRequireFallback: *requireFallback,
''',
    '''\t\tDBX:             dbx,
\t\tSBATLevel:       sbatLevel,
\t\tRequireFallback: *requireFallback,
''',
)
replace_once(
    "cmd/rufus-linux/main.go",
    '''\tfmt.Printf("Root: %s\nFallback: %s (found: %t)\nDBX checked: %t\n", result.Root, result.FallbackPath, result.FallbackFound, result.DBXChecked)
''',
    '''\tfmt.Printf("Root: %s\nFallback: %s (found: %t)\nDBX checked: %t\nSBAT level checked: %t\n", result.Root, result.FallbackPath, result.FallbackFound, result.DBXChecked, result.SBATLevelChecked)
\tif result.SBATLevelChecked {
\t\tfmt.Printf("SBAT level: %s (datestamp %s)\n", result.SBATLevelSource, result.SBATLevelDatestamp)
\t}
''',
)
replace_once(
    "cmd/rufus-linux/main.go",
    '''\t\tcase file.DirectHashRevoked || file.X509CertificateRevoked:
''',
    '''\t\tcase file.DirectHashRevoked || file.X509CertificateRevoked || file.SBATRevoked:
''',
)
replace_once(
    "cmd/rufus-linux/main.go",
    '''\t\tfor _, warning := range file.Warnings {
''',
    '''\t\tfor _, revocation := range file.SBATRevocations {
\t\t\tfmt.Printf("  SBAT revoked: %s generation %d is below trusted minimum %d\n", revocation.Component, revocation.ImageGeneration, revocation.MinimumGeneration)
\t\t}
\t\tfor _, warning := range file.Warnings {
''',
)

cli_tests = r'''

func TestUEFIValidateLoadsTrustedSBATLevel(t *testing.T) {
	root := t.TempDir()
	writeCLIUEFIFallback(t, root, 0xaa64)
	levelPath := filepath.Join(t.TempDir(), "SbatLevel.csv")
	if err := os.WriteFile(levelPath, []byte("sbat,1,2025051000\nshim,4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := captureCLIStdout(t, func() error {
		return runUEFIValidate([]string{"--directory", root, "--arch", "arm64", "--sbat-level", levelPath, "--json"})
	})
	if err != nil {
		t.Fatalf("validate with SBAT level: %v", err)
	}
	var result secureboot.UEFIMediaValidation
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("decode UEFI validation: %v\n%s", err, output)
	}
	if !result.Valid || !result.SBATLevelChecked || result.SBATLevelDatestamp != "2025051000" || result.SBATRevoked {
		t.Fatalf("unexpected SBAT-level validation: %#v", result)
	}
}

func TestUEFIValidateRejectsMalformedSBATLevel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad-sbat.csv")
	if err := os.WriteFile(path, []byte("shim,4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runUEFIValidate([]string{"--directory", t.TempDir(), "--arch", "arm64", "--sbat-level", path})
	if err == nil || !strings.Contains(err.Error(), "must start with sbat") {
		t.Fatalf("malformed SBAT level error = %v", err)
	}
}
'''
main_test_path = Path("cmd/rufus-linux/main_test.go")
main_test_path.write_text(main_test_path.read_text() + cli_tests)

replace_once(
    "docs/rufusarm64-cli.1",
    '''.RI [ --dbx " FILE" | --firmware ]
.RI [ --json ]
''',
    '''.RI [ --dbx " FILE" | --firmware ]
.RI [ --sbat-level " FILE" ]
.RI [ --json ]
''',
)
replace_once(
    "docs/rufusarm64-cli.1",
    '''.B --firmware
Apply the running firmware DBX instead of a local file.
.PP
''',
    '''.B --firmware
Apply the running firmware DBX instead of a local file.
.TP
.BI --sbat-level " FILE"
Apply a caller-trusted local shim-compatible SbatLevel CSV payload. A matching
image component is revoked only when its generation is lower than the trusted
minimum. The file is read once from a pinned regular-file descriptor; firmware
SbatLevel acquisition is not performed by this option.
.PP
''',
)
replace_once(
    "README.md",
    '''rufusarm64-cli uefi validate --directory /mnt/usb --arch arm64 --json
''',
    '''rufusarm64-cli uefi validate --directory /mnt/usb --arch arm64 --sbat-level ./SbatLevel.csv --json
''',
)
replace_once(
    "scripts/test.sh",
    '''"${native_helper}" uefi validate --directory "${native_dir}/uefi-media" --arch arm64 --json | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["valid"] and d["fallback_found"] and d["architecture"] == "arm64"'
''',
    '''printf 'sbat,1,2025051000\nshim,4\n' > "${native_dir}/SbatLevel.csv"
"${native_helper}" uefi validate --directory "${native_dir}/uefi-media" --arch arm64 --sbat-level "${native_dir}/SbatLevel.csv" --json | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["valid"] and d["fallback_found"] and d["architecture"] == "arm64" and d["sbat_level_checked"] and d["sbat_level_datestamp"] == "2025051000"'
''',
)

parity_path = Path("docs/upstream-rufus-parity.json")
parity = json.loads(parity_path.read_text())
for feature in parity["features"]:
    if feature["id"] == "uefi-runtime-validation":
        feature["notes"] = (
            "The 0.11 development line exposes descriptor-rooted CLI and GTK validation of fallback loaders, "
            "PE architecture and EFI subsystem fields, bounded SBAT metadata, optional DBX hash/certificate "
            "revocations, and shim-compatible comparison against an explicitly supplied trusted local SbatLevel. "
            "Firmware SbatLevel acquisition and complete boot-chain reference resolution remain planned."
        )
        break
else:
    raise SystemExit("UEFI runtime validation parity entry was not found")
parity_path.write_text(json.dumps(parity, indent=2) + "\n")
