package secureboot

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

const (
	imageFileMachineI386     = uint16(0x014c)
	imageFileMachineARM      = uint16(0x01c0)
	imageFileMachineARMNT    = uint16(0x01c4)
	imageFileMachineIA64     = uint16(0x0200)
	imageFileMachineEBC      = uint16(0x0ebc)
	imageFileMachineAMD64    = uint16(0x8664)
	imageFileMachineARM64    = uint16(0xaa64)
	imageFileMachineRISCV64  = uint16(0x5064)
	imageFileMachineLOONG64  = uint16(0x6264)
	imageSubsystemEFIApp     = uint16(10)
	imageSubsystemEFIBoot    = uint16(11)
	imageSubsystemEFIRuntime = uint16(12)
	imageSubsystemEFIROM     = uint16(13)
	defaultUEFIMaxFiles      = 512
	maximumUEFIMaxFiles      = 4096
	maximumUEFIFileSize      = int64(256 * 1024 * 1024)
	maximumSBATSectionSize   = uint32(1024 * 1024)
	maximumSBATRecords       = 1024
)

// UEFIValidationOptions controls a bounded, read-only validation of a mounted or
// extracted boot-media tree. DBX is optional; when supplied, every discovered
// EFI executable is also checked for direct image-hash and exact embedded X.509
// revocations.
type UEFIValidationOptions struct {
	Architecture    string
	MaxFiles        int
	DBX             *Database
	RequireFallback bool
}

// SBATComponent is one parsed generation record from a PE image's .sbat
// section. RufusArm64 reports this metadata but does not yet claim firmware SBAT
// level comparison; that requires a separately trusted revocation-level input.
type SBATComponent struct {
	Component  string `json:"component"`
	Generation uint64 `json:"generation"`
	Vendor     string `json:"vendor"`
	Package    string `json:"package"`
	Version    string `json:"version"`
	VendorURL  string `json:"vendor_url"`
}

// UEFIFileValidation describes structural and optional revocation checks for one
// EFI executable. A foreign-architecture file is reported as a warning unless it
// is the selected architecture's fallback loader.
type UEFIFileValidation struct {
	Path                   string          `json:"path"`
	Machine                uint16          `json:"machine"`
	MachineName            string          `json:"machine_name"`
	Subsystem              uint16          `json:"subsystem"`
	SubsystemName          string          `json:"subsystem_name"`
	Fallback               bool            `json:"fallback"`
	AuthenticodeSHA256     string          `json:"authenticode_sha256,omitempty"`
	DirectHashRevoked      bool            `json:"direct_hash_revoked"`
	X509CertificateRevoked bool            `json:"x509_certificate_revoked"`
	EmbeddedCertificates   int             `json:"embedded_certificates"`
	SBAT                   []SBATComponent `json:"sbat,omitempty"`
	Warnings               []string        `json:"warnings,omitempty"`
	Error                  string          `json:"error,omitempty"`
}

// UEFIMediaValidation is the complete result for a media tree. Invalid media is
// represented as a successful read-only scan with Valid=false and explanatory
// Errors; operational failures such as an unreadable root are returned as Go
// errors.
type UEFIMediaValidation struct {
	Root          string               `json:"root"`
	Architecture  string               `json:"architecture"`
	FallbackPath  string               `json:"fallback_path"`
	FallbackFound bool                 `json:"fallback_found"`
	DBXChecked    bool                 `json:"dbx_checked"`
	Valid         bool                 `json:"valid"`
	Revoked       bool                 `json:"revoked"`
	Files         []UEFIFileValidation `json:"files"`
	Warnings      []string             `json:"warnings,omitempty"`
	Errors        []string             `json:"errors,omitempty"`
}

type uefiArchitecture struct {
	name         string
	fallbackPath string
	machines     map[uint16]struct{}
}

type parsedUEFIImage struct {
	machine   uint16
	subsystem uint16
	sbat      []SBATComponent
}

// ValidateUEFIMedia performs a read-only, symlink-averse scan of EFI executable
// files below root. It validates the selected architecture's removable-media
// fallback loader, PE/COFF machine and EFI subsystem fields, bounded .sbat CSV
// metadata, and optional DBX revocation state.
func ValidateUEFIMedia(ctx context.Context, root string, opts UEFIValidationOptions) (UEFIMediaValidation, error) {
	return validateUEFIMedia(ctx, root, opts, nil)
}

func validateUEFIMedia(ctx context.Context, root string, opts UEFIValidationOptions, hook uefiTraversalHook) (UEFIMediaValidation, error) {
	if ctx == nil {
		return UEFIMediaValidation{}, errors.New("UEFI validation context is nil")
	}
	architecture, err := normalizeUEFIArchitecture(opts.Architecture)
	if err != nil {
		return UEFIMediaValidation{}, err
	}
	if opts.MaxFiles <= 0 {
		opts.MaxFiles = defaultUEFIMaxFiles
	}
	if opts.MaxFiles > maximumUEFIMaxFiles {
		return UEFIMediaValidation{}, fmt.Errorf("UEFI file limit %d exceeds the %d-file safety maximum", opts.MaxFiles, maximumUEFIMaxFiles)
	}
	resolved, mediaFiles, warnings, err := openUEFIMediaTree(ctx, root, opts.MaxFiles, hook)
	if err != nil {
		return UEFIMediaValidation{}, fmt.Errorf("scan UEFI media tree: %w", err)
	}

	result := UEFIMediaValidation{
		Root:         resolved,
		Architecture: architecture.name,
		FallbackPath: architecture.fallbackPath,
		DBXChecked:   opts.DBX != nil,
		Warnings:     warnings,
	}
	if len(mediaFiles) == 0 {
		result.Errors = append(result.Errors, "media tree contains no EFI executables")
	}

	for _, mediaFile := range mediaFiles {
		if err := ctx.Err(); err != nil {
			return UEFIMediaValidation{}, err
		}
		relative := mediaFile.relative
		isFallback := strings.EqualFold(relative, architecture.fallbackPath)
		fileResult := validateUEFIFile(mediaFile.data, relative, isFallback, architecture, opts.DBX)
		if isFallback {
			result.FallbackFound = true
		}
		if fileResult.DirectHashRevoked || fileResult.X509CertificateRevoked {
			result.Revoked = true
		}
		if fileResult.Error != "" {
			result.Errors = append(result.Errors, relative+": "+fileResult.Error)
		}
		result.Files = append(result.Files, fileResult)
	}
	if opts.RequireFallback && !result.FallbackFound {
		result.Errors = append(result.Errors, "missing architecture fallback loader "+architecture.fallbackPath)
	}
	if result.Revoked {
		result.Errors = append(result.Errors, "one or more EFI executables are revoked by the selected DBX")
	}
	result.Valid = len(result.Errors) == 0
	return result, nil
}
func validateUEFIFile(data []byte, relative string, fallback bool, architecture uefiArchitecture, dbx *Database) UEFIFileValidation {
	result := UEFIFileValidation{Path: relative, Fallback: fallback}
	parsed, err := parseUEFIImage(data)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.Machine = parsed.machine
	result.MachineName = uefiMachineName(parsed.machine)
	result.Subsystem = parsed.subsystem
	result.SubsystemName = uefiSubsystemName(parsed.subsystem)
	result.SBAT = parsed.sbat

	_, expectedMachine := architecture.machines[parsed.machine]
	if fallback && !expectedMachine {
		result.Error = fmt.Sprintf("fallback loader is %s, expected %s", result.MachineName, architecture.name)
		return result
	}
	if !fallback && !expectedMachine {
		result.Warnings = append(result.Warnings, fmt.Sprintf("foreign-architecture EFI executable (%s)", result.MachineName))
	}
	if !isEFISubsystem(parsed.subsystem) {
		result.Error = fmt.Sprintf("PE subsystem %d is not an EFI executable subsystem", parsed.subsystem)
		return result
	}
	if fallback && parsed.subsystem != imageSubsystemEFIApp {
		result.Error = fmt.Sprintf("fallback loader subsystem is %s, expected EFI application", result.SubsystemName)
		return result
	}
	if fallback && len(parsed.sbat) == 0 {
		result.Warnings = append(result.Warnings, "fallback loader has no .sbat metadata; generation-based revocation was not assessed")
	}

	if dbx != nil {
		checked := checkPEData(relative, data, dbx)
		result.AuthenticodeSHA256 = checked.AuthenticodeSHA256
		result.DirectHashRevoked = checked.DirectHashRevoked
		result.X509CertificateRevoked = checked.X509CertificateRevoked
		result.EmbeddedCertificates = checked.EmbeddedCertificates
		if checked.Error != "" {
			result.Error = checked.Error
		}
	}
	return result
}

func parseUEFIImageFile(path string) (parsedUEFIImage, error) {
	file, err := os.Open(path)
	if err != nil {
		return parsedUEFIImage{}, fmt.Errorf("open EFI executable: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return parsedUEFIImage{}, fmt.Errorf("stat EFI executable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximumUEFIFileSize {
		return parsedUEFIImage{}, fmt.Errorf("EFI executable must be a non-empty regular file no larger than %d bytes", maximumUEFIFileSize)
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return parsedUEFIImage{}, fmt.Errorf("read EFI executable: %w", err)
	}
	return parseUEFIImage(data)
}

func parseUEFIImage(data []byte) (parsedUEFIImage, error) {
	if len(data) < 0x40 || data[0] != 'M' || data[1] != 'Z' {
		return parsedUEFIImage{}, errors.New("file is not a PE/COFF image")
	}
	peOffset := int(binary.LittleEndian.Uint32(data[0x3c:0x40]))
	if peOffset < 0x40 || peOffset > len(data)-24 || !bytes.Equal(data[peOffset:peOffset+4], []byte{'P', 'E', 0, 0}) {
		return parsedUEFIImage{}, errors.New("invalid PE header offset or signature")
	}
	coff := peOffset + 4
	machine := binary.LittleEndian.Uint16(data[coff : coff+2])
	sectionCount := int(binary.LittleEndian.Uint16(data[coff+2 : coff+4]))
	optionalSize := int(binary.LittleEndian.Uint16(data[coff+16 : coff+18]))
	optional := coff + 20
	if sectionCount < 0 || sectionCount > 4096 || optionalSize < 70 || optional > len(data)-optionalSize {
		return parsedUEFIImage{}, errors.New("invalid PE optional header or section count")
	}
	magic := binary.LittleEndian.Uint16(data[optional : optional+2])
	if magic != pe32Magic && magic != pe32PlusMagic {
		return parsedUEFIImage{}, fmt.Errorf("unsupported PE optional-header magic 0x%x", magic)
	}
	subsystemOffset := optional + 68
	if subsystemOffset+2 > optional+optionalSize {
		return parsedUEFIImage{}, errors.New("truncated PE subsystem field")
	}
	subsystem := binary.LittleEndian.Uint16(data[subsystemOffset : subsystemOffset+2])
	sectionTable := optional + optionalSize
	if sectionCount > (len(data)-sectionTable)/peSectionSize {
		return parsedUEFIImage{}, errors.New("truncated PE section table")
	}
	var sbat []SBATComponent
	for index := 0; index < sectionCount; index++ {
		entry := data[sectionTable+index*peSectionSize : sectionTable+(index+1)*peSectionSize]
		name := strings.TrimRight(string(entry[:8]), "\x00")
		if name != ".sbat" {
			continue
		}
		if sbat != nil {
			return parsedUEFIImage{}, errors.New("PE image contains multiple .sbat sections")
		}
		rawSize := binary.LittleEndian.Uint32(entry[16:20])
		rawOffset := binary.LittleEndian.Uint32(entry[20:24])
		if rawSize == 0 || rawSize > maximumSBATSectionSize {
			return parsedUEFIImage{}, errors.New("invalid or oversized .sbat section")
		}
		end := uint64(rawOffset) + uint64(rawSize)
		if rawOffset == 0 || end > uint64(len(data)) || end < uint64(rawOffset) {
			return parsedUEFIImage{}, errors.New("invalid .sbat section extent")
		}
		parsed, err := parseSBAT(data[rawOffset:end])
		if err != nil {
			return parsedUEFIImage{}, err
		}
		sbat = parsed
	}
	return parsedUEFIImage{machine: machine, subsystem: subsystem, sbat: sbat}, nil
}

func parseSBAT(data []byte) ([]SBATComponent, error) {
	data = bytes.TrimRight(data, "\x00\r\n ")
	if len(data) == 0 {
		return nil, errors.New("empty .sbat section")
	}
	reader := csv.NewReader(bytes.NewReader(data))
	reader.FieldsPerRecord = -1
	var result []SBATComponent
	seen := make(map[string]struct{})
	for {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse .sbat CSV: %w", err)
		}
		if len(record) == 1 && strings.TrimSpace(record[0]) == "" {
			continue
		}
		if len(record) < 6 {
			return nil, errors.New(".sbat record has fewer than six fields")
		}
		if len(result) >= maximumSBATRecords {
			return nil, fmt.Errorf(".sbat section exceeds the %d-record safety limit", maximumSBATRecords)
		}
		for index := range record {
			record[index] = strings.TrimSpace(record[index])
		}
		if record[0] == "" || record[1] == "" {
			return nil, errors.New(".sbat record has an empty component or generation")
		}
		generation, err := strconv.ParseUint(record[1], 10, 64)
		if err != nil || generation == 0 {
			return nil, fmt.Errorf("invalid .sbat generation %q for %s", record[1], record[0])
		}
		key := strings.ToLower(record[0])
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("duplicate .sbat component %q", record[0])
		}
		seen[key] = struct{}{}
		result = append(result, SBATComponent{
			Component:  record[0],
			Generation: generation,
			Vendor:     record[2],
			Package:    record[3],
			Version:    record[4],
			VendorURL:  record[5],
		})
	}
	if len(result) == 0 {
		return nil, errors.New(".sbat section contains no records")
	}
	return result, nil
}

func normalizeUEFIArchitecture(value string) (uefiArchitecture, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		value = "arm64"
	}
	switch value {
	case "arm64", "aarch64":
		return uefiArchitecture{name: "arm64", fallbackPath: "EFI/BOOT/BOOTAA64.EFI", machines: map[uint16]struct{}{imageFileMachineARM64: {}}}, nil
	case "amd64", "x86_64", "x64":
		return uefiArchitecture{name: "amd64", fallbackPath: "EFI/BOOT/BOOTX64.EFI", machines: map[uint16]struct{}{imageFileMachineAMD64: {}}}, nil
	case "386", "i386", "i686", "x86":
		return uefiArchitecture{name: "386", fallbackPath: "EFI/BOOT/BOOTIA32.EFI", machines: map[uint16]struct{}{imageFileMachineI386: {}}}, nil
	case "arm":
		return uefiArchitecture{name: "arm", fallbackPath: "EFI/BOOT/BOOTARM.EFI", machines: map[uint16]struct{}{imageFileMachineARM: {}, imageFileMachineARMNT: {}}}, nil
	case "riscv64":
		return uefiArchitecture{name: "riscv64", fallbackPath: "EFI/BOOT/BOOTRISCV64.EFI", machines: map[uint16]struct{}{imageFileMachineRISCV64: {}}}, nil
	case "loongarch64":
		return uefiArchitecture{name: "loongarch64", fallbackPath: "EFI/BOOT/BOOTLOONGARCH64.EFI", machines: map[uint16]struct{}{imageFileMachineLOONG64: {}}}, nil
	default:
		return uefiArchitecture{}, fmt.Errorf("unsupported UEFI architecture %q", value)
	}
}

func isEFISubsystem(value uint16) bool {
	return value >= imageSubsystemEFIApp && value <= imageSubsystemEFIROM
}

func uefiMachineName(value uint16) string {
	switch value {
	case imageFileMachineI386:
		return "x86"
	case imageFileMachineARM:
		return "ARM"
	case imageFileMachineARMNT:
		return "ARM Thumb-2"
	case imageFileMachineIA64:
		return "IA64"
	case imageFileMachineEBC:
		return "EFI bytecode"
	case imageFileMachineAMD64:
		return "x86-64"
	case imageFileMachineARM64:
		return "ARM64"
	case imageFileMachineRISCV64:
		return "RISC-V 64"
	case imageFileMachineLOONG64:
		return "LoongArch 64"
	default:
		return fmt.Sprintf("unknown machine 0x%04x", value)
	}
}

func uefiSubsystemName(value uint16) string {
	switch value {
	case imageSubsystemEFIApp:
		return "EFI application"
	case imageSubsystemEFIBoot:
		return "EFI boot-service driver"
	case imageSubsystemEFIRuntime:
		return "EFI runtime driver"
	case imageSubsystemEFIROM:
		return "EFI ROM image"
	default:
		return fmt.Sprintf("subsystem %d", value)
	}
}
