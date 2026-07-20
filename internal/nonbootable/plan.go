//go:build linux

// Package nonbootable defines the unprivileged, deterministic planning contract
// for data-only removable-drive formatting. It performs no device discovery and
// never opens or modifies a disk.
package nonbootable

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	SchemaVersion = 1
	Mode          = "non-bootable"

	SchemeGPT = "gpt"
	SchemeMBR = "mbr"

	FilesystemFAT32 = "fat32"
	FilesystemExFAT = "exfat"
	FilesystemNTFS  = "ntfs"
	FilesystemExt4  = "ext4"

	alignmentBytes   = uint64(1024 * 1024)
	tailReserveBytes = uint64(1024 * 1024)
	minimumDriveSize = uint64(64 * 1024 * 1024)
	maximumFAT32Size = uint64(2 * 1024 * 1024 * 1024 * 1024)
)

// Request contains already-discovered immutable device facts and user choices.
// A later privileged executor must rediscover and revalidate every device fact.
type Request struct {
	DevicePath        string `json:"device_path"`
	ExpectedIdentity  string `json:"expected_identity"`
	DeviceSizeBytes   uint64 `json:"device_size_bytes"`
	LogicalSectorSize uint64 `json:"logical_sector_size"`
	Scheme            string `json:"scheme"`
	Filesystem        string `json:"filesystem"`
	Label             string `json:"label"`
}

// Plan is safe to display before authentication. It is deliberately explicit
// that the result is data-only and not claimed bootable.
type Plan struct {
	Schema              int      `json:"schema"`
	Mode                string   `json:"mode"`
	Bootable            bool     `json:"bootable"`
	Destructive         bool     `json:"destructive"`
	DevicePath          string   `json:"device_path"`
	ExpectedIdentity    string   `json:"expected_identity"`
	DeviceSizeBytes     uint64   `json:"device_size_bytes"`
	LogicalSectorSize   uint64   `json:"logical_sector_size"`
	Scheme              string   `json:"scheme"`
	Filesystem          string   `json:"filesystem"`
	FilesystemDisplay   string   `json:"filesystem_display"`
	Label               string   `json:"label"`
	PartitionNumber     int      `json:"partition_number"`
	PartitionStartBytes uint64   `json:"partition_start_bytes"`
	PartitionSizeBytes  uint64   `json:"partition_size_bytes"`
	PartitionType       string   `json:"partition_type"`
	RequiredTools       []string `json:"required_tools"`
	Warnings            []string `json:"warnings"`
}

type filesystemContract struct {
	display       string
	mkfs          string
	check         string
	gptType       string
	mbrType       string
	maxLabelBytes int
	maxLabelRunes int
	fatLabel      bool
	maxSize       uint64
}

var filesystemContracts = map[string]filesystemContract{
	FilesystemFAT32: {
		display:       "FAT32",
		mkfs:          "mkfs.vfat",
		check:         "fsck.vfat",
		gptType:       "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
		mbrType:       "0c",
		maxLabelBytes: 11,
		fatLabel:      true,
		maxSize:       maximumFAT32Size,
	},
	FilesystemExFAT: {
		display:       "exFAT",
		mkfs:          "mkfs.exfat",
		check:         "fsck.exfat",
		gptType:       "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
		mbrType:       "07",
		maxLabelRunes: 15,
	},
	FilesystemNTFS: {
		display:       "NTFS",
		mkfs:          "mkfs.ntfs",
		check:         "ntfsfix",
		gptType:       "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
		mbrType:       "07",
		maxLabelRunes: 32,
	},
	FilesystemExt4: {
		display:       "ext4",
		mkfs:          "mkfs.ext4",
		check:         "e2fsck",
		gptType:       "0FC63DAF-8483-4772-8E79-3D69D8477DE4",
		mbrType:       "83",
		maxLabelBytes: 16,
	},
}

// BuildPlan validates and canonicalizes an unprivileged data-only format plan.
func BuildPlan(request Request) (Plan, error) {
	path, err := normalizeDevicePath(request.DevicePath)
	if err != nil {
		return Plan{}, err
	}
	identity := strings.TrimSpace(request.ExpectedIdentity)
	if identity == "" {
		return Plan{}, errors.New("expected device identity is required")
	}
	sectorSize := request.LogicalSectorSize
	if sectorSize != 512 && sectorSize != 4096 {
		return Plan{}, fmt.Errorf("logical sector size must be 512 or 4096 bytes, not %d", sectorSize)
	}
	if request.DeviceSizeBytes < minimumDriveSize {
		return Plan{}, fmt.Errorf("device is too small for guarded formatting: %d bytes", request.DeviceSizeBytes)
	}
	scheme, err := NormalizeScheme(request.Scheme)
	if err != nil {
		return Plan{}, err
	}
	filesystem, err := NormalizeFilesystem(request.Filesystem)
	if err != nil {
		return Plan{}, err
	}
	contract := filesystemContracts[filesystem]
	label, err := normalizeLabel(request.Label, contract)
	if err != nil {
		return Plan{}, err
	}

	start, partitionSize, err := canonicalGeometry(request.DeviceSizeBytes, sectorSize, contract)
	if err != nil {
		return Plan{}, err
	}
	partitionType := contract.gptType
	if scheme == SchemeMBR {
		partitionType = contract.mbrType
	}

	plan := Plan{
		Schema:              SchemaVersion,
		Mode:                Mode,
		Bootable:            false,
		Destructive:         true,
		DevicePath:          path,
		ExpectedIdentity:    identity,
		DeviceSizeBytes:     request.DeviceSizeBytes,
		LogicalSectorSize:   sectorSize,
		Scheme:              scheme,
		Filesystem:          filesystem,
		FilesystemDisplay:   contract.display,
		Label:               label,
		PartitionNumber:     1,
		PartitionStartBytes: start,
		PartitionSizeBytes:  partitionSize,
		PartitionType:       partitionType,
		RequiredTools:       requiredTools(contract),
		Warnings:            safetyWarnings(),
	}
	if err := validatePlan(plan); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

// NormalizeScheme canonicalizes supported partition-scheme aliases.
func NormalizeScheme(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "gpt":
		return SchemeGPT, nil
	case "mbr", "msdos":
		return SchemeMBR, nil
	default:
		return "", fmt.Errorf("partition scheme must be GPT or MBR, not %q", value)
	}
}

// NormalizeFilesystem canonicalizes supported data-filesystem aliases.
func NormalizeFilesystem(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "fat", "fat32", "vfat":
		return FilesystemFAT32, nil
	case "exfat":
		return FilesystemExFAT, nil
	case "ntfs":
		return FilesystemNTFS, nil
	case "ext4":
		return FilesystemExt4, nil
	default:
		return "", fmt.Errorf("filesystem must be FAT32, exFAT, NTFS, or ext4, not %q", value)
	}
}

// ConfirmationPhrase binds the exact device, filesystem, scheme, and label that
// were reviewed before authentication. A tampered or merely plausible plan is
// refused; only the exact canonical geometry and contracts are accepted.
func ConfirmationPhrase(plan Plan) (string, error) {
	if err := validatePlan(plan); err != nil {
		return "", err
	}
	phrase := fmt.Sprintf("FORMAT %s AS %s USING %s", plan.DevicePath, plan.FilesystemDisplay, strings.ToUpper(plan.Scheme))
	if plan.Label == "" {
		return phrase + " WITHOUT A LABEL", nil
	}
	return phrase + " LABEL " + plan.Label, nil
}

func validatePlan(plan Plan) error {
	if plan.Schema != SchemaVersion || plan.Mode != Mode || plan.Bootable || !plan.Destructive {
		return errors.New("invalid non-bootable plan envelope")
	}
	path, err := normalizeDevicePath(plan.DevicePath)
	if err != nil || path != plan.DevicePath {
		return errors.New("plan contains a non-canonical device path")
	}
	identity := strings.TrimSpace(plan.ExpectedIdentity)
	if identity == "" || identity != plan.ExpectedIdentity {
		return errors.New("plan is missing a canonical expected device identity")
	}
	if plan.LogicalSectorSize != 512 && plan.LogicalSectorSize != 4096 {
		return errors.New("plan has an unsupported logical sector size")
	}
	contract, ok := filesystemContracts[plan.Filesystem]
	if !ok || contract.display != plan.FilesystemDisplay {
		return errors.New("plan has an inconsistent filesystem contract")
	}
	if plan.Scheme != SchemeGPT && plan.Scheme != SchemeMBR {
		return errors.New("plan has an unsupported partition scheme")
	}
	expectedStart, expectedSize, err := canonicalGeometry(plan.DeviceSizeBytes, plan.LogicalSectorSize, contract)
	if err != nil {
		return err
	}
	if plan.PartitionNumber != 1 || plan.PartitionStartBytes != expectedStart || plan.PartitionSizeBytes != expectedSize {
		return errors.New("plan partition geometry is not canonical for the device")
	}
	expectedType := contract.gptType
	if plan.Scheme == SchemeMBR {
		expectedType = contract.mbrType
	}
	if plan.PartitionType != expectedType {
		return errors.New("plan partition type does not match the scheme and filesystem")
	}
	label, err := normalizeLabel(plan.Label, contract)
	if err != nil || label != plan.Label {
		return errors.New("plan contains a non-canonical filesystem label")
	}
	if !slices.Equal(plan.RequiredTools, requiredTools(contract)) {
		return errors.New("plan required-tool contract is inconsistent")
	}
	if !slices.Equal(plan.Warnings, safetyWarnings()) {
		return errors.New("plan safety warnings are incomplete or altered")
	}
	return nil
}

func canonicalGeometry(deviceSize, sectorSize uint64, contract filesystemContract) (uint64, uint64, error) {
	if sectorSize != 512 && sectorSize != 4096 {
		return 0, 0, errors.New("unsupported logical sector size")
	}
	if deviceSize < minimumDriveSize {
		return 0, 0, fmt.Errorf("device is too small for guarded formatting: %d bytes", deviceSize)
	}
	start := alignUp(alignmentBytes, sectorSize)
	usableEnd := alignDown(deviceSize-tailReserveBytes, sectorSize)
	if usableEnd <= start {
		return 0, 0, errors.New("device has no usable aligned partition capacity")
	}
	partitionSize := usableEnd - start
	if contract.maxSize != 0 && partitionSize > contract.maxSize {
		return 0, 0, fmt.Errorf("%s is limited to %d bytes by the current compatibility contract", contract.display, contract.maxSize)
	}
	return start, partitionSize, nil
}

func requiredTools(contract filesystemContract) []string {
	return []string{"sfdisk", "blockdev", "udevadm", contract.mkfs, contract.check}
}

func safetyWarnings() []string {
	return []string{
		"This operation erases the complete selected drive.",
		"The resulting media is data-only and is not claimed bootable.",
	}
}

func normalizeDevicePath(value string) (string, error) {
	path := strings.TrimSpace(value)
	if !filepath.IsAbs(path) || !strings.HasPrefix(path, "/dev/") || filepath.Clean(path) != path {
		return "", fmt.Errorf("device path must be a canonical absolute path beneath /dev, not %q", value)
	}
	return path, nil
}

func normalizeLabel(value string, contract filesystemContract) (string, error) {
	if !utf8.ValidString(value) {
		return "", errors.New("filesystem label is not valid UTF-8")
	}
	if strings.TrimSpace(value) != value {
		return "", errors.New("filesystem label must not have leading or trailing whitespace")
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return "", errors.New("filesystem label must not contain control characters")
		}
	}
	if contract.fatLabel {
		value = strings.ToUpper(value)
		for _, character := range value {
			if !(character >= 'A' && character <= 'Z') && !(character >= '0' && character <= '9') && character != ' ' && character != '_' && character != '-' {
				return "", errors.New("FAT32 label may contain only ASCII letters, digits, spaces, underscore, or hyphen")
			}
		}
	}
	if contract.maxLabelBytes != 0 && len([]byte(value)) > contract.maxLabelBytes {
		return "", fmt.Errorf("%s label exceeds %d bytes", contract.display, contract.maxLabelBytes)
	}
	if contract.maxLabelRunes != 0 && utf8.RuneCountInString(value) > contract.maxLabelRunes {
		return "", fmt.Errorf("%s label exceeds %d characters", contract.display, contract.maxLabelRunes)
	}
	return value, nil
}

func alignUp(value, alignment uint64) uint64 {
	return (value + alignment - 1) / alignment * alignment
}

func alignDown(value, alignment uint64) uint64 {
	return value / alignment * alignment
}
