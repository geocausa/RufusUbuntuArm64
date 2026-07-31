//go:build linux

// Package windowstogo implements the deliberately narrow, experimental
// Windows To Go planning and materialization boundary. It does not claim that
// modern Windows supports Windows To Go or that physical firmware will boot it.
package windowstogo

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/geocausa/RufusArm64/internal/windowsconfig"
)

const (
	SchemaVersion = 1
	Mode          = "windows-to-go"

	alignmentBytes     = uint64(1024 * 1024)
	espSizeBytes       = uint64(260 * 1024 * 1024)
	tailReserveBytes   = uint64(1024 * 1024)
	minimumTargetBytes = uint64(29 * 1024 * 1024 * 1024)
	minimumFreeBytes   = uint64(2 * 1024 * 1024 * 1024)

	efiSystemPartitionGUID = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
	basicDataPartitionGUID = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"
	noDefaultDriveLetter   = uint64(1) << 63
)

type Request struct {
	TargetPath        string
	ExpectedIdentity  string
	TargetSizeBytes   uint64
	LogicalSectorSize uint64
	Metadata          windowsconfig.MediaMetadata
	ImageIndex        int
}

type Partition struct {
	Number     int    `json:"number"`
	Role       string `json:"role"`
	StartBytes uint64 `json:"start_bytes"`
	SizeBytes  uint64 `json:"size_bytes"`
	TypeGUID   string `json:"type_guid"`
	Attributes uint64 `json:"attributes,omitempty"`
	GPTName    string `json:"gpt_name"`
	Filesystem string `json:"filesystem"`
	Label      string `json:"label"`
}

type Plan struct {
	Schema            int                        `json:"schema"`
	Mode              string                     `json:"mode"`
	Experimental      bool                       `json:"experimental"`
	BootableClaim     bool                       `json:"bootable_claim"`
	TargetPath        string                     `json:"target_path"`
	ExpectedIdentity  string                     `json:"expected_identity"`
	TargetSizeBytes   uint64                     `json:"target_size_bytes"`
	LogicalSectorSize uint64                     `json:"logical_sector_size"`
	PartitionScheme   string                     `json:"partition_scheme"`
	TargetSystem      string                     `json:"target_system"`
	Architecture      string                     `json:"architecture"`
	ProductName       string                     `json:"product_name"`
	Version           string                     `json:"version"`
	InstallationType  string                     `json:"installation_type"`
	Image             windowsconfig.WindowsImage `json:"image"`
	ESP               Partition                  `json:"esp"`
	OS                Partition                  `json:"os"`
	MinimumFreeBytes  uint64                     `json:"minimum_free_bytes"`
	RequiredTools     []string                   `json:"required_tools"`
	Warnings          []string                   `json:"warnings"`
}

func BuildPlan(request Request) (Plan, error) {
	path := strings.TrimSpace(request.TargetPath)
	if !filepath.IsAbs(path) || !strings.HasPrefix(path, "/dev/") || filepath.Clean(path) != path {
		return Plan{}, fmt.Errorf("target path must be a canonical whole-device path beneath /dev, not %q", request.TargetPath)
	}
	identity := strings.TrimSpace(request.ExpectedIdentity)
	if identity == "" || identity != request.ExpectedIdentity {
		return Plan{}, errors.New("an exact canonical target identity is required")
	}
	if request.LogicalSectorSize != 512 && request.LogicalSectorSize != 4096 {
		return Plan{}, fmt.Errorf("logical sector size must be 512 or 4096 bytes, not %d", request.LogicalSectorSize)
	}
	if request.TargetSizeBytes < minimumTargetBytes {
		return Plan{}, fmt.Errorf("experimental Windows To Go requires a nominal 32 GB-class target of at least %d bytes", minimumTargetBytes)
	}
	if request.TargetSizeBytes%request.LogicalSectorSize != 0 {
		return Plan{}, errors.New("target capacity must be an exact logical-sector multiple")
	}
	profile := windowsconfig.Capabilities(request.Metadata)
	if !profile.Recognized || profile.Generation != "11" || profile.Family != "client" || profile.Architecture != "arm64" {
		return Plan{}, errors.New("experimental Windows To Go currently requires positively identified Windows 11 client ARM64 media")
	}
	if request.Metadata.ImageCount <= 0 || len(request.Metadata.Images) != request.Metadata.ImageCount {
		return Plan{}, errors.New("complete exact Windows image metadata is required")
	}
	image, err := selectImage(request.Metadata.Images, request.ImageIndex)
	if err != nil {
		return Plan{}, err
	}
	if image.TotalBytes == 0 {
		return Plan{}, errors.New("the selected Windows image does not publish a positive expanded size")
	}
	if strings.TrimSpace(image.DefaultLanguage) == "" {
		return Plan{}, errors.New("the selected Windows image does not publish a default language")
	}

	start := alignUp(alignmentBytes, request.LogicalSectorSize)
	espSize := alignUp(espSizeBytes, request.LogicalSectorSize)
	osStart := alignUp(start+espSize, alignmentBytes)
	usableEnd := alignDown(request.TargetSizeBytes-tailReserveBytes, request.LogicalSectorSize)
	if usableEnd <= osStart {
		return Plan{}, errors.New("target has no usable Windows partition capacity after the ESP")
	}
	osSize := usableEnd - osStart
	if image.TotalBytes > ^uint64(0)-minimumFreeBytes || osSize < image.TotalBytes+minimumFreeBytes {
		return Plan{}, fmt.Errorf("selected image requires %d bytes plus %d bytes headroom, but the Windows partition would contain %d bytes", image.TotalBytes, minimumFreeBytes, osSize)
	}

	plan := Plan{
		Schema:            SchemaVersion,
		Mode:              Mode,
		Experimental:      true,
		BootableClaim:     false,
		TargetPath:        path,
		ExpectedIdentity:  identity,
		TargetSizeBytes:   request.TargetSizeBytes,
		LogicalSectorSize: request.LogicalSectorSize,
		PartitionScheme:   "gpt",
		TargetSystem:      "uefi",
		Architecture:      "arm64",
		ProductName:       request.Metadata.ProductName,
		Version:           request.Metadata.Version,
		InstallationType:  request.Metadata.InstallationType,
		Image:             image,
		ESP: Partition{
			Number: 1, Role: "efi-system", StartBytes: start, SizeBytes: espSize,
			TypeGUID: efiSystemPartitionGUID, GPTName: "EFI System Partition", Filesystem: "fat32", Label: "",
		},
		OS: Partition{
			Number: 2, Role: "windows", StartBytes: osStart, SizeBytes: osSize,
			TypeGUID: basicDataPartitionGUID, Attributes: noDefaultDriveLetter, GPTName: "Windows",
			Filesystem: "ntfs", Label: "WINDOWS TO GO",
		},
		MinimumFreeBytes: minimumFreeBytes,
		RequiredTools:    requiredTools(),
		Warnings:         warnings(),
	}
	if err := ValidatePlan(plan); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

func ValidatePlan(plan Plan) error {
	if plan.Schema != SchemaVersion || plan.Mode != Mode || !plan.Experimental || plan.BootableClaim {
		return errors.New("invalid experimental Windows To Go plan envelope")
	}
	path := strings.TrimSpace(plan.TargetPath)
	if !filepath.IsAbs(path) || !strings.HasPrefix(path, "/dev/") || filepath.Clean(path) != path || path != plan.TargetPath {
		return errors.New("windows To Go plan has a non-canonical target path")
	}
	identity := strings.TrimSpace(plan.ExpectedIdentity)
	if identity == "" || identity != plan.ExpectedIdentity {
		return errors.New("windows To Go plan has a non-canonical target identity")
	}
	if plan.LogicalSectorSize != 512 && plan.LogicalSectorSize != 4096 {
		return errors.New("windows To Go plan has an unsupported logical sector size")
	}
	if plan.TargetSizeBytes < minimumTargetBytes || plan.TargetSizeBytes%plan.LogicalSectorSize != 0 {
		return errors.New("windows To Go plan has invalid target capacity")
	}
	if plan.PartitionScheme != "gpt" || plan.TargetSystem != "uefi" || plan.Architecture != "arm64" ||
		!strings.EqualFold(strings.TrimSpace(plan.InstallationType), "client") {
		return errors.New("windows To Go plan escaped the admitted GPT/UEFI/ARM64 client boundary")
	}
	if plan.Image.Index <= 0 || plan.Image.Name == "" || plan.Image.TotalBytes == 0 || plan.Image.DefaultLanguage == "" {
		return errors.New("windows To Go plan has incomplete image evidence")
	}
	expectedStart := alignUp(alignmentBytes, plan.LogicalSectorSize)
	expectedESPSize := alignUp(espSizeBytes, plan.LogicalSectorSize)
	expectedOSStart := alignUp(expectedStart+expectedESPSize, alignmentBytes)
	expectedEnd := alignDown(plan.TargetSizeBytes-tailReserveBytes, plan.LogicalSectorSize)
	if expectedEnd <= expectedOSStart {
		return errors.New("windows To Go plan has no canonical Windows partition capacity")
	}
	if plan.ESP.Number != 1 || plan.ESP.Role != "efi-system" || plan.ESP.TypeGUID != efiSystemPartitionGUID ||
		plan.ESP.GPTName != "EFI System Partition" || plan.ESP.Filesystem != "fat32" || plan.ESP.Label != "" || plan.ESP.Attributes != 0 ||
		plan.ESP.StartBytes != expectedStart || plan.ESP.SizeBytes != expectedESPSize {
		return errors.New("windows To Go ESP contract is inconsistent")
	}
	if plan.OS.Number != 2 || plan.OS.Role != "windows" || plan.OS.TypeGUID != basicDataPartitionGUID ||
		plan.OS.Attributes != noDefaultDriveLetter || plan.OS.GPTName != "Windows" || plan.OS.Filesystem != "ntfs" || plan.OS.Label != "WINDOWS TO GO" ||
		plan.OS.StartBytes != expectedOSStart || plan.OS.SizeBytes != expectedEnd-expectedOSStart {
		return errors.New("windows To Go OS partition contract is inconsistent")
	}
	if plan.MinimumFreeBytes != minimumFreeBytes || plan.Image.TotalBytes > ^uint64(0)-plan.MinimumFreeBytes ||
		plan.OS.SizeBytes < plan.Image.TotalBytes+plan.MinimumFreeBytes {
		return errors.New("windows To Go plan does not retain the required free-space headroom")
	}
	if !slices.Equal(plan.RequiredTools, requiredTools()) || !slices.Equal(plan.Warnings, warnings()) {
		return errors.New("windows To Go plan tooling or warning contract was altered")
	}
	return nil
}

func requiredTools() []string {
	return []string{
		"blkid", "blockdev", "findmnt", "fsck.vfat", "hivexsh", "hivexml",
		"lsblk", "mkfs.ntfs", "mkfs.vfat", "mount", "ntfsfix", "udevadm",
		"umount", "wipefs", "wimlib-imagex",
	}
}

func warnings() []string {
	return []string{
		"This operation erases the complete selected target drive.",
		"Microsoft removed Windows To Go support; modern Windows compatibility is not claimed.",
		"The resulting media is experimental and physical UEFI boot is not established by software checks.",
		"wimlib cannot restore encrypted files or Windows extended attributes; media containing them may be unsuitable.",
	}
}

func selectImage(images []windowsconfig.WindowsImage, index int) (windowsconfig.WindowsImage, error) {
	seen := make(map[int]struct{}, len(images))
	var selected windowsconfig.WindowsImage
	for _, image := range images {
		if image.Index <= 0 || image.Name == "" {
			return windowsconfig.WindowsImage{}, errors.New("windows image metadata is incomplete")
		}
		if _, duplicate := seen[image.Index]; duplicate {
			return windowsconfig.WindowsImage{}, fmt.Errorf("windows image index %d is duplicated", image.Index)
		}
		seen[image.Index] = struct{}{}
		if image.Index == index {
			selected = image
		}
	}
	if selected.Index == 0 {
		return windowsconfig.WindowsImage{}, fmt.Errorf("windows image index %d is not present in the inspected media", index)
	}
	return selected, nil
}

func alignUp(value, alignment uint64) uint64 {
	return (value + alignment - 1) / alignment * alignment
}

func alignDown(value, alignment uint64) uint64 {
	return value / alignment * alignment
}
