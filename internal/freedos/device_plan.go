package freedos

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

const (
	DevicePlanSchema = 2
	DeviceMode       = "freedos"
)

// DeviceRequest contains immutable device facts discovered without privileges.
// A later privileged executor must rediscover and revalidate every field.
type DeviceRequest struct {
	DevicePath        string `json:"device_path"`
	ExpectedIdentity  string `json:"expected_identity"`
	DeviceSizeBytes   uint64 `json:"device_size_bytes"`
	LogicalSectorSize uint64 `json:"logical_sector_size"`
	Label             string `json:"label"`
}

// DevicePlan binds the reviewed FreeDOS media bytes to one exact selected
// device. It is safe to display before authentication and grants no authority
// to open or modify the path.
type DevicePlan struct {
	Schema              int       `json:"schema"`
	Mode                string    `json:"mode"`
	Bootable            bool      `json:"bootable"`
	Destructive         bool      `json:"destructive"`
	TargetCPU           string    `json:"target_cpu"`
	Firmware            string    `json:"firmware"`
	Distribution        string    `json:"distribution"`
	DevicePath          string    `json:"device_path"`
	ExpectedIdentity    string    `json:"expected_identity"`
	DeviceSizeBytes     uint64    `json:"device_size_bytes"`
	LogicalSectorSize   uint64    `json:"logical_sector_size"`
	PartitionNumber     int       `json:"partition_number"`
	PartitionStartBytes uint64    `json:"partition_start_bytes"`
	PartitionSizeBytes  uint64    `json:"partition_size_bytes"`
	PartitionType       string    `json:"partition_type"`
	Filesystem          string    `json:"filesystem"`
	Label               string    `json:"label"`
	MutationBytes       uint64    `json:"mutation_bytes"`
	VerificationBytes   uint64    `json:"verification_bytes"`
	UntouchedBytes      uint64    `json:"untouched_bytes"`
	Media               MediaPlan `json:"media"`
	Warnings            []string  `json:"warnings"`
}

// BuildDevicePlan validates and canonicalizes an unprivileged identity-bound
// FreeDOS request. It performs no discovery and opens no file or device.
func BuildDevicePlan(request DeviceRequest) (DevicePlan, error) {
	path, err := canonicalFreeDOSDevicePath(request.DevicePath)
	if err != nil {
		return DevicePlan{}, err
	}
	identity := strings.TrimSpace(request.ExpectedIdentity)
	if identity == "" || identity != request.ExpectedIdentity {
		return DevicePlan{}, errors.New("expected device identity must be non-empty and canonical")
	}
	if request.LogicalSectorSize != freeDOSLogicalSectorSize {
		return DevicePlan{}, fmt.Errorf("FreeDOS device plan requires 512-byte logical sectors, not %d", request.LogicalSectorSize)
	}
	media, err := NewMediaPlan(request.DeviceSizeBytes, request.Label)
	if err != nil {
		return DevicePlan{}, err
	}
	mutationBytes, err := MediaExtentBytes(media)
	if err != nil {
		return DevicePlan{}, fmt.Errorf("calculate required FreeDOS extents: %w", err)
	}
	if mutationBytes >= request.DeviceSizeBytes {
		return DevicePlan{}, errors.New("required FreeDOS extents do not preserve free data space")
	}
	partitionStart := uint64(media.PartitionStartSector) * uint64(media.LogicalSectorSize)
	partitionSize := uint64(media.PartitionSectorCount) * uint64(media.LogicalSectorSize)
	manifest := PinnedManifest()
	plan := DevicePlan{
		Schema:              DevicePlanSchema,
		Mode:                DeviceMode,
		Bootable:            true,
		Destructive:         true,
		TargetCPU:           manifest.TargetCPU,
		Firmware:            manifest.Firmware,
		Distribution:        manifest.Distribution + " " + manifest.Version,
		DevicePath:          path,
		ExpectedIdentity:    identity,
		DeviceSizeBytes:     request.DeviceSizeBytes,
		LogicalSectorSize:   request.LogicalSectorSize,
		PartitionNumber:     1,
		PartitionStartBytes: partitionStart,
		PartitionSizeBytes:  partitionSize,
		PartitionType:       "0c",
		Filesystem:          "FAT32",
		Label:               media.Label,
		MutationBytes:       mutationBytes,
		VerificationBytes:   mutationBytes,
		UntouchedBytes:      request.DeviceSizeBytes - mutationBytes,
		Media:               media,
		Warnings:            freeDOSDeviceWarnings(),
	}
	if err := ValidateDevicePlan(plan); err != nil {
		return DevicePlan{}, err
	}
	return plan, nil
}

// ValidateDevicePlan rejects any altered identity, platform disclosure, media
// geometry, filesystem contract, extent accounting, or safety warning.
func ValidateDevicePlan(plan DevicePlan) error {
	if plan.Schema != DevicePlanSchema || plan.Mode != DeviceMode || !plan.Bootable || !plan.Destructive {
		return errors.New("invalid FreeDOS device-plan envelope")
	}
	path, err := canonicalFreeDOSDevicePath(plan.DevicePath)
	if err != nil || path != plan.DevicePath {
		return errors.New("FreeDOS device plan contains a non-canonical device path")
	}
	identity := strings.TrimSpace(plan.ExpectedIdentity)
	if identity == "" || identity != plan.ExpectedIdentity {
		return errors.New("FreeDOS device plan is missing a canonical expected identity")
	}
	manifest := PinnedManifest()
	if plan.TargetCPU != manifest.TargetCPU || plan.Firmware != manifest.Firmware ||
		plan.Distribution != manifest.Distribution+" "+manifest.Version {
		return errors.New("FreeDOS device plan platform boundary was altered")
	}
	if plan.LogicalSectorSize != freeDOSLogicalSectorSize || plan.DeviceSizeBytes != plan.Media.DiskSizeBytes {
		return errors.New("FreeDOS device plan size or logical-sector binding is inconsistent")
	}
	canonicalMedia, err := NewMediaPlan(plan.DeviceSizeBytes, plan.Label)
	if err != nil {
		return err
	}
	if canonicalMedia != plan.Media {
		return errors.New("FreeDOS device plan media contract was altered")
	}
	mutationBytes, err := MediaExtentBytes(canonicalMedia)
	if err != nil {
		return err
	}
	if plan.MutationBytes != mutationBytes || plan.VerificationBytes != mutationBytes ||
		plan.UntouchedBytes != plan.DeviceSizeBytes-mutationBytes || mutationBytes == 0 || mutationBytes >= plan.DeviceSizeBytes {
		return errors.New("FreeDOS device plan extent accounting was altered")
	}
	partitionStart := uint64(canonicalMedia.PartitionStartSector) * uint64(canonicalMedia.LogicalSectorSize)
	partitionSize := uint64(canonicalMedia.PartitionSectorCount) * uint64(canonicalMedia.LogicalSectorSize)
	if plan.PartitionNumber != 1 || plan.PartitionStartBytes != partitionStart || plan.PartitionSizeBytes != partitionSize ||
		plan.PartitionType != "0c" || plan.Filesystem != "FAT32" {
		return errors.New("FreeDOS device plan partition or filesystem contract was altered")
	}
	if !slices.Equal(plan.Warnings, freeDOSDeviceWarnings()) {
		return errors.New("FreeDOS device plan safety warnings are incomplete or altered")
	}
	return nil
}

// DeviceConfirmationPhrase binds the exact selected path, distribution, and
// firmware boundary reviewed before authentication.
func DeviceConfirmationPhrase(plan DevicePlan) (string, error) {
	if err := ValidateDevicePlan(plan); err != nil {
		return "", err
	}
	return fmt.Sprintf("WRITE FREEDOS 1.4 TO %s FOR X86 BIOS LEGACY", plan.DevicePath), nil
}

func canonicalFreeDOSDevicePath(value string) (string, error) {
	path := strings.TrimSpace(value)
	if !filepath.IsAbs(path) || !strings.HasPrefix(path, "/dev/") || filepath.Clean(path) != path {
		return "", fmt.Errorf("device path must be a canonical absolute path beneath /dev, not %q", value)
	}
	return path, nil
}

func freeDOSDeviceWarnings() []string {
	return []string{
		"This operation erases the complete selected drive.",
		"The resulting media runs only on x86-compatible processors.",
		"The resulting media requires BIOS or UEFI Legacy/CSM firmware and is not for UEFI-only systems.",
		"Software verification cannot prove that a particular physical PC will boot the media.",
	}
}
