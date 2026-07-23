//go:build linux

package windowsmedia

import (
	"errors"
	"fmt"
	"strings"
)

func normalizePartitionScheme(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "auto":
		return "auto", nil
	case "gpt":
		return "gpt", nil
	case "mbr":
		return "mbr", nil
	default:
		return "", fmt.Errorf("partition scheme must be Automatic, GPT, or MBR, not %q", value)
	}
}

func normalizeTargetSystem(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "auto":
		return "auto", nil
	case "uefi", "uefi-non-csm":
		return "uefi", nil
	case "bios", "legacy", "legacy-bios", "bios-csm":
		return "bios", nil
	default:
		return "", fmt.Errorf("target system must be Automatic, UEFI, or BIOS/CSM, not %q", value)
	}
}

func resolveWindowsLayout(plan mediaPlan, requestedScheme, requestedTarget string) (string, string, error) {
	scheme, err := normalizePartitionScheme(requestedScheme)
	if err != nil {
		return "", "", err
	}
	target, err := normalizeTargetSystem(requestedTarget)
	if err != nil {
		return "", "", err
	}
	hasUEFI := plan.HasARM64 || plan.HasX64 || plan.HasX86
	if target == "auto" {
		switch {
		case hasUEFI:
			target = "uefi"
		case plan.HasBIOS:
			target = "bios"
		default:
			return "", "", errors.New("automatic Windows layout could not identify a supported UEFI or legacy-BIOS boot path")
		}
	}
	if target == "uefi" && !hasUEFI {
		return "", "", errors.New("the selected Windows ISO has no supported standard UEFI fallback loader")
	}
	if target == "bios" && !plan.HasBIOS {
		return "", "", errors.New("the selected Windows ISO is not proven legacy-BIOS bootable")
	}
	if scheme == "auto" {
		if target == "bios" {
			scheme = "mbr"
		} else {
			scheme = "gpt"
		}
	}
	if target == "bios" && scheme != "mbr" {
		return "", "", errors.New("legacy BIOS/CSM Windows media requires the MBR partition scheme")
	}
	return scheme, target, nil
}

func normalizeFilesystem(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "auto", "automatic":
		return "auto", nil
	case "fat", "fat32", "vfat":
		return "fat32", nil
	case "ntfs":
		return "ntfs", nil
	default:
		return "", fmt.Errorf("filesystem must be Automatic, FAT32, or NTFS, not %q", value)
	}
}

func resolveFilesystem(requested string, fatCompatibilityErr error) (string, error) {
	filesystem, err := normalizeFilesystem(requested)
	if err != nil {
		return "", err
	}
	switch filesystem {
	case "fat32":
		if fatCompatibilityErr != nil {
			return "", fatCompatibilityErr
		}
		return filesystem, nil
	case "ntfs":
		return filesystem, nil
	case "auto":
		if fatCompatibilityErr != nil {
			return "ntfs", nil
		}
		return "fat32", nil
	default:
		return "", errors.New("internal filesystem selection error")
	}
}

// clusterSectorCount converts a requested FAT cluster size in bytes into the
// sectors-per-cluster value accepted by mkfs.vfat. Zero means automatic.
func clusterSectorCount(clusterBytes, sectorSize uint64) (uint64, error) {
	if clusterBytes == 0 {
		return 0, nil
	}
	if clusterBytes < sectorSize || clusterBytes%sectorSize != 0 {
		return 0, fmt.Errorf("cluster size %d is not aligned to logical sector size %d", clusterBytes, sectorSize)
	}
	sectors := clusterBytes / sectorSize
	if sectors > 128 || sectors&(sectors-1) != 0 {
		return 0, unsupportedClusterSize(clusterBytes)
	}
	if err := validateClusterBytes(clusterBytes); err != nil {
		return 0, err
	}
	return sectors, nil
}

func validateClusterBytes(clusterBytes uint64) error {
	if clusterBytes == 0 {
		return nil
	}
	if clusterBytes < 4*1024 || clusterBytes > 32*1024 || clusterBytes&(clusterBytes-1) != 0 {
		return unsupportedClusterSize(clusterBytes)
	}
	return nil
}

func unsupportedClusterSize(clusterBytes uint64) error {
	return fmt.Errorf("cluster size %d is unsupported; choose automatic, 4 KiB, 8 KiB, 16 KiB, or 32 KiB", clusterBytes)
}
