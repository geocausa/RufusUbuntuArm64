//go:build linux

package linuxmedia

import (
	"errors"
	"fmt"

	"github.com/geocausa/RufusArm64/internal/uefintfs"
	"github.com/geocausa/RufusArm64/internal/volumelabel"
)

// ExtractedMediaPlan is the complete non-destructive filesystem and partition
// decision that must be confirmed and rebound before ISO Image mode erases a
// target. Boot is present only for NTFS/UEFI:NTFS media.
type ExtractedMediaPlan struct {
	FilesystemSelection ExtractedFilesystemSelection `json:"filesystem_selection"`
	PartitionScheme     string                       `json:"partition_scheme"`
	VolumeLabel         string                       `json:"volume_label"`
	ClusterSize         uint64                       `json:"cluster_size"`
	TargetSize          uint64                       `json:"target_size"`
	SectorSize          uint64                       `json:"sector_size"`
	Data                PartitionLayout              `json:"data"`
	Boot                *PartitionLayout             `json:"boot,omitempty"`
	RequiredDataBytes   uint64                       `json:"required_data_bytes"`
	UEFINTFSImageSize   uint64                       `json:"uefi_ntfs_image_size,omitempty"`
	UEFINTFSImageSHA256 string                       `json:"uefi_ntfs_image_sha256,omitempty"`
}

// PlanExtractedMedia resolves Automatic/FAT32/NTFS and calculates every target
// extent and capacity requirement without opening or mutating the target.
func PlanExtractedMedia(manifest Manifest, requestedFilesystem, requestedScheme, volumeLabel string, requestedClusterSize, targetSize, sectorSize uint64) (ExtractedMediaPlan, error) {
	selection, err := ResolveExtractedFilesystem(requestedFilesystem, manifest)
	if err != nil {
		return ExtractedMediaPlan{}, err
	}
	scheme, err := normalizeExtractedPartitionScheme(requestedScheme)
	if err != nil {
		return ExtractedMediaPlan{}, err
	}
	if targetSize < minimumExtractedDiskSize {
		return ExtractedMediaPlan{}, fmt.Errorf("target is too small for ISO Image mode: need at least %d bytes", minimumExtractedDiskSize)
	}

	plan := ExtractedMediaPlan{
		FilesystemSelection: selection,
		PartitionScheme:     scheme,
		TargetSize:          targetSize,
		SectorSize:          sectorSize,
	}
	switch selection.Selected {
	case ExtractedFilesystemFAT32:
		clusterSize, err := normalizeExtractedClusterSize(requestedClusterSize, sectorSize)
		if err != nil {
			return ExtractedMediaPlan{}, err
		}
		label, err := normalizePersistentLabel(volumeLabel)
		if err != nil {
			return ExtractedMediaPlan{}, err
		}
		required, err := EstimateFAT32BytesForCluster(manifest, clusterSize)
		if err != nil {
			return ExtractedMediaPlan{}, err
		}
		layout, err := PlanExtractedLayoutForScheme(targetSize, sectorSize, required, scheme)
		if err != nil {
			return ExtractedMediaPlan{}, err
		}
		if err := validateExtractedFAT32Capacity(layout.Partition.SizeBytes, clusterSize); err != nil {
			return ExtractedMediaPlan{}, err
		}
		plan.VolumeLabel = label
		plan.ClusterSize = clusterSize
		plan.Data = layout.Partition
		plan.RequiredDataBytes = required
		return plan, nil

	case ExtractedFilesystemNTFS:
		clusterSize, err := normalizeExtractedNTFSClusterSize(requestedClusterSize, sectorSize)
		if err != nil {
			return ExtractedMediaPlan{}, err
		}
		label, err := normalizeExtractedNTFSLabel(volumeLabel)
		if err != nil {
			return ExtractedMediaPlan{}, err
		}
		layout, err := uefintfs.PlanLayout(scheme, targetSize, sectorSize)
		if err != nil {
			return ExtractedMediaPlan{}, err
		}
		required, err := estimateExtractedNTFSBytes(manifest)
		if err != nil {
			return ExtractedMediaPlan{}, err
		}
		if required > layout.Data.SizeBytes {
			return ExtractedMediaPlan{}, fmt.Errorf("target has %d NTFS data bytes but the verified media tree needs at least %d", layout.Data.SizeBytes, required)
		}
		boot := PartitionLayout{Number: 2, StartBytes: layout.Boot.StartBytes, SizeBytes: layout.Boot.SizeBytes}
		plan.VolumeLabel = label
		plan.ClusterSize = clusterSize
		plan.Data = PartitionLayout{Number: 1, StartBytes: layout.Data.StartBytes, SizeBytes: layout.Data.SizeBytes}
		plan.Boot = &boot
		plan.RequiredDataBytes = required
		plan.UEFINTFSImageSize = uefintfs.ImageSize
		plan.UEFINTFSImageSHA256 = uefintfs.ImageSHA256
		return plan, nil

	default:
		return ExtractedMediaPlan{}, fmt.Errorf("unsupported resolved Linux ISO Image mode filesystem %q", selection.Selected)
	}
}

func normalizeExtractedNTFSClusterSize(requested, sectorSize uint64) (uint64, error) {
	if requested == 0 {
		requested = 4096
	}
	switch requested {
	case 4096, 8192, 16384, 32768:
	default:
		return 0, errors.New("ISO Image mode NTFS cluster size must be 4096, 8192, 16384, or 32768 bytes")
	}
	if sectorSize == 0 || requested < sectorSize || requested%sectorSize != 0 {
		return 0, fmt.Errorf("NTFS cluster size %d is not aligned to logical sector size %d", requested, sectorSize)
	}
	return requested, nil
}

func normalizeExtractedNTFSLabel(value string) (string, error) {
	return volumelabel.NTFS(value, "RUFUSARM64")
}

func estimateExtractedNTFSBytes(manifest Manifest) (uint64, error) {
	if len(manifest.Entries) == 0 || manifest.TotalBytes == 0 {
		return 0, errors.New("linux media manifest is empty")
	}
	margin := manifest.TotalBytes / 20
	if margin < 64*1024*1024 {
		margin = 64 * 1024 * 1024
	}
	entryOverhead := uint64(len(manifest.Entries)) * 4096
	if uint64(len(manifest.Entries)) != 0 && entryOverhead/uint64(len(manifest.Entries)) != 4096 {
		return 0, errors.New("linux media entry count overflows NTFS sizing")
	}
	if manifest.TotalBytes > ^uint64(0)-margin || manifest.TotalBytes+margin > ^uint64(0)-entryOverhead {
		return 0, errors.New("linux media size overflows NTFS sizing")
	}
	return manifest.TotalBytes + margin + entryOverhead, nil
}
