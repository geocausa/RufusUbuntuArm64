//go:build linux

package windowsmedia

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
)

const minimumMBRDiskBytes = uint64(8 * 1024 * 1024)

func writeSinglePartitionMBR(target *os.File, targetSize, sectorSize uint64) (partitionLayout, error) {
	return writeSinglePartitionMBRType(target, targetSize, sectorSize, 0x0c)
}

func writeSinglePartitionMBRType(target *os.File, targetSize, sectorSize uint64, partitionType byte) (partitionLayout, error) {
	if target == nil {
		return partitionLayout{}, errors.New("nil MBR target")
	}
	if partitionType == 0 {
		return partitionLayout{}, errors.New("MBR partition type must be nonzero")
	}
	layout, err := mbrLayoutForSize(targetSize, sectorSize)
	if err != nil {
		return partitionLayout{}, err
	}
	if err := writeMBR(target, sectorSize, []mbrPartition{{layout: layout, bootable: true, partitionType: partitionType}}); err != nil {
		return partitionLayout{}, err
	}
	return layout, nil
}

func writeUEFINTFSMBR(target *os.File, targetSize, sectorSize, bootImageSize uint64) (diskLayout, error) {
	if target == nil {
		return diskLayout{}, errors.New("nil MBR target")
	}
	layout, err := mbrUEFINTFSLayoutForSize(targetSize, sectorSize, bootImageSize)
	if err != nil {
		return diskLayout{}, err
	}
	if layout.Boot == nil {
		return diskLayout{}, errors.New("missing MBR UEFI:NTFS boot layout")
	}
	parts := []mbrPartition{
		{layout: layout.Data, bootable: true, partitionType: 0x07},
		{layout: *layout.Boot, bootable: false, partitionType: 0xef},
	}
	if err := writeMBR(target, sectorSize, parts); err != nil {
		return diskLayout{}, err
	}
	return layout, nil
}

type mbrPartition struct {
	layout        partitionLayout
	bootable      bool
	partitionType byte
}

func writeMBR(target *os.File, sectorSize uint64, partitions []mbrPartition) error {
	if len(partitions) == 0 || len(partitions) > 4 {
		return errors.New("MBR requires between one and four partitions")
	}
	sector := make([]byte, sectorSize)
	if _, err := rand.Read(sector[440:444]); err != nil {
		return fmt.Errorf("generate MBR disk signature: %w", err)
	}
	for index, part := range partitions {
		startSector := part.layout.PartitionStartBytes / sectorSize
		partitionSectors := part.layout.PartitionSizeBytes / sectorSize
		if startSector > uint64(^uint32(0)) || partitionSectors > uint64(^uint32(0)) {
			return errors.New("target is too large for MBR; use GPT")
		}
		entry := sector[446+index*16 : 462+index*16]
		if part.bootable {
			entry[0] = 0x80
		}
		entry[1], entry[2], entry[3] = 0xfe, 0xff, 0xff
		entry[4] = part.partitionType
		entry[5], entry[6], entry[7] = 0xfe, 0xff, 0xff
		binary.LittleEndian.PutUint32(entry[8:12], uint32(startSector))
		binary.LittleEndian.PutUint32(entry[12:16], uint32(partitionSectors))
	}
	sector[510], sector[511] = 0x55, 0xaa
	if _, err := target.WriteAt(sector, 0); err != nil {
		return fmt.Errorf("write MBR partition table: %w", err)
	}
	if err := target.Sync(); err != nil {
		return fmt.Errorf("sync MBR partition table: %w", err)
	}
	return nil
}

func mbrLayoutForSize(targetSize, sectorSize uint64) (partitionLayout, error) {
	if err := validateMBRGeometry(targetSize, sectorSize); err != nil {
		return partitionLayout{}, err
	}
	totalSectors := targetSize / sectorSize
	startSector := alignUp(oneMiB, sectorSize) / sectorSize
	if startSector >= totalSectors {
		return partitionLayout{}, errors.New("target has no usable MBR partition space after alignment")
	}
	partitionSectors := totalSectors - startSector
	if startSector > uint64(^uint32(0)) || partitionSectors > uint64(^uint32(0)) {
		return partitionLayout{}, errors.New("target is too large for a single MBR partition; use GPT")
	}
	return partitionLayout{PartitionStartBytes: startSector * sectorSize, PartitionSizeBytes: partitionSectors * sectorSize}, nil
}

func mbrUEFINTFSLayoutForSize(targetSize, sectorSize, bootImageSize uint64) (diskLayout, error) {
	if err := validateMBRGeometry(targetSize, sectorSize); err != nil {
		return diskLayout{}, err
	}
	if bootImageSize == 0 || bootImageSize%sectorSize != 0 {
		return diskLayout{}, fmt.Errorf("UEFI:NTFS image size %d is not aligned to logical sector size %d", bootImageSize, sectorSize)
	}
	dataStartBytes := alignUp(oneMiB, sectorSize)
	bootStartBytes := alignDown(targetSize-bootImageSize, oneMiB)
	if bootStartBytes <= dataStartBytes {
		return diskLayout{}, errors.New("target has insufficient space for MBR NTFS data and UEFI:NTFS boot partitions")
	}
	data := partitionLayout{PartitionStartBytes: dataStartBytes, PartitionSizeBytes: bootStartBytes - dataStartBytes}
	boot := partitionLayout{PartitionStartBytes: bootStartBytes, PartitionSizeBytes: bootImageSize}
	for _, part := range []partitionLayout{data, boot} {
		start := part.PartitionStartBytes / sectorSize
		size := part.PartitionSizeBytes / sectorSize
		if start > uint64(^uint32(0)) || size > uint64(^uint32(0)) {
			return diskLayout{}, errors.New("target is too large for an MBR UEFI:NTFS layout; use GPT")
		}
	}
	return diskLayout{Data: data, Boot: &boot}, nil
}

func validateMBRGeometry(targetSize, sectorSize uint64) error {
	if targetSize < minimumMBRDiskBytes {
		return fmt.Errorf("target is too small for an MBR Windows installer: %s", humanBytes(targetSize))
	}
	if sectorSize < 512 || sectorSize > 64*1024 || sectorSize&(sectorSize-1) != 0 {
		return fmt.Errorf("unsupported logical sector size %d", sectorSize)
	}
	if targetSize%sectorSize != 0 {
		return fmt.Errorf("target size %d is not aligned to logical sector size %d", targetSize, sectorSize)
	}
	return nil
}
