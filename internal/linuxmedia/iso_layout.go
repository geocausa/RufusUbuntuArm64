//go:build linux

package linuxmedia

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
)

const (
	minimumISOImageDiskSize = uint64(512 * 1024 * 1024)
	minimumISOImageHeadroom = uint64(64 * 1024 * 1024)
	maximumISOImageFAT32    = uint64(1024 * 1024 * 1024 * 1024)
)

// ISOImageLayout describes the fresh GPT/UEFI/FAT32 layout used by Linux ISO
// Image mode. Unlike DD mode, this layout is newly created and contains one
// conventional writable EFI System Partition populated from the verified ISO
// filesystem tree.
type ISOImageLayout struct {
	SectorSize    uint64          `json:"sector_size"`
	TargetSize    uint64          `json:"target_size"`
	RequiredBytes uint64          `json:"required_bytes"`
	Partition     PartitionLayout `json:"partition"`
}

// PlanISOImageLayout reserves the normal primary and backup GPT metadata and
// uses the remaining aligned space for one FAT32 EFI System Partition. The
// required byte count already includes per-entry FAT32 allocation overhead;
// an additional fixed headroom prevents a marginally fitting image from being
// accepted before mkfs metadata and future file growth are considered.
func PlanISOImageLayout(targetSize, sectorSize, requiredBytes uint64) (ISOImageLayout, error) {
	if targetSize > uint64(math.MaxInt64) {
		return ISOImageLayout{}, errors.New("ISO Image mode target exceeds the supported signed file-offset range")
	}
	if targetSize < minimumISOImageDiskSize {
		return ISOImageLayout{}, fmt.Errorf("target is too small for Linux ISO Image mode: need at least %d bytes", minimumISOImageDiskSize)
	}
	if sectorSize < 512 || sectorSize > fat32ClusterBytes || sectorSize&(sectorSize-1) != 0 {
		return ISOImageLayout{}, fmt.Errorf("unsupported logical sector size %d", sectorSize)
	}
	if targetSize%sectorSize != 0 {
		return ISOImageLayout{}, fmt.Errorf("target size %d is not aligned to logical sector size %d", targetSize, sectorSize)
	}
	if requiredBytes == 0 {
		return ISOImageLayout{}, errors.New("Linux ISO media tree is empty")
	}
	if requiredBytes > ^uint64(0)-minimumISOImageHeadroom {
		return ISOImageLayout{}, errors.New("Linux ISO media size overflows the FAT32 capacity calculation")
	}

	totalLBAs := targetSize / sectorSize
	entryBytes := uint64(layoutGPTEntryCount * layoutGPTEntrySize)
	entryLBAs := (entryBytes + sectorSize - 1) / sectorSize
	primaryEntriesLBA := uint64(2)
	firstUsableLBA := primaryEntriesLBA + entryLBAs
	backupHeaderLBA := totalLBAs - 1
	backupEntriesLBA := backupHeaderLBA - entryLBAs
	lastUsableLBA := backupEntriesLBA - 1

	partitionStartLBA := alignLayout(layoutAlignment, sectorSize) / sectorSize
	if partitionStartLBA < firstUsableLBA {
		partitionStartLBA = firstUsableLBA
	}
	if partitionStartLBA > lastUsableLBA {
		return ISOImageLayout{}, errors.New("target has no usable space after GPT metadata")
	}
	partitionSize := (lastUsableLBA - partitionStartLBA + 1) * sectorSize
	if partitionSize > maximumISOImageFAT32 {
		return ISOImageLayout{}, fmt.Errorf("ISO Image mode FAT32 partition would exceed the supported %d-byte limit", maximumISOImageFAT32)
	}
	minimumBytes := requiredBytes + minimumISOImageHeadroom
	if partitionSize < minimumBytes {
		return ISOImageLayout{}, fmt.Errorf("target needs at least %d usable FAT32 bytes but provides %d", minimumBytes, partitionSize)
	}

	layout := ISOImageLayout{
		SectorSize:    sectorSize,
		TargetSize:    targetSize,
		RequiredBytes: requiredBytes,
		Partition: PartitionLayout{
			Number:     1,
			StartBytes: partitionStartLBA * sectorSize,
			SizeBytes:  partitionSize,
		},
	}
	if err := validateISOImageLayout(layout); err != nil {
		return ISOImageLayout{}, err
	}
	return layout, nil
}

// WriteISOImageGPT writes backup metadata first, then primary metadata and a
// protective MBR, synchronizing and reading every byte back before returning.
func WriteISOImageGPT(target layoutTarget, layout ISOImageLayout, label string) error {
	if target == nil {
		return errors.New("nil ISO Image mode layout target")
	}
	if err := validateISOImageLayout(layout); err != nil {
		return err
	}
	label, err := normalizePersistentLabel(label)
	if err != nil {
		return err
	}

	sectorSize := layout.SectorSize
	totalLBAs := layout.TargetSize / sectorSize
	entryBytes := uint64(layoutGPTEntryCount * layoutGPTEntrySize)
	entryLBAs := (entryBytes + sectorSize - 1) / sectorSize
	primaryEntriesLBA := uint64(2)
	backupHeaderLBA := totalLBAs - 1
	backupEntriesLBA := backupHeaderLBA - entryLBAs
	firstUsableLBA := primaryEntriesLBA + entryLBAs
	lastUsableLBA := backupEntriesLBA - 1

	diskGUID, err := randomLayoutGUID(rand.Reader)
	if err != nil {
		return err
	}
	partitionGUID, err := randomLayoutGUID(rand.Reader)
	if err != nil {
		return err
	}
	entries := make([]byte, entryLBAs*sectorSize)
	writeISOImageLayoutEntry(entries[:layoutGPTEntrySize], layoutEFIType, partitionGUID, layout.Partition, sectorSize, label)
	entriesCRC := crc32.ChecksumIEEE(entries[:entryBytes])
	primary := makeLayoutGPTHeader(sectorSize, 1, backupHeaderLBA, firstUsableLBA, lastUsableLBA, diskGUID, primaryEntriesLBA, entriesCRC)
	backup := makeLayoutGPTHeader(sectorSize, backupHeaderLBA, 1, firstUsableLBA, lastUsableLBA, diskGUID, backupEntriesLBA, entriesCRC)
	protective := makeLayoutProtectiveMBR(totalLBAs, sectorSize)

	for _, write := range []struct {
		offset uint64
		data   []byte
		name   string
	}{
		{backupEntriesLBA * sectorSize, entries, "backup GPT entries"},
		{backupHeaderLBA * sectorSize, backup, "backup GPT header"},
	} {
		if err := writeLayoutAt(target, write.data, write.offset); err != nil {
			return fmt.Errorf("write ISO Image mode %s: %w", write.name, err)
		}
	}
	if err := target.Sync(); err != nil {
		return fmt.Errorf("sync backup ISO Image mode GPT: %w", err)
	}
	for _, write := range []struct {
		offset uint64
		data   []byte
		name   string
	}{
		{primaryEntriesLBA * sectorSize, entries, "primary GPT entries"},
		{sectorSize, primary, "primary GPT header"},
		{0, protective, "protective MBR"},
	} {
		if err := writeLayoutAt(target, write.data, write.offset); err != nil {
			return fmt.Errorf("write ISO Image mode %s: %w", write.name, err)
		}
	}
	if err := target.Sync(); err != nil {
		return fmt.Errorf("sync primary ISO Image mode GPT: %w", err)
	}
	return verifyISOImageGPT(target, layout, label, entriesCRC, diskGUID, partitionGUID)
}

func validateISOImageLayout(layout ISOImageLayout) error {
	if layout.TargetSize > uint64(math.MaxInt64) || layout.TargetSize < minimumISOImageDiskSize ||
		layout.SectorSize < 512 || layout.SectorSize > fat32ClusterBytes || layout.SectorSize&(layout.SectorSize-1) != 0 ||
		layout.TargetSize%layout.SectorSize != 0 {
		return errors.New("ISO Image mode layout has invalid target geometry")
	}
	part := layout.Partition
	if part.Number != 1 || part.StartBytes%layout.SectorSize != 0 || part.SizeBytes == 0 || part.SizeBytes%layout.SectorSize != 0 ||
		part.StartBytes > layout.TargetSize || part.SizeBytes > layout.TargetSize-part.StartBytes || part.SizeBytes > maximumISOImageFAT32 {
		return errors.New("ISO Image mode layout contains an invalid FAT32 partition extent")
	}
	entryBytes := uint64(layoutGPTEntryCount * layoutGPTEntrySize)
	entryLBAs := (entryBytes + layout.SectorSize - 1) / layout.SectorSize
	backupEntriesStart := layout.TargetSize - (entryLBAs+1)*layout.SectorSize
	if part.StartBytes+part.SizeBytes > backupEntriesStart {
		return errors.New("ISO Image mode FAT32 partition overlaps backup GPT metadata")
	}
	if layout.RequiredBytes == 0 || layout.RequiredBytes > part.SizeBytes || part.SizeBytes-layout.RequiredBytes < minimumISOImageHeadroom {
		return errors.New("ISO Image mode layout does not retain the required FAT32 headroom")
	}
	return nil
}

func verifyISOImageGPT(target io.ReaderAt, layout ISOImageLayout, label string, entriesCRC uint32, diskGUID, partitionGUID [16]byte) error {
	sectorSize := layout.SectorSize
	totalLBAs := layout.TargetSize / sectorSize
	entryBytes := uint64(layoutGPTEntryCount * layoutGPTEntrySize)
	entryLBAs := (entryBytes + sectorSize - 1) / sectorSize
	backupHeaderLBA := totalLBAs - 1
	backupEntriesLBA := backupHeaderLBA - entryLBAs

	protectiveMBR := make([]byte, sectorSize)
	primaryHeader := make([]byte, sectorSize)
	backupHeader := make([]byte, sectorSize)
	primaryEntries := make([]byte, entryLBAs*sectorSize)
	backupEntries := make([]byte, entryLBAs*sectorSize)
	for _, read := range []struct {
		offset uint64
		data   []byte
		name   string
	}{
		{0, protectiveMBR, "protective MBR"},
		{sectorSize, primaryHeader, "primary GPT header"},
		{backupHeaderLBA * sectorSize, backupHeader, "backup GPT header"},
		{2 * sectorSize, primaryEntries, "primary GPT entries"},
		{backupEntriesLBA * sectorSize, backupEntries, "backup GPT entries"},
	} {
		if _, err := target.ReadAt(read.data, int64(read.offset)); err != nil {
			return fmt.Errorf("read back ISO Image mode %s: %w", read.name, err)
		}
	}
	if !bytes.Equal(protectiveMBR, makeLayoutProtectiveMBR(totalLBAs, sectorSize)) {
		return errors.New("ISO Image mode protective MBR verification failed")
	}
	expectedEntries := make([]byte, entryLBAs*sectorSize)
	writeISOImageLayoutEntry(expectedEntries[:layoutGPTEntrySize], layoutEFIType, partitionGUID, layout.Partition, sectorSize, label)
	if !bytes.Equal(primaryEntries, expectedEntries) || !bytes.Equal(backupEntries, expectedEntries) || crc32.ChecksumIEEE(primaryEntries[:entryBytes]) != entriesCRC {
		return errors.New("ISO Image mode GPT entry-table verification failed")
	}
	firstUsableLBA := uint64(2) + entryLBAs
	lastUsableLBA := backupEntriesLBA - 1
	expectedPrimary := makeLayoutGPTHeader(sectorSize, 1, backupHeaderLBA, firstUsableLBA, lastUsableLBA, diskGUID, 2, entriesCRC)
	expectedBackup := makeLayoutGPTHeader(sectorSize, backupHeaderLBA, 1, firstUsableLBA, lastUsableLBA, diskGUID, backupEntriesLBA, entriesCRC)
	if !bytes.Equal(primaryHeader, expectedPrimary) || !bytes.Equal(backupHeader, expectedBackup) {
		return errors.New("ISO Image mode GPT header verification failed")
	}
	return verifyISOImageLayoutEntry(primaryEntries[:layoutGPTEntrySize], layoutEFIType, partitionGUID, layout.Partition, sectorSize)
}

func writeISOImageLayoutEntry(entry []byte, partitionType, unique [16]byte, layout PartitionLayout, sectorSize uint64, name string) {
	copy(entry[0:16], partitionType[:])
	copy(entry[16:32], unique[:])
	binary.LittleEndian.PutUint64(entry[32:40], layout.StartBytes/sectorSize)
	binary.LittleEndian.PutUint64(entry[40:48], (layout.StartBytes+layout.SizeBytes)/sectorSize-1)
	binary.LittleEndian.PutUint64(entry[48:56], 0)
	writeLayoutName(entry[56:128], name)
}

func verifyISOImageLayoutEntry(entry []byte, partitionType, unique [16]byte, layout PartitionLayout, sectorSize uint64) error {
	if !bytes.Equal(entry[:16], partitionType[:]) || !bytes.Equal(entry[16:32], unique[:]) ||
		binary.LittleEndian.Uint64(entry[32:40]) != layout.StartBytes/sectorSize ||
		binary.LittleEndian.Uint64(entry[40:48]) != (layout.StartBytes+layout.SizeBytes)/sectorSize-1 ||
		binary.LittleEndian.Uint64(entry[48:56]) != 0 {
		return errors.New("ISO Image mode partition entry does not match the planned extent")
	}
	return nil
}
