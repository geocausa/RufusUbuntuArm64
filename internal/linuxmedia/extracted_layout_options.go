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
	"strings"
)

const (
	extractedPartitionMBR = "mbr"
	extractedPartitionGPT = "gpt"
	// FAT32 requires at least 65,525 data clusters. Reserve additional clusters
	// for FAT and reserved-sector metadata so the pre-erasure check stays safe.
	minimumFAT32PartitionClusters = uint64(70000)
)

func normalizeExtractedPartitionScheme(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return extractedPartitionMBR, nil
	}
	if value != extractedPartitionMBR && value != extractedPartitionGPT {
		return "", errors.New("ISO Image mode partition scheme must be MBR or GPT")
	}
	return value, nil
}

func normalizeExtractedClusterSize(requested, sectorSize uint64) (uint64, error) {
	if requested == 0 {
		requested = fat32ClusterBytes
	}
	switch requested {
	case 4096, 8192, 16384, 32768:
	default:
		return 0, errors.New("ISO Image mode FAT32 cluster size must be 4096, 8192, 16384, or 32768 bytes")
	}
	if sectorSize == 0 || requested%sectorSize != 0 {
		return 0, fmt.Errorf("FAT32 cluster size %d is not aligned to logical sector size %d", requested, sectorSize)
	}
	return requested, nil
}

// EstimateFAT32BytesForCluster conservatively accounts for file-tail slack,
// directory clusters, and long-filename records at the selected cluster size.
func EstimateFAT32BytesForCluster(manifest Manifest, clusterBytes uint64) (uint64, error) {
	if len(manifest.Entries) == 0 || manifest.TotalBytes == 0 {
		return 0, errors.New("linux media manifest is empty")
	}
	if clusterBytes == 0 {
		clusterBytes = fat32ClusterBytes
	}
	perEntry := clusterBytes + fat32EntryOverhead
	entryCount := uint64(len(manifest.Entries))
	if entryCount > ^uint64(0)/perEntry {
		return 0, errors.New("linux media entry count overflows FAT32 sizing")
	}
	overhead := entryCount * perEntry
	if manifest.TotalBytes > ^uint64(0)-overhead {
		return 0, errors.New("linux media size overflows FAT32 sizing")
	}
	return manifest.TotalBytes + overhead, nil
}

// PlanExtractedLayoutForScheme returns the exact one-partition layout selected
// for ISO Image mode. MBR preserves the original bounded implementation; GPT
// reserves complete primary and backup metadata before exposing usable space.
func PlanExtractedLayoutForScheme(targetSize, sectorSize, copiedBytes uint64, scheme string) (ExtractedLayout, error) {
	normalized, err := normalizeExtractedPartitionScheme(scheme)
	if err != nil {
		return ExtractedLayout{}, err
	}
	if normalized == extractedPartitionMBR {
		return PlanExtractedLayout(targetSize, sectorSize, copiedBytes)
	}
	if targetSize > uint64(math.MaxInt64) {
		return ExtractedLayout{}, errors.New("target exceeds the supported signed file-offset range")
	}
	if targetSize < minimumExtractedDiskSize {
		return ExtractedLayout{}, fmt.Errorf("target is too small for ISO Image mode: need at least %d bytes", minimumExtractedDiskSize)
	}
	if sectorSize < 512 || sectorSize > fat32ClusterBytes || sectorSize&(sectorSize-1) != 0 {
		return ExtractedLayout{}, fmt.Errorf("unsupported logical sector size %d", sectorSize)
	}
	if targetSize%sectorSize != 0 {
		return ExtractedLayout{}, fmt.Errorf("target size %d is not aligned to logical sector size %d", targetSize, sectorSize)
	}
	if copiedBytes == 0 {
		return ExtractedLayout{}, errors.New("linux media tree is empty")
	}
	totalLBAs := targetSize / sectorSize
	entryBytes := uint64(layoutGPTEntryCount * layoutGPTEntrySize)
	entryLBAs := (entryBytes + sectorSize - 1) / sectorSize
	if totalLBAs <= 2*entryLBAs+3 {
		return ExtractedLayout{}, errors.New("target has no usable space after GPT metadata")
	}
	firstUsableLBA := uint64(2) + entryLBAs
	backupHeaderLBA := totalLBAs - 1
	backupEntriesLBA := backupHeaderLBA - entryLBAs
	lastUsableLBA := backupEntriesLBA - 1
	startLBA := alignLayout(layoutAlignment, sectorSize) / sectorSize
	if startLBA < firstUsableLBA {
		startLBA = firstUsableLBA
	}
	if startLBA > lastUsableLBA {
		return ExtractedLayout{}, errors.New("target has no usable GPT partition space after alignment")
	}
	partitionBytes := (lastUsableLBA - startLBA + 1) * sectorSize
	margin := copiedBytes / 20
	if margin < 64*1024*1024 {
		margin = 64 * 1024 * 1024
	}
	if copiedBytes > ^uint64(0)-margin || copiedBytes+margin > partitionBytes {
		return ExtractedLayout{}, fmt.Errorf("target has %d usable bytes but the verified media tree needs at least %d", partitionBytes, copiedBytes+margin)
	}
	return ExtractedLayout{
		SectorSize: sectorSize,
		TargetSize: targetSize,
		Partition: PartitionLayout{
			Number:     1,
			StartBytes: startLBA * sectorSize,
			SizeBytes:  partitionBytes,
		},
	}, nil
}

func validateExtractedFAT32Capacity(partitionBytes, clusterBytes uint64) error {
	if clusterBytes == 0 || partitionBytes/clusterBytes < minimumFAT32PartitionClusters {
		return fmt.Errorf("the selected FAT32 cluster size %d leaves too few clusters on the target", clusterBytes)
	}
	return nil
}

func WriteExtractedPartitionTable(target layoutTarget, layout ExtractedLayout, scheme, label string) error {
	normalized, err := normalizeExtractedPartitionScheme(scheme)
	if err != nil {
		return err
	}
	if normalized == extractedPartitionMBR {
		return WriteExtractedMBR(target, layout)
	}
	return WriteExtractedGPT(target, layout, label)
}

// WriteExtractedGPT writes a single EFI System Partition with ordinary
// automount semantics and verifies protective MBR, primary/backup headers, and
// both entry tables before returning.
func WriteExtractedGPT(target layoutTarget, layout ExtractedLayout, label string) error {
	if target == nil {
		return errors.New("nil ISO Image mode target")
	}
	if err := validateExtractedGPTLayout(layout); err != nil {
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
	writeExtractedGPTEntry(entries[:layoutGPTEntrySize], partitionGUID, layout.Partition, sectorSize, label)
	entriesCRC := crc32.ChecksumIEEE(entries[:entryBytes])
	primary := makeLayoutGPTHeader(sectorSize, 1, backupHeaderLBA, firstUsableLBA, lastUsableLBA, diskGUID, primaryEntriesLBA, entriesCRC)
	backup := makeLayoutGPTHeader(sectorSize, backupHeaderLBA, 1, firstUsableLBA, lastUsableLBA, diskGUID, backupEntriesLBA, entriesCRC)
	protective := makeLayoutProtectiveMBR(totalLBAs, sectorSize)

	for _, item := range []struct {
		offset uint64
		data   []byte
		name   string
	}{
		{backupEntriesLBA * sectorSize, entries, "backup ISO Image mode GPT entries"},
		{backupHeaderLBA * sectorSize, backup, "backup ISO Image mode GPT header"},
	} {
		if err := writeLayoutAt(target, item.data, item.offset); err != nil {
			return fmt.Errorf("write %s: %w", item.name, err)
		}
	}
	if err := target.Sync(); err != nil {
		return fmt.Errorf("sync backup ISO Image mode GPT: %w", err)
	}
	for _, item := range []struct {
		offset uint64
		data   []byte
		name   string
	}{
		{primaryEntriesLBA * sectorSize, entries, "primary ISO Image mode GPT entries"},
		{sectorSize, primary, "primary ISO Image mode GPT header"},
		{0, protective, "protective ISO Image mode MBR"},
	} {
		if err := writeLayoutAt(target, item.data, item.offset); err != nil {
			return fmt.Errorf("write %s: %w", item.name, err)
		}
	}
	if err := target.Sync(); err != nil {
		return fmt.Errorf("sync primary ISO Image mode GPT: %w", err)
	}
	return verifyExtractedGPT(target, layout, entriesCRC, diskGUID, partitionGUID, label)
}

func validateExtractedGPTLayout(layout ExtractedLayout) error {
	if layout.TargetSize > uint64(math.MaxInt64) || layout.TargetSize < minimumExtractedDiskSize ||
		layout.SectorSize < 512 || layout.SectorSize > fat32ClusterBytes || layout.SectorSize&(layout.SectorSize-1) != 0 ||
		layout.TargetSize%layout.SectorSize != 0 {
		return errors.New("ISO Image mode GPT layout has invalid target geometry")
	}
	part := layout.Partition
	if part.Number != 1 || part.StartBytes%layout.SectorSize != 0 || part.SizeBytes == 0 || part.SizeBytes%layout.SectorSize != 0 ||
		part.StartBytes >= layout.TargetSize || part.SizeBytes > layout.TargetSize-part.StartBytes {
		return errors.New("ISO Image mode GPT layout has an invalid partition extent")
	}
	entryBytes := uint64(layoutGPTEntryCount * layoutGPTEntrySize)
	entryLBAs := (entryBytes + layout.SectorSize - 1) / layout.SectorSize
	firstUsable := (uint64(2) + entryLBAs) * layout.SectorSize
	backupEntriesStart := layout.TargetSize - (entryLBAs+1)*layout.SectorSize
	if part.StartBytes < firstUsable || part.StartBytes+part.SizeBytes > backupEntriesStart {
		return errors.New("ISO Image mode partition overlaps GPT metadata")
	}
	return nil
}

func writeExtractedGPTEntry(entry []byte, unique [16]byte, layout PartitionLayout, sectorSize uint64, label string) {
	copy(entry[0:16], layoutEFIType[:])
	copy(entry[16:32], unique[:])
	binary.LittleEndian.PutUint64(entry[32:40], layout.StartBytes/sectorSize)
	binary.LittleEndian.PutUint64(entry[40:48], (layout.StartBytes+layout.SizeBytes)/sectorSize-1)
	binary.LittleEndian.PutUint64(entry[48:56], 0)
	writeLayoutName(entry[56:128], label)
}

func verifyExtractedGPT(target io.ReaderAt, layout ExtractedLayout, entriesCRC uint32, diskGUID, partitionGUID [16]byte, label string) error {
	sectorSize := layout.SectorSize
	totalLBAs := layout.TargetSize / sectorSize
	entryBytes := uint64(layoutGPTEntryCount * layoutGPTEntrySize)
	entryLBAs := (entryBytes + sectorSize - 1) / sectorSize
	backupHeaderLBA := totalLBAs - 1
	backupEntriesLBA := backupHeaderLBA - entryLBAs
	protective := make([]byte, sectorSize)
	primaryHeader := make([]byte, sectorSize)
	backupHeader := make([]byte, sectorSize)
	primaryEntries := make([]byte, entryLBAs*sectorSize)
	backupEntries := make([]byte, entryLBAs*sectorSize)
	for _, item := range []struct {
		offset uint64
		data   []byte
		name   string
	}{
		{0, protective, "protective MBR"},
		{sectorSize, primaryHeader, "primary GPT header"},
		{backupHeaderLBA * sectorSize, backupHeader, "backup GPT header"},
		{2 * sectorSize, primaryEntries, "primary GPT entries"},
		{backupEntriesLBA * sectorSize, backupEntries, "backup GPT entries"},
	} {
		if _, err := target.ReadAt(item.data, int64(item.offset)); err != nil {
			return fmt.Errorf("read back %s: %w", item.name, err)
		}
	}
	if !bytes.Equal(protective, makeLayoutProtectiveMBR(totalLBAs, sectorSize)) {
		return errors.New("ISO Image mode protective MBR verification failed")
	}
	expectedEntries := make([]byte, entryLBAs*sectorSize)
	writeExtractedGPTEntry(expectedEntries[:layoutGPTEntrySize], partitionGUID, layout.Partition, sectorSize, label)
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
	entry := primaryEntries[:layoutGPTEntrySize]
	if !bytes.Equal(entry[:16], layoutEFIType[:]) || !bytes.Equal(entry[16:32], partitionGUID[:]) ||
		binary.LittleEndian.Uint64(entry[32:40]) != layout.Partition.StartBytes/sectorSize ||
		binary.LittleEndian.Uint64(entry[40:48]) != (layout.Partition.StartBytes+layout.Partition.SizeBytes)/sectorSize-1 ||
		binary.LittleEndian.Uint64(entry[48:56]) != 0 {
		return errors.New("ISO Image mode GPT partition entry verification failed")
	}
	return nil
}
