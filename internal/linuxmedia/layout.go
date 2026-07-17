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
	"unicode/utf16"

	"github.com/geocausa/RufusArm64/internal/persistence"
)

const (
	layoutAlignment       = uint64(1024 * 1024)
	minimumBootBytes      = uint64(512 * 1024 * 1024)
	minimumPersistence    = uint64(1024 * 1024 * 1024)
	minimumLayoutDiskSize = uint64(2 * 1024 * 1024 * 1024)
	fat32ClusterBytes     = uint64(4096)
	fat32EntryOverhead    = uint64(8192)
	layoutGPTHeaderSize   = 92
	layoutGPTEntrySize    = 128
	layoutGPTEntryCount   = 128
	layoutGPTNoAutomount  = uint64(1) << 63
)

var layoutEFIType = [16]byte{
	0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11,
	0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b,
}

var layoutLinuxFilesystemType = [16]byte{
	0xaf, 0x3d, 0xc6, 0x0f, 0x83, 0x84, 0x72, 0x47,
	0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4,
}

type PartitionLayout struct {
	Number     int    `json:"number"`
	StartBytes uint64 `json:"start_bytes"`
	SizeBytes  uint64 `json:"size_bytes"`
}

type PersistentLayout struct {
	SectorSize  uint64           `json:"sector_size"`
	TargetSize  uint64           `json:"target_size"`
	Boot        PartitionLayout  `json:"boot"`
	Persistence PartitionLayout  `json:"persistence"`
	Plan        persistence.Plan `json:"persistence_plan"`
}

type layoutTarget interface {
	io.ReaderAt
	io.WriterAt
	Sync() error
}

// PlanPersistentLayout creates a fresh GPT/UEFI layout for a verified writable
// Linux media tree. The boot partition is FAT32-compatible and the second
// partition implements the detected casper/live-boot persistence contract.
func PlanPersistentLayout(targetSize, sectorSize, copiedBytes, requestedPersistence uint64, detection persistence.Detection) (PersistentLayout, error) {
	if !detection.Ready() {
		return PersistentLayout{}, errors.New("media does not have a complete supported persistence contract")
	}
	if targetSize > uint64(math.MaxInt64) {
		return PersistentLayout{}, errors.New("target exceeds the supported signed file-offset range")
	}
	if targetSize < minimumLayoutDiskSize {
		return PersistentLayout{}, fmt.Errorf("target is too small for persistent Linux media: need at least %d bytes", minimumLayoutDiskSize)
	}
	if sectorSize < 512 || sectorSize > fat32ClusterBytes || sectorSize&(sectorSize-1) != 0 {
		return PersistentLayout{}, fmt.Errorf("unsupported logical sector size %d", sectorSize)
	}
	if targetSize%sectorSize != 0 {
		return PersistentLayout{}, fmt.Errorf("target size %d is not aligned to logical sector size %d", targetSize, sectorSize)
	}
	if copiedBytes == 0 {
		return PersistentLayout{}, errors.New("linux media tree is empty")
	}
	margin := copiedBytes / 20
	if margin < 64*1024*1024 {
		margin = 64 * 1024 * 1024
	}
	if copiedBytes > ^uint64(0)-margin {
		return PersistentLayout{}, errors.New("linux media size overflows the boot partition calculation")
	}
	bootSize := alignLayout(copiedBytes+margin, layoutAlignment)
	if bootSize < minimumBootBytes {
		bootSize = minimumBootBytes
	}

	totalLBAs := targetSize / sectorSize
	entryBytes := uint64(layoutGPTEntryCount * layoutGPTEntrySize)
	entryLBAs := (entryBytes + sectorSize - 1) / sectorSize
	firstUsableLBA := uint64(2) + entryLBAs
	backupHeaderLBA := totalLBAs - 1
	backupEntriesLBA := backupHeaderLBA - entryLBAs
	lastUsableLBA := backupEntriesLBA - 1
	bootStartLBA := alignLayout(layoutAlignment, sectorSize) / sectorSize
	if bootStartLBA < firstUsableLBA {
		bootStartLBA = firstUsableLBA
	}
	bootLBAs := alignLayout(bootSize, sectorSize) / sectorSize
	if bootLBAs == 0 || bootStartLBA > ^uint64(0)-bootLBAs {
		return PersistentLayout{}, errors.New("writable boot partition geometry overflow")
	}
	bootEndLBA := bootStartLBA + bootLBAs - 1
	persistenceStartBytes := alignLayout((bootEndLBA+1)*sectorSize, layoutAlignment)
	persistenceStartLBA := persistenceStartBytes / sectorSize
	if persistenceStartLBA > lastUsableLBA {
		return PersistentLayout{}, errors.New("target has no space after the writable boot partition")
	}
	availablePersistence := (lastUsableLBA - persistenceStartLBA + 1) * sectorSize
	availablePersistence = availablePersistence / layoutAlignment * layoutAlignment
	if availablePersistence < minimumPersistence {
		return PersistentLayout{}, fmt.Errorf("target needs at least %d bytes after the boot partition for persistence", minimumPersistence)
	}
	persistenceSize := requestedPersistence
	if persistenceSize == 0 {
		persistenceSize = availablePersistence
	} else {
		if persistenceSize%layoutAlignment != 0 {
			return PersistentLayout{}, fmt.Errorf("persistence size must be aligned to %d bytes", layoutAlignment)
		}
		if persistenceSize < minimumPersistence {
			return PersistentLayout{}, fmt.Errorf("persistence size must be at least %d bytes", minimumPersistence)
		}
		if persistenceSize > availablePersistence {
			return PersistentLayout{}, fmt.Errorf("requested persistence size %d exceeds available space %d", persistenceSize, availablePersistence)
		}
	}
	plan := persistence.Plan{
		Family:              detection.Family,
		PartitionTable:      persistence.TableGPT,
		PartitionNumber:     2,
		StartBytes:          persistenceStartBytes,
		SizeBytes:           persistenceSize,
		Filesystem:          detection.Filesystem,
		FilesystemLabel:     detection.FilesystemLabel,
		BootParameter:       detection.BootParameter,
		PersistenceConfig:   detection.PersistenceConfig,
		PatchPaths:          append([]string(nil), detection.PatchPaths...),
		AlreadyEnabledPaths: append([]string(nil), detection.AlreadyEnabledPaths...),
	}
	return PersistentLayout{
		SectorSize:  sectorSize,
		TargetSize:  targetSize,
		Boot:        PartitionLayout{Number: 1, StartBytes: bootStartLBA * sectorSize, SizeBytes: bootLBAs * sectorSize},
		Persistence: PartitionLayout{Number: 2, StartBytes: persistenceStartBytes, SizeBytes: persistenceSize},
		Plan:        plan,
	}, nil
}

// EstimateFAT32Bytes returns a conservative allocation estimate for a manifest
// copied onto a 4 KiB-cluster FAT32 filesystem. The per-entry allowance covers
// file tail slack, directory clusters, and long-filename directory records.
func EstimateFAT32Bytes(manifest Manifest) (uint64, error) {
	if len(manifest.Entries) == 0 || manifest.TotalBytes == 0 {
		return 0, errors.New("linux media manifest is empty")
	}
	entryCount := uint64(len(manifest.Entries))
	if entryCount > ^uint64(0)/fat32EntryOverhead {
		return 0, errors.New("linux media entry count overflows FAT32 sizing")
	}
	overhead := entryCount * fat32EntryOverhead
	if manifest.TotalBytes > ^uint64(0)-overhead {
		return 0, errors.New("linux media size overflows FAT32 sizing")
	}
	return manifest.TotalBytes + overhead, nil
}

// WritePersistentGPT writes and verifies the exact two-partition layout. The
// backup table/header are written before the primary metadata, and the whole
// target is synced before readback validation.
func WritePersistentGPT(target layoutTarget, layout PersistentLayout) error {
	if target == nil {
		return errors.New("nil persistent-layout target")
	}
	if err := validatePersistentLayout(layout); err != nil {
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
	bootGUID, err := randomLayoutGUID(rand.Reader)
	if err != nil {
		return err
	}
	persistenceGUID, err := randomLayoutGUID(rand.Reader)
	if err != nil {
		return err
	}
	entries := make([]byte, entryLBAs*sectorSize)
	writeLayoutEntry(entries[0:layoutGPTEntrySize], layoutEFIType, bootGUID, layout.Boot, sectorSize, "RUFUS-LIVE")
	writeLayoutEntry(entries[layoutGPTEntrySize:2*layoutGPTEntrySize], layoutLinuxFilesystemType, persistenceGUID, layout.Persistence, sectorSize, layout.Plan.FilesystemLabel)
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
			return fmt.Errorf("write %s: %w", write.name, err)
		}
	}
	if err := target.Sync(); err != nil {
		return fmt.Errorf("sync backup persistent GPT: %w", err)
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
			return fmt.Errorf("write %s: %w", write.name, err)
		}
	}
	if err := target.Sync(); err != nil {
		return fmt.Errorf("sync primary persistent GPT: %w", err)
	}
	return verifyPersistentGPT(target, layout, entriesCRC, diskGUID, bootGUID, persistenceGUID)
}

func validatePersistentLayout(layout PersistentLayout) error {
	if layout.TargetSize > uint64(math.MaxInt64) {
		return errors.New("persistent layout exceeds the supported signed file-offset range")
	}
	if layout.SectorSize < 512 || layout.SectorSize > fat32ClusterBytes || layout.SectorSize&(layout.SectorSize-1) != 0 ||
		layout.TargetSize < minimumLayoutDiskSize || layout.TargetSize%layout.SectorSize != 0 {
		return errors.New("persistent layout has invalid target geometry")
	}
	if layout.Boot.Number != 1 || layout.Persistence.Number != 2 || layout.Plan.PartitionNumber != 2 ||
		layout.Plan.PartitionTable != persistence.TableGPT || layout.Plan.StartBytes != layout.Persistence.StartBytes ||
		layout.Plan.SizeBytes != layout.Persistence.SizeBytes || layout.Plan.Filesystem != "ext4" {
		return errors.New("persistent layout and filesystem plan are inconsistent")
	}
	for _, part := range []PartitionLayout{layout.Boot, layout.Persistence} {
		if part.StartBytes%layout.SectorSize != 0 || part.SizeBytes == 0 || part.SizeBytes%layout.SectorSize != 0 ||
			part.StartBytes > layout.TargetSize || part.SizeBytes > layout.TargetSize-part.StartBytes {
			return errors.New("persistent layout contains an invalid partition extent")
		}
	}
	if layout.Boot.StartBytes+layout.Boot.SizeBytes > layout.Persistence.StartBytes {
		return errors.New("persistent boot and ext4 partitions overlap")
	}
	entryBytes := uint64(layoutGPTEntryCount * layoutGPTEntrySize)
	entryLBAs := (entryBytes + layout.SectorSize - 1) / layout.SectorSize
	backupEntriesStart := layout.TargetSize - (entryLBAs+1)*layout.SectorSize
	if layout.Persistence.StartBytes+layout.Persistence.SizeBytes > backupEntriesStart {
		return errors.New("persistence partition overlaps backup GPT metadata")
	}
	return nil
}

func verifyPersistentGPT(target io.ReaderAt, layout PersistentLayout, entriesCRC uint32, diskGUID, bootGUID, persistenceGUID [16]byte) error {
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
			return fmt.Errorf("read back %s: %w", read.name, err)
		}
	}
	expectedProtective := makeLayoutProtectiveMBR(totalLBAs, sectorSize)
	if !bytes.Equal(protectiveMBR, expectedProtective) {
		return errors.New("protective MBR verification failed")
	}
	expectedEntries := make([]byte, entryLBAs*sectorSize)
	writeLayoutEntry(expectedEntries[0:layoutGPTEntrySize], layoutEFIType, bootGUID, layout.Boot, sectorSize, "RUFUS-LIVE")
	writeLayoutEntry(expectedEntries[layoutGPTEntrySize:2*layoutGPTEntrySize], layoutLinuxFilesystemType, persistenceGUID, layout.Persistence, sectorSize, layout.Plan.FilesystemLabel)
	if !bytes.Equal(primaryEntries, expectedEntries) || !bytes.Equal(backupEntries, expectedEntries) || crc32.ChecksumIEEE(primaryEntries[:entryBytes]) != entriesCRC {
		return errors.New("persistent GPT entry-table verification failed")
	}
	firstUsableLBA := uint64(2) + entryLBAs
	lastUsableLBA := backupEntriesLBA - 1
	expectedPrimary := makeLayoutGPTHeader(sectorSize, 1, backupHeaderLBA, firstUsableLBA, lastUsableLBA, diskGUID, 2, entriesCRC)
	expectedBackup := makeLayoutGPTHeader(sectorSize, backupHeaderLBA, 1, firstUsableLBA, lastUsableLBA, diskGUID, backupEntriesLBA, entriesCRC)
	if !bytes.Equal(primaryHeader, expectedPrimary) {
		return errors.New("primary GPT header verification failed")
	}
	if !bytes.Equal(backupHeader, expectedBackup) {
		return errors.New("backup GPT header verification failed")
	}
	if err := verifyLayoutEntry(primaryEntries[:layoutGPTEntrySize], layoutEFIType, bootGUID, layout.Boot, sectorSize); err != nil {
		return fmt.Errorf("verify boot partition entry: %w", err)
	}
	if err := verifyLayoutEntry(primaryEntries[layoutGPTEntrySize:2*layoutGPTEntrySize], layoutLinuxFilesystemType, persistenceGUID, layout.Persistence, sectorSize); err != nil {
		return fmt.Errorf("verify persistence partition entry: %w", err)
	}
	return nil
}

func writeLayoutEntry(entry []byte, partitionType, unique [16]byte, layout PartitionLayout, sectorSize uint64, name string) {
	copy(entry[0:16], partitionType[:])
	copy(entry[16:32], unique[:])
	binary.LittleEndian.PutUint64(entry[32:40], layout.StartBytes/sectorSize)
	binary.LittleEndian.PutUint64(entry[40:48], (layout.StartBytes+layout.SizeBytes)/sectorSize-1)
	binary.LittleEndian.PutUint64(entry[48:56], layoutGPTNoAutomount)
	writeLayoutName(entry[56:128], name)
}

func verifyLayoutEntry(entry []byte, partitionType, unique [16]byte, layout PartitionLayout, sectorSize uint64) error {
	if !bytes.Equal(entry[:16], partitionType[:]) || !bytes.Equal(entry[16:32], unique[:]) ||
		binary.LittleEndian.Uint64(entry[32:40]) != layout.StartBytes/sectorSize ||
		binary.LittleEndian.Uint64(entry[40:48]) != (layout.StartBytes+layout.SizeBytes)/sectorSize-1 ||
		binary.LittleEndian.Uint64(entry[48:56]) != layoutGPTNoAutomount {
		return errors.New("partition entry does not match the planned extent")
	}
	return nil
}

func makeLayoutGPTHeader(sectorSize, current, backup, firstUsable, lastUsable uint64, diskGUID [16]byte, entriesLBA uint64, entriesCRC uint32) []byte {
	header := make([]byte, sectorSize)
	copy(header[0:8], "EFI PART")
	binary.LittleEndian.PutUint32(header[8:12], 0x00010000)
	binary.LittleEndian.PutUint32(header[12:16], layoutGPTHeaderSize)
	binary.LittleEndian.PutUint64(header[24:32], current)
	binary.LittleEndian.PutUint64(header[32:40], backup)
	binary.LittleEndian.PutUint64(header[40:48], firstUsable)
	binary.LittleEndian.PutUint64(header[48:56], lastUsable)
	copy(header[56:72], diskGUID[:])
	binary.LittleEndian.PutUint64(header[72:80], entriesLBA)
	binary.LittleEndian.PutUint32(header[80:84], layoutGPTEntryCount)
	binary.LittleEndian.PutUint32(header[84:88], layoutGPTEntrySize)
	binary.LittleEndian.PutUint32(header[88:92], entriesCRC)
	binary.LittleEndian.PutUint32(header[16:20], crc32.ChecksumIEEE(header[:layoutGPTHeaderSize]))
	return header
}

func makeLayoutProtectiveMBR(totalLBAs, sectorSize uint64) []byte {
	sector := make([]byte, sectorSize)
	entry := sector[446:462]
	entry[4] = 0xee
	entry[5], entry[6], entry[7] = 0xff, 0xff, 0xff
	binary.LittleEndian.PutUint32(entry[8:12], 1)
	count := totalLBAs - 1
	if count > uint64(^uint32(0)) {
		count = uint64(^uint32(0))
	}
	binary.LittleEndian.PutUint32(entry[12:16], uint32(count))
	sector[510], sector[511] = 0x55, 0xaa
	return sector
}

func randomLayoutGUID(reader io.Reader) ([16]byte, error) {
	var guid [16]byte
	if _, err := io.ReadFull(reader, guid[:]); err != nil {
		return guid, fmt.Errorf("generate GPT GUID: %w", err)
	}
	guid[7] = (guid[7] & 0x0f) | 0x40
	guid[8] = (guid[8] & 0x3f) | 0x80
	return guid, nil
}

func writeLayoutName(destination []byte, value string) {
	encoded := utf16.Encode([]rune(value))
	if len(encoded) > len(destination)/2 {
		encoded = encoded[:len(destination)/2]
	}
	for index, code := range encoded {
		binary.LittleEndian.PutUint16(destination[index*2:index*2+2], code)
	}
}

func writeLayoutAt(target io.WriterAt, data []byte, offset uint64) error {
	if offset > uint64(math.MaxInt64) || uint64(len(data)) > uint64(math.MaxInt64)-offset {
		return errors.New("GPT metadata write exceeds the supported signed file-offset range")
	}
	for len(data) > 0 {
		n, err := target.WriteAt(data, int64(offset))
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
		offset += uint64(n)
	}
	return nil
}

func alignLayout(value, alignment uint64) uint64 {
	return (value + alignment - 1) / alignment * alignment
}
