//go:build linux

package uefintfs

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
	"unicode/utf16"
)

const (
	SchemeMBR = "mbr"
	SchemeGPT = "gpt"

	oneMiB               = uint64(1024 * 1024)
	minimumLayoutBytes   = uint64(16 * 1024 * 1024)
	gptHeaderBytes       = 92
	gptEntryBytes        = 128
	gptEntryCount        = 128
	gptNoDriveLetter     = uint64(1) << 63
	mbrDataPartition     = byte(0x07)
	mbrUEFINTFSPartition = byte(0xef)
)

// Extent is one byte-addressed partition extent on the held target.
type Extent struct {
	StartBytes uint64 `json:"start_bytes"`
	SizeBytes  uint64 `json:"size_bytes"`
}

// Layout is the deterministic two-partition geometry used by UEFI:NTFS media.
type Layout struct {
	Scheme     string `json:"scheme"`
	TargetSize uint64 `json:"target_size"`
	SectorSize uint64 `json:"sector_size"`
	Data       Extent `json:"data"`
	Boot       Extent `json:"boot"`
}

var microsoftBasicDataType = [16]byte{
	0xa2, 0xa0, 0xd0, 0xeb, 0xe5, 0xb9, 0x33, 0x44,
	0x87, 0xc0, 0x68, 0xb6, 0xb7, 0x26, 0x99, 0xc7,
}

// PlanLayout calculates the complete data and UEFI:NTFS boot extents without
// mutating the target.
func PlanLayout(scheme string, targetSize, sectorSize uint64) (Layout, error) {
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	if err := validateGeometry(targetSize, sectorSize); err != nil {
		return Layout{}, err
	}
	switch scheme {
	case SchemeMBR:
		return planMBR(targetSize, sectorSize)
	case SchemeGPT:
		return planGPT(targetSize, sectorSize)
	default:
		return Layout{}, fmt.Errorf("unsupported UEFI:NTFS partition scheme %q", scheme)
	}
}

// WriteLayout publishes and verifies the partition table for a previously
// reviewed layout. GPT backup metadata is made durable before primary metadata.
func WriteLayout(target Target, layout Layout, dataLabel string) error {
	if target == nil {
		return errors.New("nil UEFI:NTFS layout target")
	}
	expected, err := PlanLayout(layout.Scheme, layout.TargetSize, layout.SectorSize)
	if err != nil {
		return err
	}
	if expected != layout {
		return errors.New("UEFI:NTFS layout does not match deterministic planning")
	}
	switch layout.Scheme {
	case SchemeMBR:
		return writeMBRLayout(target, layout)
	case SchemeGPT:
		return writeGPTLayout(target, layout, dataLabel)
	default:
		return fmt.Errorf("unsupported UEFI:NTFS partition scheme %q", layout.Scheme)
	}
}

func planMBR(targetSize, sectorSize uint64) (Layout, error) {
	dataStart := alignUp(oneMiB, sectorSize)
	bootStart := alignDown(targetSize-ImageSize, oneMiB)
	if bootStart <= dataStart {
		return Layout{}, errors.New("target has insufficient space for MBR NTFS data and UEFI:NTFS boot partitions")
	}
	layout := Layout{
		Scheme:     SchemeMBR,
		TargetSize: targetSize,
		SectorSize: sectorSize,
		Data:       Extent{StartBytes: dataStart, SizeBytes: bootStart - dataStart},
		Boot:       Extent{StartBytes: bootStart, SizeBytes: ImageSize},
	}
	for _, extent := range []Extent{layout.Data, layout.Boot} {
		start := extent.StartBytes / sectorSize
		size := extent.SizeBytes / sectorSize
		if start > uint64(^uint32(0)) || size > uint64(^uint32(0)) {
			return Layout{}, errors.New("target is too large for an MBR UEFI:NTFS layout; use GPT")
		}
	}
	return layout, nil
}

func planGPT(targetSize, sectorSize uint64) (Layout, error) {
	totalLBAs := targetSize / sectorSize
	entryBytes := uint64(gptEntryCount * gptEntryBytes)
	entryLBAs := (entryBytes + sectorSize - 1) / sectorSize
	firstUsableLBA := uint64(2) + entryLBAs
	backupHeaderLBA := totalLBAs - 1
	if backupHeaderLBA <= entryLBAs {
		return Layout{}, errors.New("target is too small for GPT metadata")
	}
	backupEntriesLBA := backupHeaderLBA - entryLBAs
	lastUsableLBA := backupEntriesLBA - 1
	dataStartLBA := alignUp(oneMiB, sectorSize) / sectorSize
	if dataStartLBA < firstUsableLBA {
		dataStartLBA = firstUsableLBA
	}
	endExclusiveBytes := (lastUsableLBA + 1) * sectorSize
	if endExclusiveBytes <= ImageSize {
		return Layout{}, errors.New("target has no space for the UEFI:NTFS boot partition")
	}
	bootStartBytes := alignDown(endExclusiveBytes-ImageSize, oneMiB)
	bootStartLBA := bootStartBytes / sectorSize
	bootLBAs := ImageSize / sectorSize
	bootEndLBA := bootStartLBA + bootLBAs - 1
	if bootStartLBA <= dataStartLBA || bootEndLBA > lastUsableLBA {
		return Layout{}, errors.New("target has insufficient aligned space for NTFS data and UEFI:NTFS boot partitions")
	}
	return Layout{
		Scheme:     SchemeGPT,
		TargetSize: targetSize,
		SectorSize: sectorSize,
		Data: Extent{
			StartBytes: dataStartLBA * sectorSize,
			SizeBytes:  (bootStartLBA - dataStartLBA) * sectorSize,
		},
		Boot: Extent{
			StartBytes: bootStartLBA * sectorSize,
			SizeBytes:  ImageSize,
		},
	}, nil
}

func writeMBRLayout(target Target, layout Layout) error {
	sector := make([]byte, layout.SectorSize)
	if _, err := rand.Read(sector[440:444]); err != nil {
		return fmt.Errorf("generate MBR disk signature: %w", err)
	}
	writeMBRPartition(sector[446:462], layout.Data, layout.SectorSize, true, mbrDataPartition)
	writeMBRPartition(sector[462:478], layout.Boot, layout.SectorSize, false, mbrUEFINTFSPartition)
	sector[510], sector[511] = 0x55, 0xaa
	if err := writeFullAt(target, sector, 0); err != nil {
		return fmt.Errorf("write UEFI:NTFS MBR: %w", err)
	}
	if err := target.Sync(); err != nil {
		return fmt.Errorf("sync UEFI:NTFS MBR: %w", err)
	}
	readback := make([]byte, len(sector))
	if _, err := target.ReadAt(readback, 0); err != nil {
		return fmt.Errorf("read back UEFI:NTFS MBR: %w", err)
	}
	if !bytes.Equal(readback, sector) {
		return errors.New("UEFI:NTFS MBR readback mismatch")
	}
	return nil
}

func writeMBRPartition(entry []byte, extent Extent, sectorSize uint64, bootable bool, partitionType byte) {
	if bootable {
		entry[0] = 0x80
	}
	entry[1], entry[2], entry[3] = 0xfe, 0xff, 0xff
	entry[4] = partitionType
	entry[5], entry[6], entry[7] = 0xfe, 0xff, 0xff
	binary.LittleEndian.PutUint32(entry[8:12], uint32(extent.StartBytes/sectorSize))
	binary.LittleEndian.PutUint32(entry[12:16], uint32(extent.SizeBytes/sectorSize))
}

func writeGPTLayout(target Target, layout Layout, dataLabel string) error {
	sectorSize := layout.SectorSize
	totalLBAs := layout.TargetSize / sectorSize
	entryBytes := uint64(gptEntryCount * gptEntryBytes)
	entryLBAs := (entryBytes + sectorSize - 1) / sectorSize
	primaryEntriesLBA := uint64(2)
	backupHeaderLBA := totalLBAs - 1
	backupEntriesLBA := backupHeaderLBA - entryLBAs
	firstUsableLBA := primaryEntriesLBA + entryLBAs
	lastUsableLBA := backupEntriesLBA - 1

	diskGUID, err := randomGUID()
	if err != nil {
		return fmt.Errorf("generate GPT disk GUID: %w", err)
	}
	dataGUID, err := randomGUID()
	if err != nil {
		return fmt.Errorf("generate GPT data partition GUID: %w", err)
	}
	bootGUID, err := randomGUID()
	if err != nil {
		return fmt.Errorf("generate GPT UEFI:NTFS partition GUID: %w", err)
	}

	entries := make([]byte, entryLBAs*sectorSize)
	dataEntry := entries[:gptEntryBytes]
	copy(dataEntry[0:16], microsoftBasicDataType[:])
	copy(dataEntry[16:32], dataGUID[:])
	binary.LittleEndian.PutUint64(dataEntry[32:40], layout.Data.StartBytes/sectorSize)
	binary.LittleEndian.PutUint64(dataEntry[40:48], (layout.Data.StartBytes+layout.Data.SizeBytes)/sectorSize-1)
	writeGPTName(dataEntry[56:128], dataLabel)

	bootEntry := entries[gptEntryBytes : 2*gptEntryBytes]
	copy(bootEntry[0:16], microsoftBasicDataType[:])
	copy(bootEntry[16:32], bootGUID[:])
	binary.LittleEndian.PutUint64(bootEntry[32:40], layout.Boot.StartBytes/sectorSize)
	binary.LittleEndian.PutUint64(bootEntry[40:48], (layout.Boot.StartBytes+layout.Boot.SizeBytes)/sectorSize-1)
	binary.LittleEndian.PutUint64(bootEntry[48:56], gptNoDriveLetter)
	writeGPTName(bootEntry[56:128], "UEFI:NTFS")

	entriesCRC := crc32.ChecksumIEEE(entries[:entryBytes])
	primaryHeader := makeGPTHeader(sectorSize, 1, backupHeaderLBA, firstUsableLBA, lastUsableLBA, diskGUID, primaryEntriesLBA, entriesCRC)
	backupHeader := makeGPTHeader(sectorSize, backupHeaderLBA, 1, firstUsableLBA, lastUsableLBA, diskGUID, backupEntriesLBA, entriesCRC)
	protectiveMBR := makeProtectiveMBR(totalLBAs, sectorSize)

	backup := []metadataRegion{
		{offset: backupEntriesLBA * sectorSize, data: entries, name: "backup GPT entries"},
		{offset: backupHeaderLBA * sectorSize, data: backupHeader, name: "backup GPT header"},
	}
	primary := []metadataRegion{
		{offset: primaryEntriesLBA * sectorSize, data: entries, name: "primary GPT entries"},
		{offset: sectorSize, data: primaryHeader, name: "primary GPT header"},
		{offset: 0, data: protectiveMBR, name: "protective MBR"},
	}
	for _, region := range backup {
		if err := writeFullAt(target, region.data, region.offset); err != nil {
			return fmt.Errorf("write %s: %w", region.name, err)
		}
	}
	if err := target.Sync(); err != nil {
		return fmt.Errorf("make backup GPT durable: %w", err)
	}
	for _, region := range primary {
		if err := writeFullAt(target, region.data, region.offset); err != nil {
			return fmt.Errorf("write %s: %w", region.name, err)
		}
	}
	if err := target.Sync(); err != nil {
		return fmt.Errorf("make primary GPT durable: %w", err)
	}
	regions := append(append([]metadataRegion(nil), backup...), primary...)
	for _, region := range regions {
		readback := make([]byte, len(region.data))
		if _, err := target.ReadAt(readback, int64(region.offset)); err != nil {
			return fmt.Errorf("read back %s: %w", region.name, err)
		}
		if !bytes.Equal(readback, region.data) {
			return fmt.Errorf("%s readback mismatch", region.name)
		}
	}
	return nil
}

type metadataRegion struct {
	offset uint64
	data   []byte
	name   string
}

func validateGeometry(targetSize, sectorSize uint64) error {
	if targetSize > uint64(math.MaxInt64) {
		return errors.New("target exceeds the supported signed file-offset range")
	}
	if targetSize < minimumLayoutBytes {
		return fmt.Errorf("target is too small for UEFI:NTFS media: need at least %d bytes", minimumLayoutBytes)
	}
	if sectorSize < 512 || sectorSize > 64*1024 || sectorSize&(sectorSize-1) != 0 {
		return fmt.Errorf("unsupported logical sector size %d", sectorSize)
	}
	if targetSize%sectorSize != 0 || ImageSize%sectorSize != 0 {
		return fmt.Errorf("target or UEFI:NTFS image is not aligned to logical sector size %d", sectorSize)
	}
	return nil
}

func alignUp(value, alignment uint64) uint64 {
	return (value + alignment - 1) / alignment * alignment
}

func alignDown(value, alignment uint64) uint64 {
	return value / alignment * alignment
}

func writeFullAt(target io.WriterAt, data []byte, offset uint64) error {
	if offset > uint64(math.MaxInt64) || uint64(len(data)) > uint64(math.MaxInt64)-offset {
		return errors.New("metadata write exceeds the supported signed file-offset range")
	}
	written, err := target.WriteAt(data, int64(offset))
	if err != nil {
		return err
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

func randomGUID() ([16]byte, error) {
	var guid [16]byte
	if _, err := rand.Read(guid[:]); err != nil {
		return guid, err
	}
	guid[7] = (guid[7] & 0x0f) | 0x40
	guid[8] = (guid[8] & 0x3f) | 0x80
	return guid, nil
}

func makeProtectiveMBR(totalLBAs, sectorSize uint64) []byte {
	sector := make([]byte, sectorSize)
	entry := sector[446:462]
	entry[1], entry[2], entry[3] = 0x00, 0x02, 0x00
	entry[4] = 0xee
	entry[5], entry[6], entry[7] = 0xff, 0xff, 0xff
	binary.LittleEndian.PutUint32(entry[8:12], 1)
	length := totalLBAs - 1
	if length > uint64(^uint32(0)) {
		length = uint64(^uint32(0))
	}
	binary.LittleEndian.PutUint32(entry[12:16], uint32(length))
	sector[510], sector[511] = 0x55, 0xaa
	return sector
}

func makeGPTHeader(sectorSize, currentLBA, backupLBA, firstUsableLBA, lastUsableLBA uint64, diskGUID [16]byte, entriesLBA uint64, entriesCRC uint32) []byte {
	header := make([]byte, sectorSize)
	copy(header[0:8], []byte("EFI PART"))
	binary.LittleEndian.PutUint32(header[8:12], 0x00010000)
	binary.LittleEndian.PutUint32(header[12:16], gptHeaderBytes)
	binary.LittleEndian.PutUint64(header[24:32], currentLBA)
	binary.LittleEndian.PutUint64(header[32:40], backupLBA)
	binary.LittleEndian.PutUint64(header[40:48], firstUsableLBA)
	binary.LittleEndian.PutUint64(header[48:56], lastUsableLBA)
	copy(header[56:72], diskGUID[:])
	binary.LittleEndian.PutUint64(header[72:80], entriesLBA)
	binary.LittleEndian.PutUint32(header[80:84], gptEntryCount)
	binary.LittleEndian.PutUint32(header[84:88], gptEntryBytes)
	binary.LittleEndian.PutUint32(header[88:92], entriesCRC)
	binary.LittleEndian.PutUint32(header[16:20], crc32.ChecksumIEEE(header[:gptHeaderBytes]))
	return header
}

func writeGPTName(destination []byte, value string) {
	units := utf16.Encode([]rune(strings.TrimSpace(value)))
	if len(units) > len(destination)/2 {
		units = units[:len(destination)/2]
	}
	for index, unit := range units {
		binary.LittleEndian.PutUint16(destination[index*2:index*2+2], unit)
	}
}
