//go:build linux

package windowsmedia

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"unicode/utf16"
)

type partitionLayout struct {
	PartitionStartBytes uint64
	PartitionSizeBytes  uint64
}

type diskLayout struct {
	Data partitionLayout
	Boot *partitionLayout
}

type gptTarget interface {
	io.ReaderAt
	io.WriterAt
	Sync() error
}

const (
	gptHeaderSize       = 92
	gptEntrySize        = 128
	gptEntryCount       = 128
	oneMiB              = uint64(1024 * 1024)
	minimumGPTDiskBytes = uint64(16 * 1024 * 1024)
	gptNoDriveLetter    = uint64(1) << 63
)

var efiSystemPartitionType = [16]byte{
	0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11,
	0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b,
}

// Microsoft Basic Data: EBD0A0A2-B9E5-4433-87C0-68B6B72699C7,
// encoded in GPT's mixed-endian on-disk form.
var microsoftBasicDataType = [16]byte{
	0xa2, 0xa0, 0xd0, 0xeb, 0xe5, 0xb9, 0x33, 0x44,
	0x87, 0xc0, 0x68, 0xb6, 0xb7, 0x26, 0x99, 0xc7,
}

// logicalSectorSize asks the kernel for the target's logical block size. GPT
// geometry and all on-disk LBAs are expressed in these units, so silently
// assuming 512 bytes would corrupt media that uses 4 KiB logical sectors.
func logicalSectorSize(ctx context.Context, devicePath string) (uint64, error) {
	cmd := exec.CommandContext(ctx, "blockdev", "--getss", devicePath)
	output, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		return 0, fmt.Errorf("read logical sector size for %s: %w", devicePath, err)
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse logical sector size for %s: %w", devicePath, err)
	}
	if value < 512 || value > 64*1024 || value&(value-1) != 0 {
		return 0, fmt.Errorf("unsupported logical sector size %d for %s", value, devicePath)
	}
	return value, nil
}

// writeSinglePartitionGPT writes the native FAT32 UEFI layout used by the
// existing implementation: one EFI System Partition spanning the usable disk.
func writeSinglePartitionGPT(target *os.File, targetSize, sectorSize uint64, label string) (partitionLayout, error) {
	layout, err := writeGPT(target, targetSize, sectorSize, label, false, 0)
	return layout.Data, err
}

// writeUEFINTFSGPT creates Rufus-compatible UEFI:NTFS media: one Microsoft
// Basic Data partition for NTFS setup files and a small trailing Basic Data
// partition named UEFI:NTFS that receives Rufus's FAT driver image.
func writeUEFINTFSGPT(target *os.File, targetSize, sectorSize uint64, label string, bootImageSize uint64) (diskLayout, error) {
	return writeGPT(target, targetSize, sectorSize, label, true, bootImageSize)
}

func writeGPT(target gptTarget, targetSize, sectorSize uint64, label string, uefiNTFS bool, bootImageSize uint64) (diskLayout, error) {
	if target == nil {
		return diskLayout{}, errors.New("nil GPT target")
	}
	if targetSize > uint64(math.MaxInt64) {
		return diskLayout{}, errors.New("target exceeds the supported signed file-offset range")
	}
	if targetSize < minimumGPTDiskBytes {
		return diskLayout{}, fmt.Errorf("target is too small for a GPT Windows installer: %s", humanBytes(targetSize))
	}
	if sectorSize < 512 || sectorSize > 64*1024 || sectorSize&(sectorSize-1) != 0 {
		return diskLayout{}, fmt.Errorf("unsupported logical sector size %d", sectorSize)
	}
	if targetSize%sectorSize != 0 {
		return diskLayout{}, fmt.Errorf("target size %d is not aligned to logical sector size %d", targetSize, sectorSize)
	}
	if uefiNTFS && (bootImageSize == 0 || bootImageSize%sectorSize != 0) {
		return diskLayout{}, fmt.Errorf("UEFI:NTFS image size %d is not aligned to logical sector size %d", bootImageSize, sectorSize)
	}

	totalLBAs := targetSize / sectorSize
	entryBytes := uint64(gptEntryCount * gptEntrySize)
	entryLBAs := (entryBytes + sectorSize - 1) / sectorSize
	primaryEntriesLBA := uint64(2)
	backupHeaderLBA := totalLBAs - 1
	backupEntriesLBA := backupHeaderLBA - entryLBAs
	firstUsableLBA := primaryEntriesLBA + entryLBAs
	lastUsableLBA := backupEntriesLBA - 1
	dataStartLBA := alignUp(oneMiB, sectorSize) / sectorSize
	if dataStartLBA < firstUsableLBA {
		dataStartLBA = firstUsableLBA
	}
	if dataStartLBA >= lastUsableLBA {
		return diskLayout{}, errors.New("target has no usable space after GPT metadata and alignment")
	}

	dataEndLBA := lastUsableLBA
	var bootStartLBA, bootEndLBA uint64
	if uefiNTFS {
		bootLBAs := bootImageSize / sectorSize
		// Keep the auxiliary partition on a 1 MiB boundary, like Rufus, while
		// leaving any sub-alignment tail before the backup GPT unused.
		endExclusiveBytes := (lastUsableLBA + 1) * sectorSize
		if endExclusiveBytes <= bootImageSize {
			return diskLayout{}, errors.New("target has no space for the UEFI:NTFS boot partition")
		}
		bootStartBytes := alignDown(endExclusiveBytes-bootImageSize, oneMiB)
		bootStartLBA = bootStartBytes / sectorSize
		bootEndLBA = bootStartLBA + bootLBAs - 1
		if bootStartLBA <= dataStartLBA || bootEndLBA > lastUsableLBA {
			return diskLayout{}, errors.New("target has insufficient aligned space for NTFS data and UEFI:NTFS boot partitions")
		}
		dataEndLBA = bootStartLBA - 1
	}

	diskGUID, err := randomGUID()
	if err != nil {
		return diskLayout{}, fmt.Errorf("generate GPT disk GUID: %w", err)
	}
	dataGUID, err := randomGUID()
	if err != nil {
		return diskLayout{}, fmt.Errorf("generate GPT data partition GUID: %w", err)
	}

	entries := make([]byte, entryLBAs*sectorSize)
	dataEntry := entries[:gptEntrySize]
	if uefiNTFS {
		copy(dataEntry[0:16], microsoftBasicDataType[:])
	} else {
		copy(dataEntry[0:16], efiSystemPartitionType[:])
	}
	copy(dataEntry[16:32], dataGUID[:])
	binary.LittleEndian.PutUint64(dataEntry[32:40], dataStartLBA)
	binary.LittleEndian.PutUint64(dataEntry[40:48], dataEndLBA)
	writeGPTName(dataEntry[56:128], label)

	layout := diskLayout{Data: partitionLayout{
		PartitionStartBytes: dataStartLBA * sectorSize,
		PartitionSizeBytes:  (dataEndLBA - dataStartLBA + 1) * sectorSize,
	}}
	if uefiNTFS {
		bootGUID, err := randomGUID()
		if err != nil {
			return diskLayout{}, fmt.Errorf("generate GPT UEFI:NTFS partition GUID: %w", err)
		}
		bootEntry := entries[gptEntrySize : 2*gptEntrySize]
		copy(bootEntry[0:16], microsoftBasicDataType[:])
		copy(bootEntry[16:32], bootGUID[:])
		binary.LittleEndian.PutUint64(bootEntry[32:40], bootStartLBA)
		binary.LittleEndian.PutUint64(bootEntry[40:48], bootEndLBA)
		binary.LittleEndian.PutUint64(bootEntry[48:56], gptNoDriveLetter)
		writeGPTName(bootEntry[56:128], "UEFI:NTFS")
		boot := partitionLayout{
			PartitionStartBytes: bootStartLBA * sectorSize,
			PartitionSizeBytes:  (bootEndLBA - bootStartLBA + 1) * sectorSize,
		}
		layout.Boot = &boot
	}

	entriesCRC := crc32.ChecksumIEEE(entries[:entryBytes])
	primaryHeader := makeGPTHeader(sectorSize, 1, backupHeaderLBA, firstUsableLBA, lastUsableLBA, diskGUID, primaryEntriesLBA, entriesCRC)
	backupHeader := makeGPTHeader(sectorSize, backupHeaderLBA, 1, firstUsableLBA, lastUsableLBA, diskGUID, backupEntriesLBA, entriesCRC)
	protectiveMBR := makeProtectiveMBR(totalLBAs, sectorSize)

	backupRegions := []gptMetadataRegion{
		{offset: backupEntriesLBA * sectorSize, data: entries, name: "backup GPT entries"},
		{offset: backupHeaderLBA * sectorSize, data: backupHeader, name: "backup GPT header"},
	}
	primaryRegions := []gptMetadataRegion{
		{offset: primaryEntriesLBA * sectorSize, data: entries, name: "primary GPT entries"},
		{offset: sectorSize, data: primaryHeader, name: "primary GPT header"},
		{offset: 0, data: protectiveMBR, name: "protective MBR"},
	}
	for _, region := range backupRegions {
		if _, err := writeGPTMetadataAt(target, region.data, region.offset); err != nil {
			return diskLayout{}, fmt.Errorf("write %s: %w", region.name, err)
		}
	}
	if err := target.Sync(); err != nil {
		return diskLayout{}, fmt.Errorf("make backup GPT durable: %w", err)
	}
	for _, region := range primaryRegions {
		if _, err := writeGPTMetadataAt(target, region.data, region.offset); err != nil {
			return diskLayout{}, fmt.Errorf("write %s: %w", region.name, err)
		}
	}
	if err := target.Sync(); err != nil {
		return diskLayout{}, fmt.Errorf("make primary GPT durable: %w", err)
	}
	regions := append(append([]gptMetadataRegion(nil), backupRegions...), primaryRegions...)
	if err := verifyGPTMetadata(target, regions); err != nil {
		return diskLayout{}, fmt.Errorf("verify GPT metadata: %w", err)
	}
	return layout, nil
}

type gptMetadataWriter interface {
	WriteAt([]byte, int64) (int, error)
}

func writeGPTMetadataAt(target gptMetadataWriter, data []byte, offset uint64) (int, error) {
	if offset > uint64(math.MaxInt64) || uint64(len(data)) > uint64(math.MaxInt64)-offset {
		return 0, errors.New("GPT metadata write exceeds the supported signed file-offset range")
	}
	written, err := target.WriteAt(data, int64(offset))
	if err != nil {
		return written, err
	}
	if written != len(data) {
		return written, io.ErrShortWrite
	}
	return written, nil
}

func alignUp(value, alignment uint64) uint64 {
	return (value + alignment - 1) / alignment * alignment
}

func alignDown(value, alignment uint64) uint64 {
	return value / alignment * alignment
}

func makeProtectiveMBR(totalLBAs, sectorSize uint64) []byte {
	sector := make([]byte, sectorSize)
	entry := sector[446:462]
	entry[0] = 0x00
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
	sector := make([]byte, sectorSize)
	copy(sector[0:8], "EFI PART")
	binary.LittleEndian.PutUint32(sector[8:12], 0x00010000)
	binary.LittleEndian.PutUint32(sector[12:16], gptHeaderSize)
	binary.LittleEndian.PutUint64(sector[24:32], currentLBA)
	binary.LittleEndian.PutUint64(sector[32:40], backupLBA)
	binary.LittleEndian.PutUint64(sector[40:48], firstUsableLBA)
	binary.LittleEndian.PutUint64(sector[48:56], lastUsableLBA)
	copy(sector[56:72], diskGUID[:])
	binary.LittleEndian.PutUint64(sector[72:80], entriesLBA)
	binary.LittleEndian.PutUint32(sector[80:84], gptEntryCount)
	binary.LittleEndian.PutUint32(sector[84:88], gptEntrySize)
	binary.LittleEndian.PutUint32(sector[88:92], entriesCRC)
	binary.LittleEndian.PutUint32(sector[16:20], crc32.ChecksumIEEE(sector[:gptHeaderSize]))
	return sector
}

func randomGUID() ([16]byte, error) {
	var canonical [16]byte
	if _, err := rand.Read(canonical[:]); err != nil {
		return [16]byte{}, err
	}
	canonical[6] = (canonical[6] & 0x0f) | 0x40
	canonical[8] = (canonical[8] & 0x3f) | 0x80
	return [16]byte{
		canonical[3], canonical[2], canonical[1], canonical[0],
		canonical[5], canonical[4], canonical[7], canonical[6],
		canonical[8], canonical[9], canonical[10], canonical[11],
		canonical[12], canonical[13], canonical[14], canonical[15],
	}, nil
}

func writeGPTName(destination []byte, value string) {
	units := utf16.Encode([]rune(value))
	if len(units) > len(destination)/2 {
		units = units[:len(destination)/2]
	}
	for index, unit := range units {
		binary.LittleEndian.PutUint16(destination[index*2:index*2+2], unit)
	}
}
