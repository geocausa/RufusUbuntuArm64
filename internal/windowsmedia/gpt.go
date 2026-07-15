//go:build linux

package windowsmedia

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"unicode/utf16"
)

type gptLayout struct {
	PartitionStartBytes uint64
	PartitionSizeBytes  uint64
}

const (
	gptHeaderSize       = 92
	gptEntrySize        = 128
	gptEntryCount       = 128
	oneMiB              = uint64(1024 * 1024)
	minimumGPTDiskBytes = uint64(16 * 1024 * 1024)
)

var efiSystemPartitionType = [16]byte{
	0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11,
	0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b,
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

// writeSinglePartitionGPT writes a protective MBR and a standards-compliant
// primary/backup GPT containing one EFI System Partition. It writes through the
// already-open, identity-checked and exclusively locked target descriptor. This
// avoids depending on libparted's global udev queue, which can time out because
// of unrelated devices on the host.
func writeSinglePartitionGPT(target *os.File, targetSize, sectorSize uint64, label string) (gptLayout, error) {
	if target == nil {
		return gptLayout{}, errors.New("nil GPT target")
	}
	if targetSize < minimumGPTDiskBytes {
		return gptLayout{}, fmt.Errorf("target is too small for a GPT Windows installer: %s", humanBytes(targetSize))
	}
	if sectorSize < 512 || sectorSize > 64*1024 || sectorSize&(sectorSize-1) != 0 {
		return gptLayout{}, fmt.Errorf("unsupported logical sector size %d", sectorSize)
	}
	if targetSize%sectorSize != 0 {
		return gptLayout{}, fmt.Errorf("target size %d is not aligned to logical sector size %d", targetSize, sectorSize)
	}

	totalLBAs := targetSize / sectorSize
	entryBytes := uint64(gptEntryCount * gptEntrySize)
	entryLBAs := (entryBytes + sectorSize - 1) / sectorSize
	primaryEntriesLBA := uint64(2)
	backupHeaderLBA := totalLBAs - 1
	backupEntriesLBA := backupHeaderLBA - entryLBAs
	firstUsableLBA := primaryEntriesLBA + entryLBAs
	lastUsableLBA := backupEntriesLBA - 1
	partitionStartLBA := (oneMiB + sectorSize - 1) / sectorSize
	if partitionStartLBA < firstUsableLBA {
		partitionStartLBA = firstUsableLBA
	}
	if partitionStartLBA >= lastUsableLBA {
		return gptLayout{}, errors.New("target has no usable space after GPT metadata and alignment")
	}

	diskGUID, err := randomGUID()
	if err != nil {
		return gptLayout{}, fmt.Errorf("generate GPT disk GUID: %w", err)
	}
	partitionGUID, err := randomGUID()
	if err != nil {
		return gptLayout{}, fmt.Errorf("generate GPT partition GUID: %w", err)
	}

	entries := make([]byte, entryLBAs*sectorSize)
	entry := entries[:gptEntrySize]
	copy(entry[0:16], efiSystemPartitionType[:])
	copy(entry[16:32], partitionGUID[:])
	binary.LittleEndian.PutUint64(entry[32:40], partitionStartLBA)
	binary.LittleEndian.PutUint64(entry[40:48], lastUsableLBA)
	writeGPTName(entry[56:128], label)
	entriesCRC := crc32.ChecksumIEEE(entries[:entryBytes])

	primaryHeader := makeGPTHeader(
		sectorSize,
		1,
		backupHeaderLBA,
		firstUsableLBA,
		lastUsableLBA,
		diskGUID,
		primaryEntriesLBA,
		entriesCRC,
	)
	backupHeader := makeGPTHeader(
		sectorSize,
		backupHeaderLBA,
		1,
		firstUsableLBA,
		lastUsableLBA,
		diskGUID,
		backupEntriesLBA,
		entriesCRC,
	)
	protectiveMBR := makeProtectiveMBR(totalLBAs, sectorSize)

	writes := []struct {
		offset uint64
		data   []byte
		name   string
	}{
		// Write the backup first, then primary entries/header, and expose the
		// protective MBR last. A failed write therefore leaves either no visible
		// table or a table with the greatest possible amount of recoverable GPT
		// metadata, rather than advertising entries that were never persisted.
		{backupEntriesLBA * sectorSize, entries, "backup GPT entries"},
		{backupHeaderLBA * sectorSize, backupHeader, "backup GPT header"},
		{primaryEntriesLBA * sectorSize, entries, "primary GPT entries"},
		{sectorSize, primaryHeader, "primary GPT header"},
		{0, protectiveMBR, "protective MBR"},
	}
	for _, write := range writes {
		if _, err := target.WriteAt(write.data, int64(write.offset)); err != nil {
			return gptLayout{}, fmt.Errorf("write %s: %w", write.name, err)
		}
	}
	if err := target.Sync(); err != nil {
		return gptLayout{}, fmt.Errorf("sync GPT metadata: %w", err)
	}
	return gptLayout{
		PartitionStartBytes: partitionStartLBA * sectorSize,
		PartitionSizeBytes:  (lastUsableLBA - partitionStartLBA + 1) * sectorSize,
	}, nil
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

func makeGPTHeader(
	sectorSize, currentLBA, backupLBA, firstUsableLBA, lastUsableLBA uint64,
	diskGUID [16]byte,
	entriesLBA uint64,
	entriesCRC uint32,
) []byte {
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
	canonical[6] = (canonical[6] & 0x0f) | 0x40 // RFC 4122 version 4.
	canonical[8] = (canonical[8] & 0x3f) | 0x80 // RFC 4122 variant 1.
	// GPT stores the first three UUID fields little-endian and the final eight
	// bytes in network order.
	return [16]byte{
		canonical[3], canonical[2], canonical[1], canonical[0],
		canonical[5], canonical[4],
		canonical[7], canonical[6],
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
