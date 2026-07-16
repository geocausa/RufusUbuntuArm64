//go:build linux

package windowsmedia

import (
	"context"
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"

	"github.com/geocausa/RufusArm64/internal/imaging"
)

func TestWriteSinglePartitionGPT512(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.img")
	const size = uint64(64 * 1024 * 1024)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(int64(size)); err != nil {
		file.Close()
		t.Fatal(err)
	}
	layout, err := writeSinglePartitionGPT(file, size, 512, "WINDOWS")
	if err != nil {
		file.Close()
		t.Fatal(err)
	}
	if layout.PartitionStartBytes != oneMiB || layout.PartitionSizeBytes == 0 {
		file.Close()
		t.Fatalf("unexpected layout: %#v", layout)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	info, err := imaging.InspectImage(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.HasGPT || !info.HasMBR {
		t.Fatalf("generated table was not recognized: %#v", info)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data[512:520]) != "EFI PART" {
		t.Fatal("primary GPT signature missing")
	}
	if string(data[len(data)-512:len(data)-504]) != "EFI PART" {
		t.Fatal("backup GPT signature missing")
	}
	entry := data[1024 : 1024+gptEntrySize]
	if string(entry[:16]) != string(efiSystemPartitionType[:]) {
		t.Fatalf("wrong partition type GUID: %x", entry[:16])
	}
	if start := binary.LittleEndian.Uint64(entry[32:40]); start != 2048 {
		t.Fatalf("partition start=%d want 2048", start)
	}
}

func TestWriteSinglePartitionGPTFourKiBSectors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk-4k.img")
	const (
		size       = uint64(64 * 1024 * 1024)
		sectorSize = uint64(4096)
	)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(int64(size)); err != nil {
		file.Close()
		t.Fatal(err)
	}
	layout, err := writeSinglePartitionGPT(file, size, sectorSize, "WINDOWS")
	if err != nil {
		file.Close()
		t.Fatal(err)
	}
	if layout.PartitionStartBytes != oneMiB || layout.PartitionSizeBytes == 0 {
		file.Close()
		t.Fatalf("unexpected 4 KiB layout: %#v", layout)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	primary := data[sectorSize : 2*sectorSize]
	backup := data[len(data)-int(sectorSize):]
	for name, header := range map[string][]byte{"primary": primary, "backup": backup} {
		if string(header[:8]) != "EFI PART" {
			t.Fatalf("%s signature missing", name)
		}
		headerSize := binary.LittleEndian.Uint32(header[12:16])
		stored := binary.LittleEndian.Uint32(header[16:20])
		copyHeader := append([]byte(nil), header[:headerSize]...)
		binary.LittleEndian.PutUint32(copyHeader[16:20], 0)
		if got := crc32.ChecksumIEEE(copyHeader); got != stored {
			t.Fatalf("%s CRC=%08x want %08x", name, got, stored)
		}
	}
	entryStart := 2 * sectorSize
	entry := data[entryStart : entryStart+gptEntrySize]
	if start := binary.LittleEndian.Uint64(entry[32:40]); start != 256 {
		t.Fatalf("4 KiB partition start=%d want 256", start)
	}
}

func TestLogicalSectorSize(t *testing.T) {
	fakeBin := t.TempDir()
	writeExecutable(t, filepath.Join(fakeBin, "blockdev"), "#!/bin/sh\nprintf '4096\\n'\n")
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	got, err := logicalSectorSize(context.Background(), "/dev/fake")
	if err != nil || got != 4096 {
		t.Fatalf("sector size=%d err=%v", got, err)
	}
}

func TestLogicalSectorSizeRejectsInvalidValue(t *testing.T) {
	fakeBin := t.TempDir()
	writeExecutable(t, filepath.Join(fakeBin, "blockdev"), "#!/bin/sh\nprintf '1000\\n'\n")
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if _, err := logicalSectorSize(context.Background(), "/dev/fake"); err == nil {
		t.Fatal("invalid logical sector size was accepted")
	}
}

func TestWriteUEFINTFSGPT512(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk-ntfs.img")
	const (
		size          = uint64(64 * 1024 * 1024)
		bootImageSize = uint64(1024 * 1024)
	)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(int64(size)); err != nil {
		file.Close()
		t.Fatal(err)
	}
	layout, err := writeUEFINTFSGPT(file, size, 512, "WINDOWS", bootImageSize)
	if err != nil {
		file.Close()
		t.Fatal(err)
	}
	if layout.Boot == nil {
		file.Close()
		t.Fatal("missing UEFI:NTFS boot partition")
	}
	if layout.Data.PartitionStartBytes != oneMiB || layout.Data.PartitionSizeBytes == 0 {
		file.Close()
		t.Fatalf("unexpected data layout: %#v", layout.Data)
	}
	if layout.Boot.PartitionSizeBytes != bootImageSize || layout.Boot.PartitionStartBytes%oneMiB != 0 {
		file.Close()
		t.Fatalf("unexpected boot layout: %#v", *layout.Boot)
	}
	if layout.Data.PartitionStartBytes+layout.Data.PartitionSizeBytes != layout.Boot.PartitionStartBytes {
		file.Close()
		t.Fatalf("partitions are not contiguous: %#v", layout)
	}

	entries := make([]byte, 2*gptEntrySize)
	if _, err := file.ReadAt(entries, 2*512); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	dataEntry := entries[:gptEntrySize]
	bootEntry := entries[gptEntrySize : 2*gptEntrySize]
	if string(dataEntry[:16]) != string(microsoftBasicDataType[:]) {
		t.Fatalf("wrong data partition type GUID: %x", dataEntry[:16])
	}
	if string(bootEntry[:16]) != string(microsoftBasicDataType[:]) {
		t.Fatalf("wrong boot partition type GUID: %x", bootEntry[:16])
	}
	if got := binary.LittleEndian.Uint64(bootEntry[48:56]); got != gptNoDriveLetter {
		t.Fatalf("boot attributes=%016x want %016x", got, gptNoDriveLetter)
	}
	units := make([]uint16, 0, 36)
	for offset := 56; offset < 128; offset += 2 {
		unit := binary.LittleEndian.Uint16(bootEntry[offset : offset+2])
		if unit == 0 {
			break
		}
		units = append(units, unit)
	}
	if got := string(utf16.Decode(units)); got != "UEFI:NTFS" {
		t.Fatalf("boot partition name=%q", got)
	}
}
