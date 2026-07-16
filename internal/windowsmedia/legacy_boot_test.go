//go:build linux

package windowsmedia

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallLegacyBIOSBootNTFS(t *testing.T) {
	diskPath := filepath.Join(t.TempDir(), "disk")
	partitionPath := filepath.Join(t.TempDir(), "partition")
	writeSizedTestFile(t, diskPath, 16*oneMiB)
	writeSizedTestFile(t, partitionPath, 4*oneMiB)

	disk, err := os.OpenFile(diskPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer disk.Close()
	layout, err := writeSinglePartitionMBRType(disk, 16*oneMiB, 512, 0x07)
	if err != nil {
		t.Fatal(err)
	}
	before := make([]byte, 72)
	if _, err := disk.ReadAt(before, 440); err != nil {
		t.Fatal(err)
	}

	partition, err := os.OpenFile(partitionPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := partition.WriteAt([]byte("NTFS    "), 0x03); err != nil {
		t.Fatal(err)
	}
	if _, err := partition.WriteAt([]byte{0x11, 0x22, 0x33, 0x44}, 0x30); err != nil {
		t.Fatal(err)
	}
	partition.Close()

	if err := installLegacyBIOSBoot(disk, partitionPath, "ntfs", layout, 512); err != nil {
		t.Fatal(err)
	}
	after := make([]byte, 72)
	if _, err := disk.ReadAt(after, 440); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("MBR disk signature and partition table were not preserved")
	}
	mbrCode := make([]byte, len(windows7MBRCode))
	if _, err := disk.ReadAt(mbrCode, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mbrCode, windows7MBRCode) {
		t.Fatal("Windows 7 MBR bootstrap was not installed")
	}
	pbr, err := os.ReadFile(partitionPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pbr[:len(ntfsPBR0)], ntfsPBR0) || !bytes.Equal(pbr[0x54:0x54+len(ntfsPBR54)], ntfsPBR54) {
		t.Fatal("NTFS BOOTMGR partition boot record was not installed")
	}
	if !bytes.Equal(pbr[0x30:0x34], []byte{0x11, 0x22, 0x33, 0x44}) {
		t.Fatal("NTFS BPB area was overwritten")
	}
}

func TestInstallLegacyBIOSBootFAT32PrimaryAndBackup(t *testing.T) {
	diskPath := filepath.Join(t.TempDir(), "disk")
	partitionPath := filepath.Join(t.TempDir(), "partition")
	writeSizedTestFile(t, diskPath, 16*oneMiB)
	writeSizedTestFile(t, partitionPath, 4*oneMiB)

	disk, err := os.OpenFile(diskPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer disk.Close()
	layout, err := writeSinglePartitionMBR(disk, 16*oneMiB, 512)
	if err != nil {
		t.Fatal(err)
	}
	partition, err := os.OpenFile(partitionPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := partition.WriteAt([]byte("FAT32   "), 0x52); err != nil {
		t.Fatal(err)
	}
	if _, err := partition.WriteAt([]byte{6, 0}, 0x32); err != nil {
		t.Fatal(err)
	}
	if _, err := partition.WriteAt([]byte{0xa1, 0xb2, 0xc3, 0xd4}, 0x20); err != nil {
		t.Fatal(err)
	}
	partition.Close()

	if err := installLegacyBIOSBoot(disk, partitionPath, "fat32", layout, 512); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(partitionPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, base := range []int{0, 6 * 512} {
		if !bytes.Equal(data[base:base+len(fat32PBR0)], fat32PBR0) ||
			!bytes.Equal(data[base+0x52:base+0x52+len(fat32PBR52)], fat32PBR52) ||
			!bytes.Equal(data[base+0x3f0:base+0x3f0+len(fat32PBR3F0)], fat32PBR3F0) ||
			!bytes.Equal(data[base+0x1800:base+0x1800+len(fat32PBR1800)], fat32PBR1800) {
			t.Fatalf("FAT32 Windows PE boot code missing at base %#x", base)
		}
	}
	if !bytes.Equal(data[0x20:0x24], []byte{0xa1, 0xb2, 0xc3, 0xd4}) {
		t.Fatal("FAT32 BPB area was overwritten")
	}
}

func TestLegacyBootAssetsPinned(t *testing.T) {
	if err := validateLegacyBootAssets(); err != nil {
		t.Fatal(err)
	}
}

func writeSizedTestFile(t *testing.T, path string, size uint64) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(int64(size)); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
