//go:build linux

package windowsmedia

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

// The boot-code fragments below are pinned from Rufus 4.15's GPL ms-sys
// implementation. The original source files and notices are shipped under
// vendor/ms-sys. Embedding the exact bytes in the privileged helper avoids
// runtime path replacement and packaging mismatches.

//go:embed bootassets/windows7-mbr-code.bin
var windows7MBRCode []byte

//go:embed bootassets/ntfs-pbr-0x0.bin
var ntfsPBR0 []byte

//go:embed bootassets/ntfs-pbr-0x54.bin
var ntfsPBR54 []byte

//go:embed bootassets/fat32-pbr-0x0.bin
var fat32PBR0 []byte

//go:embed bootassets/fat32-pbr-0x52.bin
var fat32PBR52 []byte

//go:embed bootassets/fat32-pbr-0x3f0.bin
var fat32PBR3F0 []byte

//go:embed bootassets/fat32-pbr-0x1800.bin
var fat32PBR1800 []byte

type bootCodeAsset struct {
	name   string
	data   []byte
	size   int
	sha256 string
}

var legacyBootAssets = []bootCodeAsset{
	{"Windows 7 MBR", windows7MBRCode, 440, "59019b8b59cffb325855cdc7716d38f8ce2112b9b027f2f8516992e2e686525b"},
	{"NTFS PBR prefix", ntfsPBR0, 11, "31d8233ca5e09344616973de6908c8eb0d6b6792d6aac6950e44b92ad796fb52"},
	{"NTFS PBR code", ntfsPBR54, 4052, "331cd27121fb2f9954e2c269e95a0111066d8479f78f44272b4491c6b36128fd"},
	{"FAT32 PBR prefix", fat32PBR0, 11, "e08eb0254294a42a6dc29fa094f8c6e4fee38513b4082deb81f305b2c31e5531"},
	{"FAT32 PE PBR code", fat32PBR52, 923, "45fd3b18c1d320ea854fdfdcac06ef4d9ae846d84daa728f6fcdd0eeb3d6d7b1"},
	{"FAT32 PE PBR tail", fat32PBR3F0, 528, "c412950968e5b783040d78831ebec5a33ea2cc51239c32dd92b7b8729a58c669"},
	{"FAT32 PE extended boot code", fat32PBR1800, 512, "ed75f19c0705c18b3628db1e981e6c314f80009f791399abbf291513f7cbd9b4"},
}

func validateLegacyBootAssets() error {
	for _, asset := range legacyBootAssets {
		if len(asset.data) != asset.size {
			return fmt.Errorf("embedded %s has size %d; expected %d", asset.name, len(asset.data), asset.size)
		}
		digest := fmt.Sprintf("%x", sha256.Sum256(asset.data))
		if digest != asset.sha256 {
			return fmt.Errorf("embedded %s failed its pinned SHA-256 check", asset.name)
		}
	}
	return nil
}

func installLegacyBIOSBoot(disk *os.File, partitionPath, filesystem string, layout partitionLayout, sectorSize uint64) error {
	if disk == nil {
		return errors.New("nil whole-disk descriptor")
	}
	if sectorSize < 512 || sectorSize > 64*1024 || sectorSize&(sectorSize-1) != 0 {
		return fmt.Errorf("unsupported logical sector size %d", sectorSize)
	}
	if layout.PartitionStartBytes == 0 || layout.PartitionSizeBytes < 2*oneMiB {
		return errors.New("invalid legacy-BIOS partition layout")
	}
	if err := validateLegacyBootAssets(); err != nil {
		return err
	}
	if err := patchAndVerify(disk, 0, windows7MBRCode); err != nil {
		return fmt.Errorf("write Windows MBR bootstrap: %w", err)
	}
	mbr := make([]byte, 512)
	if _, err := disk.ReadAt(mbr, 0); err != nil {
		return fmt.Errorf("read back Windows MBR: %w", err)
	}
	if mbr[446] != 0x80 || mbr[510] != 0x55 || mbr[511] != 0xaa {
		return errors.New("Windows MBR bootstrap verification found an invalid active partition table")
	}

	partition, err := os.OpenFile(partitionPath, os.O_RDWR|os.O_EXCL, 0)
	if err != nil {
		return fmt.Errorf("open formatted partition for BIOS boot code: %w", err)
	}
	defer partition.Close()

	switch filesystem {
	case "ntfs":
		if err := requireFilesystemMagic(partition, 0x03, []byte("NTFS    ")); err != nil {
			return err
		}
		if err := patchAndVerify(partition, 0, ntfsPBR0); err != nil {
			return fmt.Errorf("write NTFS PBR prefix: %w", err)
		}
		if err := patchAndVerify(partition, 0x54, ntfsPBR54); err != nil {
			return fmt.Errorf("write NTFS BOOTMGR PBR: %w", err)
		}
	case "fat32":
		if err := requireFilesystemMagic(partition, 0x52, []byte("FAT32   ")); err != nil {
			return err
		}
		backupSector, err := readFAT32BackupSector(partition)
		if err != nil {
			return err
		}
		for _, base := range []uint64{0, backupSector * sectorSize} {
			patches := []struct {
				offset uint64
				data   []byte
			}{
				{0, fat32PBR0},
				{0x52, fat32PBR52},
				{0x3f0, fat32PBR3F0},
				{0x1800, fat32PBR1800},
			}
			for _, patch := range patches {
				end := base + patch.offset + uint64(len(patch.data))
				if end > layout.PartitionSizeBytes {
					return errors.New("FAT32 partition is too small for Windows BIOS boot code")
				}
				if err := patchAndVerify(partition, int64(base+patch.offset), patch.data); err != nil {
					return fmt.Errorf("write FAT32 BOOTMGR PBR at offset %#x: %w", base+patch.offset, err)
				}
			}
		}
	default:
		return fmt.Errorf("legacy BIOS boot is unsupported for filesystem %q", filesystem)
	}
	if err := partition.Sync(); err != nil {
		return fmt.Errorf("sync legacy BIOS partition boot code: %w", err)
	}
	if err := disk.Sync(); err != nil {
		return fmt.Errorf("sync legacy BIOS MBR: %w", err)
	}
	return nil
}

func requireFilesystemMagic(file *os.File, offset int64, expected []byte) error {
	actual := make([]byte, len(expected))
	if _, err := file.ReadAt(actual, offset); err != nil {
		return fmt.Errorf("read formatted filesystem signature: %w", err)
	}
	if !bytes.Equal(actual, expected) {
		return fmt.Errorf("formatted partition has signature %q, expected %q", actual, expected)
	}
	return nil
}

func readFAT32BackupSector(file *os.File) (uint64, error) {
	field := make([]byte, 2)
	if _, err := file.ReadAt(field, 0x32); err != nil {
		return 0, fmt.Errorf("read FAT32 backup boot-sector number: %w", err)
	}
	sector := uint64(binary.LittleEndian.Uint16(field))
	if sector == 0 || sector == 0xffff {
		sector = 6
	}
	if sector > 1024 {
		return 0, fmt.Errorf("invalid FAT32 backup boot-sector number %d", sector)
	}
	return sector, nil
}

func patchAndVerify(file *os.File, offset int64, data []byte) error {
	if len(data) == 0 {
		return errors.New("empty boot-code patch")
	}
	n, err := file.WriteAt(data, offset)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	actual := make([]byte, len(data))
	if _, err := file.ReadAt(actual, offset); err != nil {
		return err
	}
	if !bytes.Equal(actual, data) {
		return errors.New("boot-code readback mismatch")
	}
	return nil
}
