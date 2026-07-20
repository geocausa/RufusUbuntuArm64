package freedos

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	mbrSectorSize       = 512
	fat32BootRegionSize = 0x600
	fat32BackupSector   = 6
)

//go:embed bootassets/rufus-mbr-code.bin
var rufusMBRCode []byte

//go:embed bootassets/fat32-freedos-pbr-0x0.bin
var fat32FreeDOSPBR0 []byte

//go:embed bootassets/fat32-freedos-pbr-0x52.bin
var fat32FreeDOSPBR52 []byte

//go:embed bootassets/fat32-freedos-pbr-0x3f0.bin
var fat32FreeDOSPBR3F0 []byte

type bootAsset struct {
	name   string
	data   []byte
	size   int
	sha256 string
}

var freeDOSBootAssets = []bootAsset{
	{"Rufus MBR code", rufusMBRCode, 440, "4fca7dcfac9f90390d00ab42c2e814952fbce41c83aa87c5c696e663efd60259"},
	{"FAT32 FreeDOS PBR prefix", fat32FreeDOSPBR0, 11, "e08eb0254294a42a6dc29fa094f8c6e4fee38513b4082deb81f305b2c31e5531"},
	{"FAT32 FreeDOS PBR loader", fat32FreeDOSPBR52, 918, "8a6fd500a6c4ca72d0a27149528a2e811954528d4340c9c2d7d284f2c5e897aa"},
	{"FAT32 FreeDOS PBR continuation", fat32FreeDOSPBR3F0, 528, "2435a2b31cfd762807f6538ff3363b21abbc9c3caa2ad936c8a54848da3f6165"},
}

// ValidateBootAssets verifies that the embedded bytes match the reviewed source
// extraction. It performs no device or filesystem operation.
func ValidateBootAssets() error {
	for _, asset := range freeDOSBootAssets {
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

// ApplyRufusMBRCode installs only the pinned bootstrap bytes and 0x55AA marker.
// Disk signature, reserved bytes, and the complete partition table are retained.
func ApplyRufusMBRCode(mbr []byte) error {
	if err := ValidateBootAssets(); err != nil {
		return err
	}
	if len(mbr) < mbrSectorSize {
		return errors.New("MBR sector is shorter than 512 bytes")
	}
	metadata := append([]byte(nil), mbr[440:510]...)
	copy(mbr[:440], rufusMBRCode)
	mbr[510], mbr[511] = 0x55, 0xaa
	if !bytes.Equal(metadata, mbr[440:510]) {
		return errors.New("MBR metadata changed while applying bootstrap code")
	}
	return nil
}

// VerifyRufusFreeDOSMBR checks the pinned code and the default Rufus FreeDOS
// MBR layout contract: one active first partition using FAT32 LBA type 0x0c.
func VerifyRufusFreeDOSMBR(mbr []byte) error {
	if err := ValidateBootAssets(); err != nil {
		return err
	}
	if len(mbr) < mbrSectorSize {
		return errors.New("MBR sector is shorter than 512 bytes")
	}
	if !bytes.Equal(mbr[:440], rufusMBRCode) {
		return errors.New("Rufus MBR bootstrap does not match the pinned asset")
	}
	if mbr[510] != 0x55 || mbr[511] != 0xaa {
		return errors.New("MBR boot marker is invalid")
	}
	first := mbr[446:462]
	if first[0] != 0x80 || first[4] != 0x0c {
		return errors.New("first partition is not active FAT32 LBA")
	}
	if binary.LittleEndian.Uint32(first[8:12]) == 0 || binary.LittleEndian.Uint32(first[12:16]) == 0 {
		return errors.New("first partition has invalid LBA geometry")
	}
	for index := 1; index < 4; index++ {
		if mbr[446+index*16] == 0x80 {
			return errors.New("more than one MBR partition is active")
		}
	}
	return nil
}

// ApplyFreeDOSFAT32BootRegions installs the pinned FreeDOS code into a formatted
// FAT32 primary boot region and its sector-6 backup. BPB and filesystem metadata
// bytes that Rufus deliberately leaves untouched are preserved exactly.
func ApplyFreeDOSFAT32BootRegions(image []byte, sectorSize int) error {
	if err := ValidateBootAssets(); err != nil {
		return err
	}
	bases, err := fat32BootBases(image, sectorSize)
	if err != nil {
		return err
	}
	if err := validateFAT32Pair(image, bases, sectorSize); err != nil {
		return err
	}
	for _, base := range bases {
		bpb := append([]byte(nil), image[base+0x0b:base+0x52]...)
		gap := append([]byte(nil), image[base+0x3e8:base+0x3f0]...)
		copy(image[base:base+len(fat32FreeDOSPBR0)], fat32FreeDOSPBR0)
		copy(image[base+0x52:base+0x52+len(fat32FreeDOSPBR52)], fat32FreeDOSPBR52)
		copy(image[base+0x3f0:base+0x3f0+len(fat32FreeDOSPBR3F0)], fat32FreeDOSPBR3F0)
		if !bytes.Equal(bpb, image[base+0x0b:base+0x52]) || !bytes.Equal(gap, image[base+0x3e8:base+0x3f0]) {
			return errors.New("FAT32 metadata changed while applying FreeDOS boot code")
		}
	}
	return VerifyFreeDOSFAT32BootRegions(image, sectorSize)
}

// VerifyFreeDOSFAT32BootRegions verifies both reviewed boot-code copies and the
// formatted FAT32 metadata they are required to preserve.
func VerifyFreeDOSFAT32BootRegions(image []byte, sectorSize int) error {
	if err := ValidateBootAssets(); err != nil {
		return err
	}
	bases, err := fat32BootBases(image, sectorSize)
	if err != nil {
		return err
	}
	if err := validateFAT32Pair(image, bases, sectorSize); err != nil {
		return err
	}
	for _, base := range bases {
		if !bytes.Equal(image[base:base+len(fat32FreeDOSPBR0)], fat32FreeDOSPBR0) ||
			!bytes.Equal(image[base+0x52:base+0x52+len(fat32FreeDOSPBR52)], fat32FreeDOSPBR52) ||
			!bytes.Equal(image[base+0x3f0:base+0x3f0+len(fat32FreeDOSPBR3F0)], fat32FreeDOSPBR3F0) {
			return fmt.Errorf("FreeDOS FAT32 boot region at byte offset %d does not match pinned assets", base)
		}
	}
	return nil
}

func fat32BootBases(image []byte, sectorSize int) ([]int, error) {
	if sectorSize != 512 && sectorSize != 4096 {
		return nil, fmt.Errorf("unsupported logical sector size %d", sectorSize)
	}
	bases := []int{0, fat32BackupSector * sectorSize}
	required := bases[1] + fat32BootRegionSize
	if len(image) < required {
		return nil, fmt.Errorf("FAT32 image has %d bytes; need at least %d", len(image), required)
	}
	return bases, nil
}

func validateFAT32Pair(image []byte, bases []int, sectorSize int) error {
	for _, base := range bases {
		if err := validateFAT32Region(image[base:base+fat32BootRegionSize], sectorSize); err != nil {
			return fmt.Errorf("FAT32 boot region at byte offset %d: %w", base, err)
		}
	}
	if !bytes.Equal(image[bases[0]+0x0b:bases[0]+0x52], image[bases[1]+0x0b:bases[1]+0x52]) {
		return errors.New("primary and backup FAT32 BIOS parameter blocks differ")
	}
	return nil
}

func validateFAT32Region(region []byte, sectorSize int) error {
	if !bytes.Equal(region[0x52:0x5a], []byte("FAT32   ")) {
		return errors.New("missing FAT32 filesystem marker")
	}
	if region[510] != 0x55 || region[511] != 0xaa {
		return errors.New("missing FAT32 boot marker")
	}
	if int(binary.LittleEndian.Uint16(region[0x0b:0x0d])) != sectorSize {
		return errors.New("FAT32 bytes-per-sector field does not match the selected logical sector size")
	}
	sectorsPerCluster := region[0x0d]
	if sectorsPerCluster == 0 || sectorsPerCluster&(sectorsPerCluster-1) != 0 {
		return errors.New("invalid FAT32 sectors-per-cluster field")
	}
	reserved := binary.LittleEndian.Uint16(region[0x0e:0x10])
	if reserved <= fat32BackupSector || region[0x10] == 0 {
		return errors.New("invalid FAT32 reserved-sector or FAT-count field")
	}
	if binary.LittleEndian.Uint32(region[0x20:0x24]) == 0 ||
		binary.LittleEndian.Uint32(region[0x24:0x28]) == 0 ||
		binary.LittleEndian.Uint32(region[0x2c:0x30]) < 2 {
		return errors.New("invalid FAT32 capacity, FAT size, or root cluster")
	}
	if binary.LittleEndian.Uint16(region[0x30:0x32]) >= reserved ||
		binary.LittleEndian.Uint16(region[0x32:0x34]) != fat32BackupSector {
		return errors.New("invalid FAT32 FSInfo or backup-boot-sector field")
	}
	return nil
}
