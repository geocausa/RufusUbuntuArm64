package freedos

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

func TestPinnedBootAssetsAreValid(t *testing.T) {
	if err := ValidateBootAssets(); err != nil {
		t.Fatalf("pinned boot assets are invalid: %v", err)
	}
}

func TestRufusMBRCodePreservesMetadata(t *testing.T) {
	mbr := make([]byte, 512)
	for index := 440; index < 510; index++ {
		mbr[index] = byte(index)
	}
	mbr[446] = 0x80
	mbr[450] = 0x0c
	binary.LittleEndian.PutUint32(mbr[454:458], 2048)
	binary.LittleEndian.PutUint32(mbr[458:462], 1024*1024)
	metadata := append([]byte(nil), mbr[440:510]...)

	if err := ApplyRufusMBRCode(mbr); err != nil {
		t.Fatalf("apply Rufus MBR code: %v", err)
	}
	if !bytes.Equal(metadata, mbr[440:510]) {
		t.Fatal("disk signature, reserved bytes, or partition table changed")
	}
	if err := VerifyRufusFreeDOSMBR(mbr); err != nil {
		t.Fatalf("verify Rufus FreeDOS MBR: %v", err)
	}

	mbr[32] ^= 0xff
	if err := VerifyRufusFreeDOSMBR(mbr); err == nil {
		t.Fatal("tampered MBR bootstrap was accepted")
	}
}

func TestRufusMBRVerifierRejectsUnsafeLayout(t *testing.T) {
	mbr := make([]byte, 512)
	mbr[446] = 0x80
	mbr[450] = 0x0c
	binary.LittleEndian.PutUint32(mbr[454:458], 2048)
	binary.LittleEndian.PutUint32(mbr[458:462], 4096)
	if err := ApplyRufusMBRCode(mbr); err != nil {
		t.Fatal(err)
	}

	mbr[462] = 0x80
	if err := VerifyRufusFreeDOSMBR(mbr); err == nil {
		t.Fatal("multiple active partitions were accepted")
	}
	mbr[462] = 0
	mbr[450] = 0x0b
	if err := VerifyRufusFreeDOSMBR(mbr); err == nil {
		t.Fatal("non-LBA FAT32 partition was accepted")
	}
}

func TestFreeDOSFAT32BootRegions(t *testing.T) {
	for _, sectorSize := range []int{512, 4096} {
		t.Run(fmt.Sprintf("sector-%d", sectorSize), func(t *testing.T) {
			image := syntheticFAT32BootImage(sectorSize)
			bases := []int{0, fat32BackupSector * sectorSize}
			bpbs := make([][]byte, len(bases))
			gaps := make([][]byte, len(bases))
			for index, base := range bases {
				bpbs[index] = append([]byte(nil), image[base+0x0b:base+0x52]...)
				gaps[index] = append([]byte(nil), image[base+0x3e8:base+0x3f0]...)
			}

			if err := ApplyFreeDOSFAT32BootRegions(image, sectorSize); err != nil {
				t.Fatalf("apply FreeDOS FAT32 boot regions: %v", err)
			}
			if err := VerifyFreeDOSFAT32BootRegions(image, sectorSize); err != nil {
				t.Fatalf("verify FreeDOS FAT32 boot regions: %v", err)
			}
			for index, base := range bases {
				if !bytes.Equal(bpbs[index], image[base+0x0b:base+0x52]) {
					t.Fatalf("BPB changed at boot-region base %d", base)
				}
				if !bytes.Equal(gaps[index], image[base+0x3e8:base+0x3f0]) {
					t.Fatalf("filesystem metadata gap changed at boot-region base %d", base)
				}
			}

			image[bases[1]+0x80] ^= 0x01
			if err := VerifyFreeDOSFAT32BootRegions(image, sectorSize); err == nil {
				t.Fatal("tampered backup boot region was accepted")
			}
		})
	}
}

func TestFreeDOSFAT32RejectsInvalidMetadata(t *testing.T) {
	image := syntheticFAT32BootImage(512)
	binary.LittleEndian.PutUint16(image[0x32:0x34], 7)
	if err := ApplyFreeDOSFAT32BootRegions(image, 512); err == nil {
		t.Fatal("unexpected FAT32 backup sector was accepted")
	}

	image = syntheticFAT32BootImage(512)
	image[fat32BackupSector*512+0x0d] = 4
	if err := ApplyFreeDOSFAT32BootRegions(image, 512); err == nil {
		t.Fatal("mismatched primary and backup BPBs were accepted")
	}

	if err := ApplyFreeDOSFAT32BootRegions(make([]byte, 4096), 4096); err == nil {
		t.Fatal("short FAT32 image was accepted")
	}
	if err := ApplyFreeDOSFAT32BootRegions(syntheticFAT32BootImage(512), 1024); err == nil {
		t.Fatal("unsupported logical sector size was accepted")
	}
}

func syntheticFAT32BootImage(sectorSize int) []byte {
	image := make([]byte, fat32BackupSector*sectorSize+fat32BootRegionSize)
	bpb := make([]byte, 0x52-0x0b)
	binary.LittleEndian.PutUint16(bpb[0x00:0x02], uint16(sectorSize))
	bpb[0x02] = 8
	binary.LittleEndian.PutUint16(bpb[0x03:0x05], 32)
	bpb[0x05] = 2
	binary.LittleEndian.PutUint32(bpb[0x15:0x19], 1024*1024)
	binary.LittleEndian.PutUint32(bpb[0x19:0x1d], 1024)
	binary.LittleEndian.PutUint32(bpb[0x21:0x25], 2)
	binary.LittleEndian.PutUint16(bpb[0x25:0x27], 1)
	binary.LittleEndian.PutUint16(bpb[0x27:0x29], fat32BackupSector)

	for _, base := range []int{0, fat32BackupSector * sectorSize} {
		copy(image[base+0x0b:base+0x52], bpb)
		copy(image[base+0x52:base+0x5a], []byte("FAT32   "))
		image[base+510], image[base+511] = 0x55, 0xaa
		for index := base + 0x3e8; index < base+0x3f0; index++ {
			image[index] = 0xa5
		}
	}
	return image
}
