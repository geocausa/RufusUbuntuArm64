//go:build linux

package windowsmedia

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/geocausa/RufusArm64/internal/uefintfs"
)

func TestSharedUEFINTFSAssetEvidenceMatchesWindowsMedia(t *testing.T) {
	if uefintfs.ImageSHA256 != uefiNTFSImageSHA256 {
		t.Fatalf("shared UEFI:NTFS SHA-256 = %s, Windows media expects %s", uefintfs.ImageSHA256, uefiNTFSImageSHA256)
	}
	if uefintfs.ImageSize != oneMiB {
		t.Fatalf("shared UEFI:NTFS size = %d, want %d", uefintfs.ImageSize, oneMiB)
	}
	if uefintfs.BundledImage != bundledUEFINTFSPath {
		t.Fatalf("shared UEFI:NTFS package path = %q, Windows media expects %q", uefintfs.BundledImage, bundledUEFINTFSPath)
	}
}

func TestSharedUEFINTFSMBRGeometryMatchesWindowsMedia(t *testing.T) {
	const targetSize = uint64(64 * 1024 * 1024)
	const sectorSize = uint64(512)

	legacy, err := mbrUEFINTFSLayoutForSize(targetSize, sectorSize, uefintfs.ImageSize)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := uefintfs.PlanLayout(uefintfs.SchemeMBR, targetSize, sectorSize)
	if err != nil {
		t.Fatal(err)
	}
	assertSharedLayoutMatchesWindows(t, shared, legacy)
}

func TestSharedUEFINTFSGPTGeometryMatchesWindowsMedia(t *testing.T) {
	const targetSize = uint64(64 * 1024 * 1024)
	const sectorSize = uint64(512)

	path := filepath.Join(t.TempDir(), "windows-gpt.img")
	target, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if err := target.Truncate(int64(targetSize)); err != nil {
		t.Fatal(err)
	}
	legacy, err := writeUEFINTFSGPT(target, targetSize, sectorSize, "WINDOWS", uefintfs.ImageSize)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := uefintfs.PlanLayout(uefintfs.SchemeGPT, targetSize, sectorSize)
	if err != nil {
		t.Fatal(err)
	}
	assertSharedLayoutMatchesWindows(t, shared, legacy)
}

func assertSharedLayoutMatchesWindows(t *testing.T, shared uefintfs.Layout, legacy diskLayout) {
	t.Helper()
	if shared.Data.StartBytes != legacy.Data.PartitionStartBytes || shared.Data.SizeBytes != legacy.Data.PartitionSizeBytes {
		t.Fatalf("shared data extent = %+v, Windows media = %+v", shared.Data, legacy.Data)
	}
	if legacy.Boot == nil {
		t.Fatal("Windows media UEFI:NTFS layout has no boot partition")
	}
	if shared.Boot.StartBytes != legacy.Boot.PartitionStartBytes || shared.Boot.SizeBytes != legacy.Boot.PartitionSizeBytes {
		t.Fatalf("shared boot extent = %+v, Windows media = %+v", shared.Boot, *legacy.Boot)
	}
}
