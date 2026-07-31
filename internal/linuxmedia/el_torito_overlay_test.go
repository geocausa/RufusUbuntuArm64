//go:build linux

package linuxmedia

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareExtractedManifestUsesTestOverlayOnlyWhenFallbackMissing(t *testing.T) {
	isoRoot := t.TempDir()
	writeLinuxTestFile(t, filepath.Join(isoRoot, "casper", "vmlinuz"), "kernel")
	overlayRoot := t.TempDir()
	writeLinuxTestBytes(t, filepath.Join(overlayRoot, "EFI", "BOOT", "BOOTAA64.EFI"), linuxTestARM64EFI(0x91))
	isoPath := filepath.Join(t.TempDir(), "source.iso")
	writeLinuxTestFile(t, isoPath, "held-source")
	isoFile, err := os.Open(isoPath)
	if err != nil {
		t.Fatal(err)
	}
	defer isoFile.Close()
	t.Setenv("RUFUS_TEST_EL_TORITO_ROOT", overlayRoot)
	prepared, err := prepareExtractedManifest(context.Background(), isoFile, isoRoot, t.TempDir(), Options{
		Architecture: "arm64", RequireUEFI: true, RequireFAT32: true,
	}, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	if prepared.Manifest.UEFIBootPath != "EFI/BOOT/BOOTAA64.EFI" || len(prepared.Manifest.SourceRoots) != 2 {
		t.Fatalf("prepared manifest=%#v", prepared.Manifest)
	}
	if prepared.Manifest.ElToritoOverlay != nil {
		t.Fatal("test-only overlay must not invent production El Torito plan evidence")
	}
}

func TestPrepareExtractedManifestReportsMissingFallbackAndInvalidISO(t *testing.T) {
	isoRoot := t.TempDir()
	writeLinuxTestFile(t, filepath.Join(isoRoot, "casper", "vmlinuz"), "kernel")
	isoPath := filepath.Join(t.TempDir(), "source.iso")
	writeLinuxTestFile(t, isoPath, "not-an-el-torito-iso")
	isoFile, err := os.Open(isoPath)
	if err != nil {
		t.Fatal(err)
	}
	defer isoFile.Close()
	_, err = prepareExtractedManifest(context.Background(), isoFile, isoRoot, t.TempDir(), Options{
		Architecture: "arm64", RequireUEFI: true,
	}, false, nil)
	if err == nil || !strings.Contains(err.Error(), "El Torito") {
		t.Fatalf("missing fallback error=%v", err)
	}
}
