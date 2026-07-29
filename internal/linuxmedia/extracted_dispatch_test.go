//go:build linux

package linuxmedia

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

func TestSelectExtractedFilesystemImagePrefersFAT32(t *testing.T) {
	isoRoot := t.TempDir()
	writeLinuxTestBytes(t, filepath.Join(isoRoot, "EFI", "BOOT", "BOOTAA64.EFI"), linuxTestARM64EFI(0x81))
	writeLinuxTestFile(t, filepath.Join(isoRoot, "casper", "vmlinuz"), "kernel")
	isoPath, identity := dispatchTestSource(t)
	t.Setenv("RUFUS_TEST_ISO_ROOT", isoRoot)

	selection, err := SelectExtractedFilesystemImage(context.Background(), isoPath, ExtractedCreateOptions{
		ExpectedSource: identity,
		Architecture:   "arm64",
		WorkDirectory:  t.TempDir(),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if selection.Requested != ExtractedFilesystemAutomatic || selection.Selected != ExtractedFilesystemFAT32 || selection.FAT32Refusal != "" {
		t.Fatalf("selection = %+v", selection)
	}
}

func TestSelectExtractedFilesystemImageUsesNTFSForFAT32LongPath(t *testing.T) {
	isoRoot := t.TempDir()
	writeLinuxTestBytes(t, filepath.Join(isoRoot, "EFI", "BOOT", "BOOTAA64.EFI"), linuxTestARM64EFI(0x82))
	longRelative := filepath.Join(strings.Repeat("segment/", 31), "payload.bin")
	writeLinuxTestFile(t, filepath.Join(isoRoot, longRelative), "payload")
	isoPath, identity := dispatchTestSource(t)
	t.Setenv("RUFUS_TEST_ISO_ROOT", isoRoot)

	selection, err := SelectExtractedFilesystemImage(context.Background(), isoPath, ExtractedCreateOptions{
		ExpectedSource: identity,
		Architecture:   "arm64",
		WorkDirectory:  t.TempDir(),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if selection.Selected != ExtractedFilesystemNTFS || !strings.Contains(selection.FAT32Refusal, "FAT32 path limit") {
		t.Fatalf("selection = %+v", selection)
	}
	if message := automaticExtractedFilesystemMessage(selection); !strings.Contains(message, "chose NTFS") || !strings.Contains(message, "FAT32 path limit") {
		t.Fatalf("message = %q", message)
	}
}

func TestSelectExtractedFilesystemImageRequiresBoundSource(t *testing.T) {
	if _, err := SelectExtractedFilesystemImage(context.Background(), "missing.iso", ExtractedCreateOptions{}, nil); err == nil || !strings.Contains(err.Error(), "identity-bound") {
		t.Fatalf("error = %v", err)
	}
	if _, err := normalizeExtractedFilesystem("ext4"); err == nil {
		t.Fatal("unsupported dispatch filesystem was accepted")
	}
}

func dispatchTestSource(t *testing.T) (string, sourcefile.Identity) {
	t.Helper()
	isoPath := filepath.Join(t.TempDir(), "linux.iso")
	writeLinuxTestFile(t, isoPath, "pinned-image")
	_, identity, err := sourcefile.Inspect(isoPath)
	if err != nil {
		t.Fatal(err)
	}
	return isoPath, identity
}
