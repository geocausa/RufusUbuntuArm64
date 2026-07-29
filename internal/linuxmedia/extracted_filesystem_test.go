//go:build linux

package linuxmedia

import (
	"strings"
	"testing"
)

func TestResolveExtractedFilesystemAutomaticPrefersFAT32(t *testing.T) {
	manifest := testExtractedFilesystemManifest(Entry{Path: "casper/vmlinuz", Size: 4096, SHA256: strings.Repeat("a", 64)})
	selection, err := ResolveExtractedFilesystem("auto", manifest)
	if err != nil {
		t.Fatal(err)
	}
	if selection.Requested != ExtractedFilesystemAutomatic || selection.Selected != ExtractedFilesystemFAT32 || selection.FAT32Refusal != "" {
		t.Fatalf("selection = %+v", selection)
	}
}

func TestResolveExtractedFilesystemAutomaticUsesNTFSForLargeFile(t *testing.T) {
	manifest := testExtractedFilesystemManifest(Entry{Path: "images/rootfs.img", Size: fat32MaxFileSize + 1, SHA256: strings.Repeat("b", 64)})
	selection, err := ResolveExtractedFilesystem("", manifest)
	if err != nil {
		t.Fatal(err)
	}
	if selection.Selected != ExtractedFilesystemNTFS || !strings.Contains(selection.FAT32Refusal, "single-file limit") {
		t.Fatalf("selection = %+v", selection)
	}
}

func TestResolveExtractedFilesystemAutomaticUsesNTFSForLongPath(t *testing.T) {
	longPath := strings.Repeat("segment/", 31) + "payload.bin"
	manifest := testExtractedFilesystemManifest(Entry{Path: longPath, Size: 1, SHA256: strings.Repeat("c", 64)})
	selection, err := ResolveExtractedFilesystem("auto", manifest)
	if err != nil {
		t.Fatal(err)
	}
	if selection.Selected != ExtractedFilesystemNTFS || !strings.Contains(selection.FAT32Refusal, "FAT32 path limit") {
		t.Fatalf("selection = %+v", selection)
	}
}

func TestResolveExtractedFilesystemExplicitFAT32FailsClosed(t *testing.T) {
	manifest := testExtractedFilesystemManifest(Entry{Path: "images/rootfs.img", Size: fat32MaxFileSize + 1, SHA256: strings.Repeat("d", 64)})
	if _, err := ResolveExtractedFilesystem("fat32", manifest); err == nil || !strings.Contains(err.Error(), "FAT32 is incompatible") {
		t.Fatalf("error = %v", err)
	}
}

func TestResolveExtractedFilesystemNTFSRejectsReservedAndCollidingNames(t *testing.T) {
	reserved := testExtractedFilesystemManifest(Entry{Path: "boot/CON.txt", Size: 1, SHA256: strings.Repeat("e", 64)})
	if _, err := ResolveExtractedFilesystem("ntfs", reserved); err == nil || !strings.Contains(err.Error(), "reserved NTFS name") {
		t.Fatalf("reserved-name error = %v", err)
	}

	collision := testExtractedFilesystemManifest(
		Entry{Path: "EFI/vendor/loader.efi", Size: 1, SHA256: strings.Repeat("f", 64)},
		Entry{Path: "efi/VENDOR/LOADER.EFI", Size: 1, SHA256: strings.Repeat("1", 64)},
	)
	if _, err := ResolveExtractedFilesystem("ntfs", collision); err == nil || !strings.Contains(err.Error(), "case-insensitive path collision") {
		t.Fatalf("collision error = %v", err)
	}
}

func TestResolveExtractedFilesystemRequiresUEFIAndKnownChoice(t *testing.T) {
	manifest := testExtractedFilesystemManifest()
	manifest.UEFIBootPath = ""
	if _, err := ResolveExtractedFilesystem("auto", manifest); err == nil || !strings.Contains(err.Error(), "fallback UEFI loader") {
		t.Fatalf("UEFI error = %v", err)
	}
	manifest.UEFIBootPath = "efi/boot/bootaa64.efi"
	if _, err := ResolveExtractedFilesystem("ext4", manifest); err == nil || !strings.Contains(err.Error(), "auto, fat32, or ntfs") {
		t.Fatalf("choice error = %v", err)
	}
}

func TestValidateNTFSPathBoundaries(t *testing.T) {
	for _, path := range []string{
		"directory/trailing. ",
		"directory/bad:name",
		"directory/$MFT",
		"directory/LPT9.log",
	} {
		if err := validateNTFSPath(path); err == nil {
			t.Fatalf("validateNTFSPath(%q) succeeded", path)
		}
	}
	if err := validateNTFSPath(strings.Repeat("a", 256)); err == nil || !strings.Contains(err.Error(), "too long for NTFS") {
		t.Fatalf("long-component error = %v", err)
	}
	if err := validateNTFSPath("efi/boot/bootaa64.efi"); err != nil {
		t.Fatal(err)
	}
}

func testExtractedFilesystemManifest(extra ...Entry) Manifest {
	entries := []Entry{{
		Path:   "efi/boot/bootaa64.efi",
		Size:   8192,
		SHA256: strings.Repeat("0", 64),
	}}
	entries = append(entries, extra...)
	var total uint64
	for _, entry := range entries {
		total += entry.Size
	}
	return Manifest{
		Architecture: "arm64",
		Entries:      entries,
		Files:        len(entries),
		TotalBytes:   total,
		UEFIBootPath: "efi/boot/bootaa64.efi",
	}
}
