//go:build linux

package qualification

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func validRecord() CreationRecord {
	return CreationRecord{
		Creator:       "RufusArm64 0.9",
		CreatedAt:     time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC),
		SourceSHA256:  strings.Repeat("ab", 32),
		SourceSize:    4 * 1024 * 1024 * 1024,
		Architecture:  runtime.GOARCH,
		Family:        "ubuntu-casper",
		DisplayName:   "Ubuntu 24.04 arm64",
		TargetSize:    64 * 1024 * 1024 * 1024,
		LogicalSector: 512,
		Boot: PartitionRecord{
			Number: 1, StartBytes: 1024 * 1024, SizeBytes: 8 * 1024 * 1024 * 1024,
			Filesystem: "fat32", Label: "RUFUS-LIVE",
		},
		Persistence: PartitionRecord{
			Number: 2, StartBytes: 9 * 1024 * 1024 * 1024, SizeBytes: 16 * 1024 * 1024 * 1024,
			Filesystem: "ext4", Label: "casper-rw",
		},
		BootParameter:   "persistent",
		ManifestEntries: 1200,
		ManifestBytes:   7 * 1024 * 1024 * 1024,
		PatchedPaths:    []string{"boot/grub/grub.cfg", "boot/grub/grub.cfg", "isolinux/txt.cfg"},
	}
}

func TestRecordRoundTripAndChecksum(t *testing.T) {
	root := t.TempDir()
	stored, err := WriteRecord(root, validRecord())
	if err != nil {
		t.Fatal(err)
	}
	if stored.SHA256 == "" || stored.Path != ".rufusarm64/creation.json" {
		t.Fatalf("stored = %#v", stored)
	}
	loaded, err := LoadVerifiedRecord(filepath.Join(root, filepath.FromSlash(stored.Path)))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.SHA256 != stored.SHA256 || len(loaded.Record.PatchedPaths) != 2 {
		t.Fatalf("loaded = %#v", loaded)
	}
}

func TestRecordRejectsTamperedChecksum(t *testing.T) {
	root := t.TempDir()
	stored, err := WriteRecord(root, validRecord())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, filepath.FromSlash(stored.Path))
	if err := os.WriteFile(path+".sha256", []byte(strings.Repeat("0", 64)+"  creation.json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadVerifiedRecord(path); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("error = %v", err)
	}
}

func TestRecordRefusesMetadataSymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, metadataDirName)); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteRecord(root, validRecord()); err == nil || !strings.Contains(err.Error(), "real directory") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseRecordRejectsUnknownField(t *testing.T) {
	data, _, err := MarshalRecord(validRecord())
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), "\n}", ",\n  \"unknown\": true\n}", 1))
	if _, _, err := ParseRecord(data); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("error = %v", err)
	}
}
