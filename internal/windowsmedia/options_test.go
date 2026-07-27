//go:build linux

package windowsmedia

import (
	"fmt"
	"testing"
)

func TestNormalizePartitionScheme(t *testing.T) {
	for input, want := range map[string]string{"": "auto", "auto": "auto", "GPT": "gpt", "mbr": "mbr"} {
		got, err := normalizePartitionScheme(input)
		if err != nil || got != want {
			t.Fatalf("%q => %q, %v", input, got, err)
		}
	}
	if _, err := normalizePartitionScheme("bsd"); err == nil {
		t.Fatal("invalid scheme accepted")
	}
}

func TestNormalizeTargetSystem(t *testing.T) {
	for input, want := range map[string]string{"": "auto", "auto": "auto", "UEFI": "uefi", "legacy-bios": "bios"} {
		got, err := normalizeTargetSystem(input)
		if err != nil || got != want {
			t.Fatalf("%q => %q, %v", input, got, err)
		}
	}
	if _, err := normalizeTargetSystem("openfirmware"); err == nil {
		t.Fatal("invalid target system accepted")
	}
}

func TestClusterSectorCount(t *testing.T) {
	for _, tc := range []struct{ bytes, sector, want uint64 }{{0, 512, 0}, {4096, 512, 8}, {32768, 4096, 8}} {
		got, err := clusterSectorCount(tc.bytes, tc.sector)
		if err != nil || got != tc.want {
			t.Fatalf("%+v => %d, %v", tc, got, err)
		}
	}
	for _, bad := range []struct{ bytes, sector uint64 }{{2048, 512}, {65536, 512}, {4096, 8192}, {6000, 512}} {
		if _, err := clusterSectorCount(bad.bytes, bad.sector); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
}

func TestNormalizeAndResolveFilesystem(t *testing.T) {
	for input, want := range map[string]string{"": "auto", "Automatic": "auto", "FAT": "fat32", "vfat": "fat32", "NTFS": "ntfs"} {
		got, err := normalizeFilesystem(input)
		if err != nil || got != want {
			t.Fatalf("%q => %q, %v", input, got, err)
		}
	}
	if _, err := normalizeFilesystem("exfat"); err == nil {
		t.Fatal("unsupported filesystem accepted")
	}
	fatErr := fmt.Errorf("too large for FAT32")
	for _, tc := range []struct {
		requested string
		fatErr    error
		want      string
		wantErr   bool
	}{
		{"auto", nil, "fat32", false},
		{"auto", fatErr, "ntfs", false},
		{"fat32", nil, "fat32", false},
		{"fat32", fatErr, "", true},
		{"ntfs", fatErr, "ntfs", false},
	} {
		got, err := resolveFilesystem(tc.requested, tc.fatErr)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Fatalf("%+v => %q, %v", tc, got, err)
		}
	}
}
