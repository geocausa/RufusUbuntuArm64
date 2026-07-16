//go:build linux

package linuxmedia

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/geocausa/RufusArm64/internal/persistence"
)

func readyUbuntuDetection() persistence.Detection {
	return persistence.Detection{
		Family:          persistence.FamilyUbuntuCasper,
		DisplayName:     "Ubuntu casper",
		BootParameter:   "persistent",
		Filesystem:      "ext4",
		FilesystemLabel: "casper-rw",
		PatchPaths:      []string{"boot/grub/grub.cfg"},
	}
}

func TestPlanPersistentLayoutUsesAlignedGPTPartitions(t *testing.T) {
	layout, err := PlanPersistentLayout(16*1024*1024*1024, 512, 3*1024*1024*1024, 4*1024*1024*1024, readyUbuntuDetection())
	if err != nil {
		t.Fatal(err)
	}
	if layout.Boot.Number != 1 || layout.Persistence.Number != 2 || layout.Plan.PartitionNumber != 2 {
		t.Fatalf("unexpected partition numbers: %#v", layout)
	}
	if layout.Boot.StartBytes%layoutAlignment != 0 || layout.Boot.SizeBytes%layoutAlignment != 0 || layout.Persistence.StartBytes%layoutAlignment != 0 {
		t.Fatalf("layout is not MiB-aligned: %#v", layout)
	}
	if layout.Persistence.SizeBytes != 4*1024*1024*1024 || layout.Plan.SizeBytes != layout.Persistence.SizeBytes {
		t.Fatalf("persistence size mismatch: %#v", layout)
	}
	if layout.Boot.StartBytes+layout.Boot.SizeBytes > layout.Persistence.StartBytes {
		t.Fatalf("partitions overlap: %#v", layout)
	}
}

func TestPlanPersistentLayoutRejectsUnsafeGeometry(t *testing.T) {
	if _, err := PlanPersistentLayout(1024*1024*1024, 512, 128*1024*1024, 0, readyUbuntuDetection()); err == nil {
		t.Fatal("accepted undersized target")
	}
	if _, err := PlanPersistentLayout(8*1024*1024*1024, 1000, 128*1024*1024, 0, readyUbuntuDetection()); err == nil {
		t.Fatal("accepted invalid sector size")
	}
	if _, err := PlanPersistentLayout(8*1024*1024*1024, 512, 128*1024*1024, minimumPersistence+1, readyUbuntuDetection()); err == nil {
		t.Fatal("accepted unaligned persistence size")
	}
}

func TestWritePersistentGPTWritesAndVerifiesBothCopies(t *testing.T) {
	layout, err := PlanPersistentLayout(4*1024*1024*1024, 512, 64*1024*1024, 1024*1024*1024, readyUbuntuDetection())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "disk.img")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(int64(layout.TargetSize)); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := WritePersistentGPT(file, layout); err != nil {
		file.Close()
		t.Fatal(err)
	}
	sector := make([]byte, 1024)
	if _, err := file.ReadAt(sector, 0); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if sector[510] != 0x55 || sector[511] != 0xaa || sector[450] != 0xee || string(sector[512:520]) != "EFI PART" {
		file.Close()
		t.Fatalf("invalid primary GPT bytes")
	}
	backup := make([]byte, 8)
	if _, err := file.ReadAt(backup, int64(layout.TargetSize-layout.SectorSize)); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if !bytes.Equal(backup, []byte("EFI PART")) {
		file.Close()
		t.Fatalf("backup GPT signature=%q", backup)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPlanPersistentLayoutSupportsFourKiBLogicalSectors(t *testing.T) {
	layout, err := PlanPersistentLayout(8*1024*1024*1024, 4096, 512*1024*1024, 2*1024*1024*1024, readyUbuntuDetection())
	if err != nil {
		t.Fatal(err)
	}
	if layout.Boot.StartBytes%4096 != 0 || layout.Persistence.StartBytes%4096 != 0 {
		t.Fatalf("4K layout is unaligned: %#v", layout)
	}
}

func TestWritePersistentGPTRejectsOverlappingLayout(t *testing.T) {
	layout, err := PlanPersistentLayout(4*1024*1024*1024, 512, 64*1024*1024, minimumPersistence, readyUbuntuDetection())
	if err != nil {
		t.Fatal(err)
	}
	layout.Persistence.StartBytes = layout.Boot.StartBytes
	layout.Plan.StartBytes = layout.Persistence.StartBytes
	path := filepath.Join(t.TempDir(), "disk.img")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := file.Truncate(int64(layout.TargetSize)); err != nil {
		t.Fatal(err)
	}
	if err := WritePersistentGPT(file, layout); err == nil {
		t.Fatal("accepted overlapping persistent layout")
	}
}
