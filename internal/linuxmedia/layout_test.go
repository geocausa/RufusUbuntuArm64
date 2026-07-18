//go:build linux

package linuxmedia

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
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
	if _, err := PlanPersistentLayout(8*1024*1024*1024, 8192, 128*1024*1024, 0, readyUbuntuDetection()); err == nil {
		t.Fatal("accepted a logical sector size that FAT32 cannot represent safely")
	}
	if _, err := PlanPersistentLayout(8*1024*1024*1024, 512, 128*1024*1024, minimumPersistence+1, readyUbuntuDetection()); err == nil {
		t.Fatal("accepted unaligned persistence size")
	}
}

func TestEstimateFAT32BytesIncludesAllocationAndDirectoryOverhead(t *testing.T) {
	manifest := Manifest{
		TotalBytes: 3,
		Entries: []Entry{
			{Path: "EFI"},
			{Path: "EFI/BOOT"},
			{Path: "EFI/BOOT/BOOTAA64.EFI", Size: 3, SHA256: strings.Repeat("0", 64)},
		},
	}
	estimate, err := EstimateFAT32Bytes(manifest)
	if err != nil {
		t.Fatal(err)
	}
	want := manifest.TotalBytes + uint64(len(manifest.Entries))*fat32EntryOverhead
	if estimate != want {
		t.Fatalf("estimate=%d want=%d", estimate, want)
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
	entries := make([]byte, 2*layoutGPTEntrySize)
	if _, err := file.ReadAt(entries, int64(2*layout.SectorSize)); err != nil {
		file.Close()
		t.Fatal(err)
	}
	for index := 0; index < 2; index++ {
		entry := entries[index*layoutGPTEntrySize : (index+1)*layoutGPTEntrySize]
		if attributes := binary.LittleEndian.Uint64(entry[48:56]); attributes != layoutGPTNoAutomount {
			file.Close()
			t.Fatalf("partition %d attributes=%#x want=%#x", index+1, attributes, layoutGPTNoAutomount)
		}
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

type recordingLayoutTarget struct {
	*os.File
	operations []string
	sectorSize uint64
	targetSize uint64
}

func (target *recordingLayoutTarget) WriteAt(data []byte, offset int64) (int, error) {
	name := "other"
	entryBytes := int64(layoutGPTEntryCount * layoutGPTEntrySize)
	entryLBAs := (uint64(entryBytes) + target.sectorSize - 1) / target.sectorSize
	backupHeader := int64(target.targetSize - target.sectorSize)
	backupEntries := int64(target.targetSize - (entryLBAs+1)*target.sectorSize)
	switch offset {
	case backupEntries:
		name = "backup-entries"
	case backupHeader:
		name = "backup-header"
	case int64(2 * target.sectorSize):
		name = "primary-entries"
	case int64(target.sectorSize):
		name = "primary-header"
	case 0:
		name = "protective-mbr"
	}
	target.operations = append(target.operations, name)
	return target.File.WriteAt(data, offset)
}

func (target *recordingLayoutTarget) Sync() error {
	target.operations = append(target.operations, "sync")
	return target.File.Sync()
}

func TestWritePersistentGPTMakesBackupDurableBeforePrimary(t *testing.T) {
	layout, err := PlanPersistentLayout(4*1024*1024*1024, 512, 64*1024*1024, minimumPersistence, readyUbuntuDetection())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "disk.img")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := file.Truncate(int64(layout.TargetSize)); err != nil {
		t.Fatal(err)
	}
	target := &recordingLayoutTarget{File: file, sectorSize: layout.SectorSize, targetSize: layout.TargetSize}
	if err := WritePersistentGPT(target, layout); err != nil {
		t.Fatal(err)
	}
	want := []string{"backup-entries", "backup-header", "sync", "primary-entries", "primary-header", "protective-mbr", "sync"}
	if strings.Join(target.operations, ",") != strings.Join(want, ",") {
		t.Fatalf("operation order=%v want=%v", target.operations, want)
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
