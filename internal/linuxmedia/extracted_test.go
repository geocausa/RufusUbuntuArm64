//go:build linux

package linuxmedia

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

func TestPlanExtractedLayoutUsesSingleAlignedFAT32Partition(t *testing.T) {
	const targetSize = uint64(512 * 1024 * 1024)
	layout, err := PlanExtractedLayout(targetSize, 512, 32*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if layout.Partition.Number != 1 || layout.Partition.StartBytes != 1024*1024 {
		t.Fatalf("unexpected partition start: %#v", layout)
	}
	if layout.Partition.SizeBytes != targetSize-layout.Partition.StartBytes {
		t.Fatalf("partition does not use remaining capacity: %#v", layout)
	}
	if err := validateExtractedLayout(layout); err != nil {
		t.Fatal(err)
	}
}

func TestPlanExtractedLayoutRejectsUnsafeGeometryAndCapacity(t *testing.T) {
	if _, err := PlanExtractedLayout(64*1024*1024, 512, 1); err == nil {
		t.Fatal("accepted a target below the minimum ISO Image mode size")
	}
	if _, err := PlanExtractedLayout(512*1024*1024, 1000, 1); err == nil {
		t.Fatal("accepted an unsupported logical sector size")
	}
	if _, err := PlanExtractedLayout(128*1024*1024, 512, 120*1024*1024); err == nil {
		t.Fatal("accepted a media tree that cannot fit with the safety margin")
	}
}

func TestWriteExtractedMBRWritesActiveFAT32LBAEntry(t *testing.T) {
	const targetSize = uint64(512 * 1024 * 1024)
	layout, err := PlanExtractedLayout(targetSize, 512, 8*1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "target.img")
	truncateLinuxTestFile(t, path, targetSize)
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := WriteExtractedMBR(file, layout); err != nil {
		t.Fatal(err)
	}
	sector := make([]byte, 512)
	if _, err := file.ReadAt(sector, 0); err != nil {
		t.Fatal(err)
	}
	entry := sector[446:462]
	if entry[0] != 0x80 || entry[4] != 0x0c || sector[510] != 0x55 || sector[511] != 0xaa {
		t.Fatalf("unexpected MBR bytes: entry=%x signature=%x", entry, sector[510:512])
	}
	if got := uint64(binary.LittleEndian.Uint32(entry[8:12])) * 512; got != layout.Partition.StartBytes {
		t.Fatalf("partition start=%d want=%d", got, layout.Partition.StartBytes)
	}
	if got := uint64(binary.LittleEndian.Uint32(entry[12:16])) * 512; got != layout.Partition.SizeBytes {
		t.Fatalf("partition size=%d want=%d", got, layout.Partition.SizeBytes)
	}
}

func TestCreateExtractedOrchestratesVerifiedUEFIMedia(t *testing.T) {
	isoRoot := t.TempDir()
	writeLinuxTestFile(t, filepath.Join(isoRoot, ".disk", "info"), "Ubuntu ARM64 live media\n")
	writeLinuxTestFile(t, filepath.Join(isoRoot, "casper", "vmlinuz"), "kernel")
	writeLinuxTestFile(t, filepath.Join(isoRoot, "casper", "initrd"), "initrd")
	writeLinuxTestBytes(t, filepath.Join(isoRoot, "EFI", "BOOT", "BOOTAA64.EFI"), linuxTestARM64EFI(0x44))
	writeLinuxTestFile(t, filepath.Join(isoRoot, "boot", "grub", "grub.cfg"), "linux /casper/vmlinuz boot=casper --- quiet\n")

	manifest, err := Inspect(context.Background(), isoRoot, Options{Architecture: "arm64", RequireUEFI: true, RequireFAT32: true})
	if err != nil {
		t.Fatal(err)
	}
	fat32Bytes, err := EstimateFAT32Bytes(manifest)
	if err != nil {
		t.Fatal(err)
	}
	const targetSize = uint64(512 * 1024 * 1024)
	layout, err := PlanExtractedLayout(targetSize, 512, fat32Bytes)
	if err != nil {
		t.Fatal(err)
	}

	isoPath := filepath.Join(t.TempDir(), "ubuntu.iso")
	writeLinuxTestFile(t, isoPath, "pinned-image")
	_, identity, err := sourcefile.Inspect(isoPath)
	if err != nil {
		t.Fatal(err)
	}
	targetPath := filepath.Join(t.TempDir(), "target.img")
	truncateLinuxTestFile(t, targetPath, targetSize)
	partitionPath := filepath.Join(t.TempDir(), "partition.img")
	truncateLinuxTestFile(t, partitionPath, layout.Partition.SizeBytes)
	destinationRoot := t.TempDir()
	fakeBin := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "commands.log")
	installPersistentFakeTools(t, fakeBin)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("RUFUS_TEST_ISO_ROOT", isoRoot)
	t.Setenv("RUFUS_TEST_ISO_PARTITION", partitionPath)
	t.Setenv("RUFUS_TEST_ISO_DESTINATION", destinationRoot)
	t.Setenv("RUFUS_TEST_LOG", logPath)

	var stages []string
	result, err := CreateExtracted(context.Background(), isoPath, targetPath, ExtractedCreateOptions{
		TargetSize:     targetSize,
		ExpectedSource: identity,
		Architecture:   "arm64",
		VolumeLabel:    "RUFUS-LIVE",
		WorkDirectory:  t.TempDir(),
	}, func(event PersistentEvent) { stages = append(stages, event.Stage) })
	if err != nil {
		t.Fatal(err)
	}
	if result.Layout.Partition != layout.Partition || result.UEFIBootPath != "EFI/BOOT/BOOTAA64.EFI" || len(result.SourceSHA256) != 64 {
		t.Fatalf("unexpected result: %#v", result)
	}
	for _, path := range []string{
		filepath.Join(destinationRoot, "EFI", "BOOT", "BOOTAA64.EFI"),
		filepath.Join(destinationRoot, "casper", "vmlinuz"),
		filepath.Join(destinationRoot, "boot", "grub", "grub.cfg"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("copied path %s: %v", path, err)
		}
	}
	config, err := os.ReadFile(filepath.Join(destinationRoot, "boot", "grub", "grub.cfg"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(config), " persistent ") {
		t.Fatalf("ordinary ISO Image mode unexpectedly patched persistence: %s", config)
	}
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	logText := string(logData)
	for _, command := range []string{"wipefs", "mkfs.vfat", "fsck.vfat"} {
		if !strings.Contains(logText, command) {
			t.Fatalf("missing %s command in log:\n%s", command, logText)
		}
	}
	if !strings.Contains(logText, "mkfs.vfat -F 32 -s 8 -n RUFUS-LIVE /proc/self/fd/3") {
		t.Fatalf("FAT32 format was not descriptor-bound:\n%s", logText)
	}
	if !containsLinuxStage(stages, "complete") {
		t.Fatalf("completion event missing: %v", stages)
	}
}
