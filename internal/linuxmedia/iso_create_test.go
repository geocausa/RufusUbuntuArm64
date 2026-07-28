//go:build linux

package linuxmedia

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

func TestCreateISOImageOrchestratesVerifiedFAT32Media(t *testing.T) {
	isoRoot := t.TempDir()
	writeLinuxTestFile(t, filepath.Join(isoRoot, ".disk", "info"), "Ubuntu test arm64\n")
	writeLinuxTestFile(t, filepath.Join(isoRoot, "casper", "vmlinuz"), "kernel")
	writeLinuxTestFile(t, filepath.Join(isoRoot, "casper", "initrd"), "initrd")
	writeLinuxTestFile(t, filepath.Join(isoRoot, "casper", "filesystem.squashfs"), "squashfs")
	writeLinuxTestBytes(t, filepath.Join(isoRoot, "EFI", "BOOT", "BOOTAA64.EFI"), linuxTestARM64EFI(0x44))
	writeLinuxTestFile(t, filepath.Join(isoRoot, "boot", "grub", "grub.cfg"), "linux /casper/vmlinuz boot=casper --- quiet\n")

	manifest, err := Inspect(context.Background(), isoRoot, Options{Architecture: "arm64", RequireUEFI: true, RequireFAT32: true})
	if err != nil {
		t.Fatal(err)
	}
	required, err := EstimateFAT32Bytes(manifest)
	if err != nil {
		t.Fatal(err)
	}
	const targetSize = uint64(2 * 1024 * 1024 * 1024)
	layout, err := PlanISOImageLayout(targetSize, 512, required)
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
	bootPartition := filepath.Join(t.TempDir(), "boot-partition.img")
	truncateLinuxTestFile(t, bootPartition, layout.Partition.SizeBytes)
	bootRoot := t.TempDir()
	fakeBin := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "commands.log")
	installPersistentFakeTools(t, fakeBin)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("RUFUS_TEST_ISO_ROOT", isoRoot)
	t.Setenv("RUFUS_TEST_BOOT_ROOT", bootRoot)
	t.Setenv("RUFUS_TEST_BOOT_PARTITION", bootPartition)
	t.Setenv("RUFUS_TEST_LOG", logPath)

	var stages []string
	result, err := CreateISOImage(context.Background(), isoPath, targetPath, ISOImageCreateOptions{
		TargetSize:     targetSize,
		ExpectedSource: identity,
		Architecture:   "arm64",
		VolumeLabel:    "RUFUS-LIVE",
		WorkDirectory:  t.TempDir(),
	}, func(event PersistentEvent) { stages = append(stages, event.Stage) })
	if err != nil {
		t.Fatal(err)
	}
	if result.Layout.Partition.Number != 1 || result.Manifest.Files != manifest.Files || len(result.SourceSHA256) != 64 {
		t.Fatalf("unexpected ISO Image mode result: %#v", result)
	}
	for _, path := range []string{
		filepath.Join(bootRoot, "EFI", "BOOT", "BOOTAA64.EFI"),
		filepath.Join(bootRoot, "casper", "filesystem.squashfs"),
		filepath.Join(bootRoot, "boot", "grub", "grub.cfg"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("copied path missing %s: %v", path, err)
		}
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
	if strings.Contains(logText, "mkfs.ext4") || strings.Contains(logText, "e2fsck") {
		t.Fatalf("ISO Image mode unexpectedly invoked persistence filesystem tools:\n%s", logText)
	}
	if !containsLinuxStage(stages, "complete") {
		t.Fatalf("completion event missing: %v", stages)
	}
}

func TestCreateISOImageRefusesUnsupportedTreeBeforeTargetMutation(t *testing.T) {
	isoRoot := t.TempDir()
	writeLinuxTestFile(t, filepath.Join(isoRoot, "casper", "filesystem.squashfs"), "payload")
	writeLinuxTestFile(t, filepath.Join(isoRoot, "bad:name"), "unsupported FAT32 path")
	isoPath := filepath.Join(t.TempDir(), "ubuntu.iso")
	writeLinuxTestFile(t, isoPath, "pinned-image")
	_, identity, err := sourcefile.Inspect(isoPath)
	if err != nil {
		t.Fatal(err)
	}
	targetPath := filepath.Join(t.TempDir(), "target.img")
	writeLinuxTestFile(t, targetPath, "unchanged-target")
	before, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	fakeBin := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "commands.log")
	installPersistentFakeTools(t, fakeBin)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("RUFUS_TEST_ISO_ROOT", isoRoot)
	t.Setenv("RUFUS_TEST_LOG", logPath)

	_, err = CreateISOImage(context.Background(), isoPath, targetPath, ISOImageCreateOptions{
		TargetSize:     uint64(len(before)),
		ExpectedSource: identity,
		Architecture:   "arm64",
		VolumeLabel:    "RUFUS-LIVE",
		WorkDirectory:  t.TempDir(),
	}, nil)
	if err == nil {
		t.Fatal("accepted an ISO tree with an unsupported FAT32 path")
	}
	after, readErr := os.ReadFile(targetPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(after) != string(before) {
		t.Fatal("target changed before unsupported ISO tree was refused")
	}
	if log, _ := os.ReadFile(logPath); strings.Contains(string(log), "wipefs") {
		t.Fatalf("destructive command ran before compatibility refusal:\n%s", log)
	}
}
