//go:build linux

package linuxmedia

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geocausa/RufusArm64/internal/qualification"
	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

func TestCreatePersistentOrchestratesVerifiedUbuntuMedia(t *testing.T) {
	isoRoot := t.TempDir()
	writeLinuxTestFile(t, filepath.Join(isoRoot, ".disk", "info"), "Ubuntu 24.04.2 LTS arm64\n")
	writeLinuxTestFile(t, filepath.Join(isoRoot, "casper", "vmlinuz"), "kernel")
	writeLinuxTestFile(t, filepath.Join(isoRoot, "casper", "initrd"), "initrd")
	writeLinuxTestFile(t, filepath.Join(isoRoot, "casper", "filesystem.squashfs"), "squashfs")
	writeLinuxTestFile(t, filepath.Join(isoRoot, "EFI", "BOOT", "BOOTAA64.EFI"), "efi")
	writeLinuxTestFile(t, filepath.Join(isoRoot, "boot", "grub", "grub.cfg"), "linux /casper/vmlinuz boot=casper --- quiet\n")

	manifest, err := Inspect(context.Background(), isoRoot, Options{Architecture: "arm64", RequireUEFI: true, RequireFAT32: true})
	if err != nil {
		t.Fatal(err)
	}
	const targetSize = uint64(4 * 1024 * 1024 * 1024)
	layout, err := PlanPersistentLayout(targetSize, 512, manifest.TotalBytes, minimumPersistence, readyUbuntuDetection())
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
	truncateLinuxTestFile(t, bootPartition, layout.Boot.SizeBytes)
	persistencePartition := filepath.Join(t.TempDir(), "persistence-partition.img")
	truncateLinuxTestFile(t, persistencePartition, layout.Persistence.SizeBytes)
	bootRoot := t.TempDir()
	fakeBin := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "commands.log")
	installPersistentFakeTools(t, fakeBin)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("RUFUS_TEST_ISO_ROOT", isoRoot)
	t.Setenv("RUFUS_TEST_BOOT_ROOT", bootRoot)
	t.Setenv("RUFUS_TEST_BOOT_PARTITION", bootPartition)
	t.Setenv("RUFUS_TEST_PERSIST_PARTITION", persistencePartition)
	t.Setenv("RUFUS_TEST_PARTITION", persistencePartition)
	t.Setenv("RUFUS_TEST_LOG", logPath)

	var stages []string
	result, err := CreatePersistent(context.Background(), isoPath, targetPath, PersistentCreateOptions{
		TargetSize:      targetSize,
		ExpectedSource:  identity,
		Architecture:    "arm64",
		PersistenceSize: minimumPersistence,
		VolumeLabel:     "RUFUS-LIVE",
		WorkDirectory:   t.TempDir(),
		CreatorVersion:  "RufusArm64 test",
	}, func(event PersistentEvent) { stages = append(stages, event.Stage) })
	if err != nil {
		t.Fatal(err)
	}
	if result.Layout.Persistence.SizeBytes != minimumPersistence || len(result.PatchedPaths) != 1 {
		t.Fatalf("unexpected result: %#v", result)
	}
	config, err := os.ReadFile(filepath.Join(bootRoot, "boot", "grub", "grub.cfg"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(config), "boot=casper persistent ---") {
		t.Fatalf("boot configuration was not patched: %s", config)
	}
	if _, err := os.Stat(filepath.Join(bootRoot, "EFI", "BOOT", "BOOTAA64.EFI")); err != nil {
		t.Fatal(err)
	}
	if result.QualificationRecordPath != ".rufusarm64/creation.json" || len(result.QualificationRecordSHA256) != 64 {
		t.Fatalf("qualification result = %#v", result)
	}
	record, err := qualification.LoadVerifiedRecord(filepath.Join(bootRoot, filepath.FromSlash(result.QualificationRecordPath)))
	if err != nil {
		t.Fatal(err)
	}
	if record.Record.Creator != "RufusArm64 test" || record.Record.SourceSize != uint64(identity.Size) || record.Record.Persistence.Label != "casper-rw" {
		t.Fatalf("qualification record = %#v", record.Record)
	}
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	logText := string(logData)
	for _, command := range []string{"wipefs", "mkfs.vfat", "fsck.vfat", "mkfs.ext4", "e2fsck"} {
		if !strings.Contains(logText, command) {
			t.Fatalf("missing %s command in log:\n%s", command, logText)
		}
	}
	if !strings.Contains(logText, "mkfs.vfat -F 32 -s 8") || !strings.Contains(logText, "/proc/self/fd/3") {
		t.Fatalf("FAT32 tools were not bound to the inherited partition descriptor:\n%s", logText)
	}
	if !containsLinuxStage(stages, "complete") {
		t.Fatalf("completion event missing: %v", stages)
	}
}

func TestOpenPersistentPartitionRejectsSymlinkAndWrongSize(t *testing.T) {
	realPath := filepath.Join(t.TempDir(), "partition.img")
	truncateLinuxTestFile(t, realPath, 1024*1024)
	symlinkPath := filepath.Join(t.TempDir(), "partition-link")
	if err := os.Symlink(realPath, symlinkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := openPersistentPartition(symlinkPath, PartitionLayout{SizeBytes: 1024 * 1024}, 0, true); err == nil {
		t.Fatal("accepted a symbolic-link partition path")
	}
	if _, err := openPersistentPartition(realPath, PartitionLayout{SizeBytes: 2 * 1024 * 1024}, 0, true); err == nil {
		t.Fatal("accepted a test partition with the wrong size")
	}
}

func installPersistentFakeTools(t *testing.T, directory string) {
	t.Helper()
	for _, name := range []string{"mount", "umount", "wipefs", "sync", "mkfs.vfat", "fsck.vfat", "mkfs.ext4", "e2fsck", "lsblk"} {
		writeLinuxExecutable(t, filepath.Join(directory, name), "#!/bin/sh\nprintf '"+name+" %s\\n' \"$*\" >> \"$RUFUS_TEST_LOG\"\nexit 0\n")
	}
	writeLinuxExecutable(t, filepath.Join(directory, "findmnt"), "#!/bin/sh\nexit 1\n")
	writeLinuxExecutable(t, filepath.Join(directory, "blockdev"), "#!/bin/sh\nprintf 'blockdev %s\\n' \"$*\" >> \"$RUFUS_TEST_LOG\"\ncase \"$1\" in --getss) echo 512;; --getsize64) echo 4294967296;; esac\nexit 0\n")
}

func writeLinuxExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func writeLinuxTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func truncateLinuxTestFile(t *testing.T, path string, size uint64) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(int64(size)); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func containsLinuxStage(stages []string, wanted string) bool {
	for _, stage := range stages {
		if stage == wanted {
			return true
		}
	}
	return false
}

func TestNormalizePersistentLabelRejectsUnsafeText(t *testing.T) {
	for _, value := range []string{"TOO-LONG-LABEL", "BAD/NAME", "LINE\nBREAK", "MÉDIA"} {
		if _, err := normalizePersistentLabel(value); err == nil {
			t.Fatalf("accepted unsafe FAT32 label %q", value)
		}
	}
	if label, err := normalizePersistentLabel("rufus-live"); err != nil || label != "RUFUS-LIVE" {
		t.Fatalf("label=%q err=%v", label, err)
	}
}
