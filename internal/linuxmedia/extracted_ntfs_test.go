//go:build linux

package linuxmedia

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geocausa/RufusArm64/internal/sourcefile"
	"github.com/geocausa/RufusArm64/internal/uefintfs"
)

func TestCreateExtractedNTFSOrchestratesVerifiedUEFIMedia(t *testing.T) {
	isoRoot := t.TempDir()
	writeLinuxTestFile(t, filepath.Join(isoRoot, ".disk", "info"), "Ubuntu ARM64 live media\n")
	writeLinuxTestFile(t, filepath.Join(isoRoot, "casper", "vmlinuz"), "kernel")
	writeLinuxTestFile(t, filepath.Join(isoRoot, "casper", "initrd"), "initrd")
	writeLinuxTestBytes(t, filepath.Join(isoRoot, "EFI", "BOOT", "BOOTAA64.EFI"), linuxTestARM64EFI(0x71))
	writeLinuxTestFile(t, filepath.Join(isoRoot, "boot", "grub", "grub.cfg"), "linux /casper/vmlinuz boot=casper --- quiet\n")

	manifest, err := Inspect(context.Background(), isoRoot, Options{Architecture: "arm64", RequireUEFI: true})
	if err != nil {
		t.Fatal(err)
	}
	const targetSize = uint64(256 * 1024 * 1024)
	plan, err := PlanExtractedMedia(manifest, "ntfs", "gpt", "RUFUS-NTFS", 4096, targetSize, 512)
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
	dataPartitionPath := filepath.Join(t.TempDir(), "data-partition.img")
	truncateLinuxTestFile(t, dataPartitionPath, plan.Data.SizeBytes)

	assetSource := filepath.Join("..", "..", "vendor", "uefi-ntfs", "uefi-ntfs.img")
	assetBytes, err := os.ReadFile(assetSource)
	if err != nil {
		t.Fatalf("read pinned UEFI:NTFS test asset: %v", err)
	}
	if uint64(len(assetBytes)) != uefintfs.ImageSize {
		t.Fatalf("pinned UEFI:NTFS test asset size = %d", len(assetBytes))
	}
	assetPath := filepath.Join(t.TempDir(), "uefi-ntfs.img")
	writeLinuxTestBytes(t, assetPath, assetBytes)
	bootPartitionPath := filepath.Join(t.TempDir(), "boot-partition.img")
	writeLinuxTestBytes(t, bootPartitionPath, assetBytes)

	destinationRoot := t.TempDir()
	fakeBin := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "commands.log")
	installPersistentFakeTools(t, fakeBin)
	writeLinuxExecutable(t, filepath.Join(fakeBin, "mkfs.ntfs"), "#!/bin/sh\nprintf 'mkfs.ntfs %s\\n' \"$*\" >> \"$RUFUS_TEST_LOG\"\nexit 0\n")
	writeLinuxExecutable(t, filepath.Join(fakeBin, "ntfsfix"), "#!/bin/sh\nprintf 'ntfsfix %s\\n' \"$*\" >> \"$RUFUS_TEST_LOG\"\nexit 0\n")
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv(uefintfs.ImageEnv, assetPath)
	t.Setenv("RUFUS_TEST_ISO_ROOT", isoRoot)
	t.Setenv("RUFUS_TEST_ISO_PARTITION", dataPartitionPath)
	t.Setenv("RUFUS_TEST_ISO_BOOT_PARTITION", bootPartitionPath)
	t.Setenv("RUFUS_TEST_ISO_DESTINATION", destinationRoot)
	t.Setenv("RUFUS_TEST_LOG", logPath)

	var stages []string
	result, err := CreateExtractedNTFS(context.Background(), isoPath, targetPath, ExtractedCreateOptions{
		TargetSize:      targetSize,
		ExpectedSource:  identity,
		Architecture:    "arm64",
		VolumeLabel:     "RUFUS-NTFS",
		PartitionScheme: "gpt",
		ClusterSize:     4096,
		WorkDirectory:   t.TempDir(),
	}, func(event PersistentEvent) { stages = append(stages, event.Stage) })
	if err != nil {
		t.Fatal(err)
	}
	if result.Plan != plan || result.UEFIBootPath != "EFI/BOOT/BOOTAA64.EFI" || result.UEFINTFSSHA256 != uefintfs.ImageSHA256 || len(result.SourceSHA256) != 64 {
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
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	logText := string(logData)
	for _, command := range []string{"wipefs", "mkfs.ntfs", "ntfsfix"} {
		if !strings.Contains(logText, command) {
			t.Fatalf("missing %s command in log:\n%s", command, logText)
		}
	}
	if !strings.Contains(logText, "mkfs.ntfs -F -Q -L RUFUS-NTFS -c 4096 /proc/self/fd/3") {
		t.Fatalf("NTFS format was not descriptor-bound:\n%s", logText)
	}
	if !strings.Contains(logText, "ntfsfix -n /proc/self/fd/3") {
		t.Fatalf("NTFS check was not descriptor-bound:\n%s", logText)
	}
	if !containsLinuxStage(stages, "complete") {
		t.Fatalf("completion event missing: %v", stages)
	}
}

func TestCreateExtractedNTFSRejectsAlteredAssetBeforeTargetMutation(t *testing.T) {
	isoRoot := t.TempDir()
	writeLinuxTestBytes(t, filepath.Join(isoRoot, "EFI", "BOOT", "BOOTAA64.EFI"), linuxTestARM64EFI(0x72))
	writeLinuxTestFile(t, filepath.Join(isoRoot, "payload"), "data")
	isoPath := filepath.Join(t.TempDir(), "linux.iso")
	writeLinuxTestFile(t, isoPath, "pinned-image")
	_, identity, err := sourcefile.Inspect(isoPath)
	if err != nil {
		t.Fatal(err)
	}
	const targetSize = uint64(256 * 1024 * 1024)
	targetPath := filepath.Join(t.TempDir(), "target.img")
	writeLinuxTestFile(t, targetPath, "unchanged-target")
	before, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatal(err)
	}

	fakeBin := t.TempDir()
	installPersistentFakeTools(t, fakeBin)
	writeLinuxExecutable(t, filepath.Join(fakeBin, "mkfs.ntfs"), "#!/bin/sh\nexit 0\n")
	writeLinuxExecutable(t, filepath.Join(fakeBin, "ntfsfix"), "#!/bin/sh\nexit 0\n")
	badAsset := filepath.Join(t.TempDir(), "uefi-ntfs.img")
	truncateLinuxTestFile(t, badAsset, uefintfs.ImageSize)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv(uefintfs.ImageEnv, badAsset)
	t.Setenv("RUFUS_TEST_ISO_ROOT", isoRoot)

	_, err = CreateExtractedNTFS(context.Background(), isoPath, targetPath, ExtractedCreateOptions{
		TargetSize:      targetSize,
		ExpectedSource:  identity,
		Architecture:    "arm64",
		PartitionScheme: "gpt",
		WorkDirectory:   t.TempDir(),
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("asset refusal error = %v", err)
	}
	after, readErr := os.ReadFile(targetPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(after) != string(before) {
		t.Fatal("target changed after UEFI:NTFS asset refusal")
	}
}
