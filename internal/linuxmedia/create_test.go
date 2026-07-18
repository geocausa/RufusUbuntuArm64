//go:build linux

package linuxmedia

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geocausa/RufusArm64/internal/qualification"
	"github.com/geocausa/RufusArm64/internal/runtimeintegrity"
	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

func TestCreatePersistentOrchestratesVerifiedUbuntuMedia(t *testing.T) {
	isoRoot := t.TempDir()
	writeLinuxTestFile(t, filepath.Join(isoRoot, ".disk", "info"), "Ubuntu 24.04.2 LTS arm64\n")
	writeLinuxTestFile(t, filepath.Join(isoRoot, "casper", "vmlinuz"), "kernel")
	writeLinuxTestFile(t, filepath.Join(isoRoot, "casper", "initrd"), "initrd")
	writeLinuxTestFile(t, filepath.Join(isoRoot, "casper", "filesystem.squashfs"), "squashfs")
	originalLoader := linuxTestARM64EFI(0x11)
	writeLinuxTestBytes(t, filepath.Join(isoRoot, "EFI", "BOOT", "BOOTAA64.EFI"), originalLoader)
	writeLinuxTestFile(t, filepath.Join(isoRoot, "boot", "grub", "grub.cfg"), "linux /casper/vmlinuz boot=casper --- quiet\n")
	wrapperLoader := linuxTestARM64EFI(0x22)
	wrapperPath := filepath.Join(t.TempDir(), "bootaa64.efi")
	writeLinuxTestBytes(t, wrapperPath, wrapperLoader)
	wrapperDigest := sha256.Sum256(wrapperLoader)

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
		TargetSize:                      targetSize,
		ExpectedSource:                  identity,
		Architecture:                    "arm64",
		PersistenceSize:                 minimumPersistence,
		VolumeLabel:                     "RUFUS-LIVE",
		WorkDirectory:                   t.TempDir(),
		CreatorVersion:                  "RufusArm64 test",
		RuntimeUEFIValidation:           true,
		RuntimeUEFILoaderPath:           wrapperPath,
		RuntimeUEFILoaderSHA256:         fmt.Sprintf("%x", wrapperDigest[:]),
		RuntimeUEFILoaderSourceCommit:   "6195f2ef754c2ad390bda6590628708f410d55f6",
		RuntimeUEFILoaderProvenance:     "test reproducible unsigned loader",
		RuntimeUEFIUnsignedAcknowledged: true,
	}, func(event PersistentEvent) { stages = append(stages, event.Stage) })
	if err != nil {
		t.Fatal(err)
	}
	if result.Layout.Persistence.SizeBytes != minimumPersistence || len(result.PatchedPaths) != 1 {
		t.Fatalf("unexpected result: %#v", result)
	}
	if result.RuntimeIntegrity == nil || !result.RuntimeIntegrity.VerificationValid || result.RuntimeIntegrity.SecureBootCompatible {
		t.Fatalf("runtime integrity result = %#v", result.RuntimeIntegrity)
	}
	activeLoader, err := os.ReadFile(filepath.Join(bootRoot, filepath.FromSlash(runtimeintegrity.ARM64FallbackPath)))
	if err != nil || !bytes.Equal(activeLoader, wrapperLoader) {
		t.Fatalf("active runtime loader mismatch: err=%v", err)
	}
	backedUpLoader, err := os.ReadFile(filepath.Join(bootRoot, filepath.FromSlash(runtimeintegrity.ARM64OriginalPath)))
	if err != nil || !bytes.Equal(backedUpLoader, originalLoader) {
		t.Fatalf("backed-up fallback mismatch: err=%v", err)
	}
	verification, err := runtimeintegrity.Verify(context.Background(), bootRoot, runtimeintegrity.Options{})
	if err != nil || !verification.Valid {
		t.Fatalf("runtime integrity verification = %#v err=%v", verification, err)
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
	if record.Record.Properties["runtime_uefi_validation"] != "enabled" || record.Record.Properties["runtime_uefi_wrapper_sha256"] != result.RuntimeIntegrity.WrapperSHA256 || record.Record.Properties["runtime_uefi_secure_boot_compatible"] != "false" {
		t.Fatalf("runtime integrity qualification properties = %#v", record.Record.Properties)
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
	writeLinuxTestBytes(t, path, []byte(content))
}

func writeLinuxTestBytes(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
}

func linuxTestARM64EFI(marker byte) []byte {
	data := make([]byte, 512)
	data[0], data[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(data[0x3c:0x40], 0x80)
	copy(data[0x80:0x84], []byte{'P', 'E', 0, 0})
	coff := 0x84
	binary.LittleEndian.PutUint16(data[coff:coff+2], 0xaa64)
	binary.LittleEndian.PutUint16(data[coff+16:coff+18], 0xf0)
	optional := coff + 20
	binary.LittleEndian.PutUint16(data[optional:optional+2], 0x20b)
	binary.LittleEndian.PutUint16(data[optional+68:optional+70], 10)
	data[len(data)-1] = marker
	return data
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

func TestCreatePersistentRejectsRuntimeLoaderBeforeTargetMutation(t *testing.T) {
	isoPath := filepath.Join(t.TempDir(), "ubuntu.iso")
	writeLinuxTestFile(t, isoPath, "pinned-image")
	_, identity, err := sourcefile.Inspect(isoPath)
	if err != nil {
		t.Fatal(err)
	}
	loaderPath := filepath.Join(t.TempDir(), "bootaa64.efi")
	writeLinuxTestBytes(t, loaderPath, linuxTestARM64EFI(0x33))
	targetPath := filepath.Join(t.TempDir(), "target.img")
	writeLinuxTestFile(t, targetPath, "unchanged-target")
	before, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = CreatePersistent(context.Background(), isoPath, targetPath, PersistentCreateOptions{
		ExpectedSource:                  identity,
		Architecture:                    "arm64",
		RuntimeUEFIValidation:           true,
		RuntimeUEFILoaderPath:           loaderPath,
		RuntimeUEFILoaderSHA256:         strings.Repeat("0", 64),
		RuntimeUEFILoaderSourceCommit:   "6195f2ef754c2ad390bda6590628708f410d55f6",
		RuntimeUEFILoaderProvenance:     "test provenance",
		RuntimeUEFIUnsignedAcknowledged: true,
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "loader SHA-256") {
		t.Fatalf("wrong loader digest error = %v", err)
	}
	after, readErr := os.ReadFile(targetPath)
	if readErr != nil || !bytes.Equal(before, after) {
		t.Fatalf("target changed before loader refusal: err=%v", readErr)
	}
}

func TestCreatePersistentRejectsRuntimeValidationOnNonARM64(t *testing.T) {
	isoPath := filepath.Join(t.TempDir(), "ubuntu.iso")
	writeLinuxTestFile(t, isoPath, "pinned-image")
	_, identity, err := sourcefile.Inspect(isoPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = CreatePersistent(context.Background(), isoPath, filepath.Join(t.TempDir(), "target.img"), PersistentCreateOptions{
		ExpectedSource:                  identity,
		Architecture:                    "amd64",
		RuntimeUEFIValidation:           true,
		RuntimeUEFIUnsignedAcknowledged: true,
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "requires ARM64") {
		t.Fatalf("non-ARM64 runtime validation error = %v", err)
	}
}
