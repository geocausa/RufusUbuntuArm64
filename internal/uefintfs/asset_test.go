//go:build linux

package uefintfs

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestPinnedImageProvesCompleteArchitectureManifest(t *testing.T) {
	path := filepath.Join("..", "..", "vendor", "uefi-ntfs", "uefi-ntfs.img")
	asset, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	report, err := asset.ArchitectureReport()
	if err != nil {
		t.Fatal(err)
	}
	if report.Schema != 1 || report.Filesystem != "fat12" || report.VolumeLabel != "RUFUS_BOOT" ||
		report.ImageSize != ImageSize || report.ImageSHA256 != ImageSHA256 || report.ManifestSHA256 != ArchitectureManifestSHA256 {
		t.Fatalf("unexpected report envelope: %#v", report)
	}
	names := make([]string, 0, len(report.Architectures))
	for _, architecture := range report.Architectures {
		names = append(names, architecture.Name)
		for _, file := range []FileEvidence{architecture.Fallback, architecture.NTFS, architecture.ExFAT} {
			if file.Path == "" || file.Size == 0 || len(file.SHA256) != 64 || file.Machine == 0 || file.Subsystem == 0 {
				t.Fatalf("incomplete %s evidence: %#v", architecture.Name, file)
			}
		}
	}
	if want := []string{"arm", "arm64", "ia32", "riscv64", "x64"}; !slices.Equal(names, want) {
		t.Fatalf("architectures=%v want=%v", names, want)
	}
	if report.Architectures[3].Fallback.Path != "EFI/Boot/bootriscv64.efi" ||
		report.Architectures[3].Fallback.Machine != 0x5064 {
		t.Fatalf("RISC-V evidence=%#v", report.Architectures[3])
	}
}

func TestPinnedArchitectureParserRejectsMissingRISCVFallback(t *testing.T) {
	path := filepath.Join("..", "..", "vendor", "uefi-ntfs", "uefi-ntfs.img")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	shortName := []byte("BOOTRI~1EFI")
	offset := bytes.Index(data, shortName)
	if offset < 0 {
		t.Fatal("RISC-V short directory entry not found in fixture")
	}
	data[offset] = 0xe5
	if _, err := inspectPinnedArchitectureManifest(bytes.NewReader(data), ImageSHA256); err == nil ||
		!strings.Contains(err.Error(), "expected exactly") {
		t.Fatalf("missing RISC-V fallback error=%v", err)
	}
}

func TestCustomTestAssetHasNoPinnedArchitectureClaim(t *testing.T) {
	asset, _ := makeTestAsset(t)
	if _, err := asset.ArchitectureReport(); err == nil {
		t.Fatal("custom test asset unexpectedly received pinned architecture evidence")
	}
}

func TestVerifyAssetRequiresExactSizeHashAndRegularFile(t *testing.T) {
	asset, data := makeTestAsset(t)
	if asset.Size() != ImageSize {
		t.Fatalf("asset size = %d, want %d", asset.Size(), ImageSize)
	}
	if asset.SHA256() != fmt.Sprintf("%x", sha256.Sum256(data)) {
		t.Fatalf("asset digest = %s", asset.SHA256())
	}

	if _, err := verifyAsset(asset.Path(), ImageSize-1, asset.SHA256()); err == nil || !strings.Contains(err.Error(), "expected exactly") {
		t.Fatalf("wrong-size verification error = %v", err)
	}
	if _, err := verifyAsset(asset.Path(), ImageSize, strings.Repeat("0", sha256.Size*2)); err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("wrong-digest verification error = %v", err)
	}

	symlink := filepath.Join(t.TempDir(), "uefi-ntfs-link.img")
	if err := os.Symlink(asset.Path(), symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyAsset(symlink, ImageSize, asset.SHA256()); err == nil {
		t.Fatal("symlinked asset was accepted")
	}
}

func TestLocateTreatsEnvironmentOverrideAsAuthoritative(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.img")
	if err := os.WriteFile(bad, []byte("not the pinned image"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(ImageEnv, bad)
	if _, err := Locate(); err == nil || !strings.Contains(err.Error(), ImageEnv) {
		t.Fatalf("Locate() error = %v", err)
	}
}

func TestWriteAndVerifyPublishesExactPartitionExtent(t *testing.T) {
	asset, data := makeTestAsset(t)
	targetPath := filepath.Join(t.TempDir(), "disk.img")
	target, err := os.OpenFile(targetPath, os.O_CREATE|os.O_RDWR|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if err := target.Truncate(4 * int64(ImageSize)); err != nil {
		t.Fatal(err)
	}
	partition := Partition{StartBytes: 2 * ImageSize, SizeBytes: ImageSize}
	if err := WriteAndVerify(target, asset, partition); err != nil {
		t.Fatal(err)
	}
	actual := make([]byte, ImageSize)
	if _, err := target.ReadAt(actual, int64(partition.StartBytes)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, data) {
		t.Fatal("published partition does not match the admitted asset")
	}

	before := make([]byte, partition.StartBytes)
	if _, err := target.ReadAt(before, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, make([]byte, len(before))) {
		t.Fatal("bytes before the UEFI:NTFS partition were changed")
	}
}

func TestWriteAndVerifyRevalidatesAssetBeforeMutation(t *testing.T) {
	asset, _ := makeTestAsset(t)
	if err := os.WriteFile(asset.Path(), make([]byte, ImageSize), 0o600); err != nil {
		t.Fatal(err)
	}
	target, err := os.CreateTemp(t.TempDir(), "disk-*.img")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if err := target.Truncate(2 * int64(ImageSize)); err != nil {
		t.Fatal(err)
	}
	if err := WriteAndVerify(target, asset, Partition{StartBytes: ImageSize, SizeBytes: ImageSize}); err == nil || !strings.Contains(err.Error(), "reverify") {
		t.Fatalf("WriteAndVerify() error = %v", err)
	}

	contents, err := os.ReadFile(target.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(contents, make([]byte, len(contents))) {
		t.Fatal("target changed after asset revalidation failure")
	}
}

func TestVerifyPartitionPathChecksRegularFiles(t *testing.T) {
	asset, data := makeTestAsset(t)
	partition := filepath.Join(t.TempDir(), "partition.img")
	if err := os.WriteFile(partition, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPartitionPath(partition, asset); err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 0xff
	if err := os.WriteFile(partition, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPartitionPath(partition, asset); err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("VerifyPartitionPath() error = %v", err)
	}
}

func makeTestAsset(t *testing.T) (Asset, []byte) {
	t.Helper()
	data := make([]byte, ImageSize)
	for index := range data {
		data[index] = byte((index*131 + 17) & 0xff)
	}
	path := filepath.Join(t.TempDir(), "uefi-ntfs.img")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	asset, err := verifyAsset(path, ImageSize, fmt.Sprintf("%x", digest))
	if err != nil {
		t.Fatal(err)
	}
	return asset, data
}

func TestPinnedArchitectureParserRejectsCorruptLongFilenameChecksum(t *testing.T) {
	data := readPinnedUEFINTFSImage(t)
	shortName := []byte("BOOTRI~1EFI")
	offset := bytes.Index(data, shortName)
	if offset < 32 {
		t.Fatal("RISC-V short directory entry or preceding LFN was not found")
	}
	lfn := data[offset-32 : offset]
	if lfn[11] != 0x0f {
		t.Fatalf("preceding entry is not LFN: attribute=0x%02x", lfn[11])
	}
	lfn[13] ^= 0xff
	if _, err := inspectPinnedArchitectureManifest(bytes.NewReader(data), ImageSHA256); err == nil ||
		!strings.Contains(err.Error(), "long-filename") {
		t.Fatalf("corrupt LFN checksum error=%v", err)
	}
}

func TestPinnedArchitectureParserRejectsClusterLoop(t *testing.T) {
	data := readPinnedUEFINTFSImage(t)
	filesystem, err := parseFAT12Image(data)
	if err != nil {
		t.Fatal(err)
	}
	shortName := []byte("NTFS_R~1EFI")
	offset := bytes.Index(data, shortName)
	if offset < 0 {
		t.Fatal("RISC-V NTFS short entry not found")
	}
	cluster := binary.LittleEndian.Uint16(data[offset+26 : offset+28])
	setFAT12Entry(t, filesystem.fat, cluster, cluster)
	if _, err := inspectPinnedArchitectureManifest(bytes.NewReader(data), ImageSHA256); err == nil ||
		!strings.Contains(err.Error(), "loop") {
		t.Fatalf("cluster-loop error=%v", err)
	}
}

func TestPinnedArchitectureParserRejectsVolumeIdentityMutation(t *testing.T) {
	data := readPinnedUEFINTFSImage(t)
	copy(data[43:54], []byte("OTHER_BOOT "))
	if _, err := inspectPinnedArchitectureManifest(bytes.NewReader(data), ImageSHA256); err == nil ||
		!strings.Contains(err.Error(), "RUFUS_BOOT/FAT12") {
		t.Fatalf("volume-identity error=%v", err)
	}
}

func readPinnedUEFINTFSImage(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "vendor", "uefi-ntfs", "uefi-ntfs.img")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func setFAT12Entry(t *testing.T, fat []byte, cluster, value uint16) {
	t.Helper()
	offset := int(cluster) + int(cluster)/2
	if offset+2 > len(fat) {
		t.Fatalf("FAT12 entry %d exceeds FAT", cluster)
	}
	current := binary.LittleEndian.Uint16(fat[offset : offset+2])
	if cluster&1 == 0 {
		current = (current & 0xf000) | (value & 0x0fff)
	} else {
		current = (current & 0x000f) | ((value & 0x0fff) << 4)
	}
	binary.LittleEndian.PutUint16(fat[offset:offset+2], current)
}
