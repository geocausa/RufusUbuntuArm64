//go:build linux

package uefintfs

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
