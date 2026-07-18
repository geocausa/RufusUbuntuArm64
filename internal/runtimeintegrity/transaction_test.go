//go:build linux

package runtimeintegrity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
)

func minimalARM64EFI(marker byte) []byte {
	data := make([]byte, 512)
	data[0], data[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(data[0x3c:0x40], 0x80)
	copy(data[0x80:0x84], []byte{'P', 'E', 0, 0})
	coff := 0x84
	binary.LittleEndian.PutUint16(data[coff:coff+2], 0xaa64)
	binary.LittleEndian.PutUint16(data[coff+2:coff+4], 0)
	binary.LittleEndian.PutUint16(data[coff+16:coff+18], 0xf0)
	optional := coff + 20
	binary.LittleEndian.PutUint16(data[optional:optional+2], 0x20b)
	binary.LittleEndian.PutUint16(data[optional+68:optional+70], 10)
	data[len(data)-1] = marker
	return data
}

type treeSnapshotEntry struct {
	Mode os.FileMode
	Data []byte
}

func snapshotTree(t *testing.T, root string) map[string]treeSnapshotEntry {
	t.Helper()
	result := make(map[string]treeSnapshotEntry)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		item := treeSnapshotEntry{Mode: info.Mode()}
		if info.Mode().IsRegular() {
			item.Data, err = os.ReadFile(path)
			if err != nil {
				return err
			}
		} else if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			item.Data = []byte(target)
		}
		result[filepath.ToSlash(relative)] = item
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func requireSameTree(t *testing.T, expected, actual map[string]treeSnapshotEntry) {
	t.Helper()
	if len(expected) != len(actual) {
		t.Fatalf("tree entry count changed: expected %d, got %d\nexpected=%v\nactual=%v", len(expected), len(actual), sortedSnapshotKeys(expected), sortedSnapshotKeys(actual))
	}
	for path, wanted := range expected {
		got, exists := actual[path]
		if !exists {
			t.Fatalf("tree path %s disappeared", path)
		}
		if wanted.Mode != got.Mode || !bytes.Equal(wanted.Data, got.Data) {
			t.Fatalf("tree path %s changed", path)
		}
	}
}

func sortedSnapshotKeys(values map[string]treeSnapshotEntry) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func createTransactionTree(t *testing.T) (string, []byte, []byte, LoaderAsset) {
	t.Helper()
	root := t.TempDir()
	boot := filepath.Join(root, "EFI", "BOOT")
	if err := os.MkdirAll(boot, 0o755); err != nil {
		t.Fatal(err)
	}
	original := minimalARM64EFI(0x11)
	wrapper := minimalARM64EFI(0x22)
	if err := os.WriteFile(filepath.Join(boot, arm64FallbackName), original, 0o744); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "boot", "grub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "boot", "grub", "grub.cfg"), []byte("set default=0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(wrapper)
	asset := LoaderAsset{
		Data:                 wrapper,
		ExpectedSHA256:       fmt.Sprintf("%x", digest[:]),
		SourceCommit:         "6195f2ef754c2ad390bda6590628708f410d55f6",
		Provenance:           "test provenance",
		SecureBootCompatible: false,
	}
	return root, original, wrapper, asset
}

func TestInstallAndRemoveARM64RuntimeIntegrity(t *testing.T) {
	root, original, wrapper, asset := createTransactionTree(t)
	installed, err := InstallARM64(context.Background(), root, asset, TransactionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !installed.Verification.Valid || installed.Record.WrapperSHA256 != asset.ExpectedSHA256 || installed.Record.WrapperSecureBootCompatible {
		t.Fatalf("unexpected installation result: %#v", installed)
	}
	fallback, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(ARM64FallbackPath)))
	if err != nil || !bytes.Equal(fallback, wrapper) {
		t.Fatalf("active wrapper mismatch: err=%v", err)
	}
	backup, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(ARM64OriginalPath)))
	if err != nil || !bytes.Equal(backup, original) {
		t.Fatalf("original backup mismatch: err=%v", err)
	}
	manifestData, err := os.ReadFile(filepath.Join(root, ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	record, canonical, err := parseInstallationRecord(manifestData)
	if err != nil {
		t.Fatal(err)
	}
	if record.OriginalSHA256 != sha256Hex(original) || record.ManifestRecordsSHA256 != sha256Hex(canonical) {
		t.Fatalf("unexpected embedded record: %#v", record)
	}
	verification, err := Verify(context.Background(), root, Options{})
	if err != nil || !verification.Valid {
		t.Fatalf("verify installed tree: result=%#v err=%v", verification, err)
	}
	removed, err := RemoveARM64(context.Background(), root, TransactionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if removed.RestoredSHA256 != sha256Hex(original) || removed.RemovedManifestSHA256 != sha256Hex(manifestData) {
		t.Fatalf("unexpected removal result: %#v", removed)
	}
	restored, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(ARM64FallbackPath)))
	if err != nil || !bytes.Equal(restored, original) {
		t.Fatalf("restored fallback mismatch: err=%v", err)
	}
	for _, path := range []string{ARM64OriginalPath, ManifestName} {
		if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(path))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s remains after removal: %v", path, err)
		}
	}
}

func TestInstallRollbackAtEveryBoundary(t *testing.T) {
	stages := []string{"validated", "backup-published", "wrapper-replaced", "manifest-generated", "manifest-published", "verified"}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			root, _, _, asset := createTransactionTree(t)
			before := snapshotTree(t, root)
			_, err := installARM64(context.Background(), root, asset, TransactionOptions{hook: func(current string) error {
				if current == stage {
					return errors.New("stop")
				}
				return nil
			}})
			if err == nil || !strings.Contains(err.Error(), stage) {
				t.Fatalf("expected injected failure at %s, got %v", stage, err)
			}
			requireSameTree(t, before, snapshotTree(t, root))
		})
	}
}

func TestRemovalRollbackAtEveryBoundary(t *testing.T) {
	stages := []string{"remove-original-restored", "remove-backup-removed", "remove-manifest-removed", "remove-verified"}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			root, _, _, asset := createTransactionTree(t)
			if _, err := InstallARM64(context.Background(), root, asset, TransactionOptions{}); err != nil {
				t.Fatal(err)
			}
			before := snapshotTree(t, root)
			_, err := RemoveARM64(context.Background(), root, TransactionOptions{hook: func(current string) error {
				if current == stage {
					return errors.New("stop")
				}
				return nil
			}})
			if err == nil || !strings.Contains(err.Error(), stage) {
				t.Fatalf("expected injected failure at %s, got %v", stage, err)
			}
			requireSameTree(t, before, snapshotTree(t, root))
		})
	}
}

func TestRemovalRefusesTamperedInstalledState(t *testing.T) {
	root, _, _, asset := createTransactionTree(t)
	if _, err := InstallARM64(context.Background(), root, asset, TransactionOptions{}); err != nil {
		t.Fatal(err)
	}
	wrapperPath := filepath.Join(root, filepath.FromSlash(ARM64FallbackPath))
	if err := os.WriteFile(wrapperPath, minimalARM64EFI(0x44), 0o644); err != nil {
		t.Fatal(err)
	}
	before := snapshotTree(t, root)
	if _, err := RemoveARM64(context.Background(), root, TransactionOptions{}); err == nil {
		t.Fatal("tampered wrapper was accepted")
	}
	requireSameTree(t, before, snapshotTree(t, root))
}

func TestInstallRefusesWrongAssetAmbiguousStateAndSymlink(t *testing.T) {
	root, _, _, asset := createTransactionTree(t)
	bad := asset
	bad.ExpectedSHA256 = strings.Repeat("0", 64)
	if _, err := InstallARM64(context.Background(), root, bad, TransactionOptions{}); err == nil {
		t.Fatal("wrong digest accepted")
	}
	foreign := asset
	foreign.Data = append([]byte(nil), asset.Data...)
	binary.LittleEndian.PutUint16(foreign.Data[0x84:0x86], 0x8664)
	foreign.ExpectedSHA256 = sha256Hex(foreign.Data)
	if _, err := InstallARM64(context.Background(), root, foreign, TransactionOptions{}); err == nil {
		t.Fatal("foreign architecture accepted")
	}
	if err := os.WriteFile(filepath.Join(root, "EFI", "BOOT", "BootAa64_Original.Efi"), []byte("collision"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallARM64(context.Background(), root, asset, TransactionOptions{}); err == nil {
		t.Fatal("case collision accepted")
	}
	if err := os.Remove(filepath.Join(root, "EFI", "BOOT", "BootAa64_Original.Efi")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", filepath.Join(root, "boot", "grub", "linked")); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallARM64(context.Background(), root, asset, TransactionOptions{}); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("symlink tree accepted: %v", err)
	}
}

func TestInstallRefusesConcurrentRootLock(t *testing.T) {
	root, _, _, asset := createTransactionTree(t)
	locked, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer locked.Close()
	if err := syscall.Flock(int(locked.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(locked.Fd()), syscall.LOCK_UN)
	if _, err := InstallARM64(context.Background(), root, asset, TransactionOptions{}); err == nil || !strings.Contains(err.Error(), "lock media root") {
		t.Fatalf("concurrent lock accepted: %v", err)
	}
}
