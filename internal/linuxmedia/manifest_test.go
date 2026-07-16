//go:build linux

package linuxmedia

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectAndCopyVerifiedTree(t *testing.T) {
	source := t.TempDir()
	writeMediaFile(t, source, "EFI/BOOT/BOOTAA64.EFI", "arm64 bootloader")
	writeMediaFile(t, source, "casper/vmlinuz", "kernel")
	if err := os.Symlink("vmlinuz", filepath.Join(source, "casper", "vmlinuz-current")); err != nil {
		t.Fatal(err)
	}
	manifest, err := Inspect(context.Background(), source, Options{Architecture: "arm64", RequireUEFI: true, RequireFAT32: true})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.UEFIBootPath == "" || manifest.Files != 3 || manifest.DereferencedSymlinks != 1 {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
	destination := t.TempDir()
	var last CopyEvent
	if err := CopyAndVerify(context.Background(), manifest, destination, CopyOptions{Event: func(event CopyEvent) { last = event }}); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(destination, "casper", "vmlinuz-current"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "kernel" || last.Done != manifest.TotalBytes || last.Total != manifest.TotalBytes {
		t.Fatalf("copy result content=%q event=%+v manifest=%+v", content, last, manifest)
	}
}

func TestInspectRejectsEscapingAndDirectorySymlinks(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	writeMediaFile(t, source, "efi/boot/bootaa64.efi", "boot")
	if err := os.Symlink(outside, filepath.Join(source, "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(context.Background(), source, Options{}); err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("escaping symlink error = %v", err)
	}

	source = t.TempDir()
	writeMediaFile(t, source, "efi/boot/bootaa64.efi", "boot")
	if err := os.Mkdir(filepath.Join(source, "real-dir"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real-dir", filepath.Join(source, "dir-link")); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(context.Background(), source, Options{}); err == nil || !strings.Contains(err.Error(), "regular files") {
		t.Fatalf("directory symlink error = %v", err)
	}
}

func TestInspectRejectsFAT32CollisionsAndNames(t *testing.T) {
	source := t.TempDir()
	writeMediaFile(t, source, "efi/boot/bootaa64.efi", "boot")
	writeMediaFile(t, source, "Readme", "one")
	writeMediaFile(t, source, "README", "two")
	if _, err := Inspect(context.Background(), source, Options{RequireFAT32: true}); err == nil || !strings.Contains(err.Error(), "collision") {
		t.Fatalf("collision error = %v", err)
	}

	source = t.TempDir()
	writeMediaFile(t, source, "efi/boot/bootaa64.efi", "boot")
	writeMediaFile(t, source, "CON.txt", "bad")
	if _, err := Inspect(context.Background(), source, Options{RequireFAT32: true}); err == nil || !strings.Contains(err.Error(), "reserved DOS") {
		t.Fatalf("reserved-name error = %v", err)
	}
}

func TestInspectRejectsOversizedFAT32File(t *testing.T) {
	source := t.TempDir()
	writeMediaFile(t, source, "efi/boot/bootaa64.efi", "boot")
	path := filepath.Join(source, "huge.img")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(int64(fat32MaxFileSize + 1)); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(context.Background(), source, Options{RequireFAT32: true, MaxBytes: fat32MaxFileSize + 1024}); err == nil || !strings.Contains(err.Error(), "single-file limit") {
		t.Fatalf("large-file error = %v", err)
	}
}

func TestCopyRefusesChangedSource(t *testing.T) {
	source := t.TempDir()
	writeMediaFile(t, source, "efi/boot/bootaa64.efi", "boot")
	writeMediaFile(t, source, "payload", "original")
	manifest, err := Inspect(context.Background(), source, Options{RequireUEFI: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "payload"), []byte("modified"), 0o644); err != nil {
		t.Fatal(err)
	}
	err = CopyAndVerify(context.Background(), manifest, t.TempDir(), CopyOptions{})
	if err == nil || !strings.Contains(err.Error(), "manifest") {
		t.Fatalf("changed-source error = %v", err)
	}
}

func TestCopyEntryCancellationRemovesTemporaryFile(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(source, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := Inspect(context.Background(), filepath.Dir(source), Options{})
	if err != nil {
		t.Fatal(err)
	}
	var entry Entry
	for _, candidate := range manifest.Entries {
		if candidate.SHA256 != "" {
			entry = candidate
			break
		}
	}
	destinationRoot := t.TempDir()
	destination := filepath.Join(destinationRoot, "output")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := copyEntry(ctx, entry, destination); err == nil {
		t.Fatal("expected cancellation")
	}
	entries, err := os.ReadDir(destinationRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("temporary files remain: %v", entries)
	}
}

func TestSafeMkdirAllRefusesSymlinkComponent(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := safeMkdirAll(root, filepath.Join("link", "child"), 0o755); err == nil || !strings.Contains(err.Error(), "real directory") {
		t.Fatalf("symlink component error = %v", err)
	}
}

func writeMediaFile(t *testing.T, root, relative, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
