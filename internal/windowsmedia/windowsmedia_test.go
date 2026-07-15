//go:build linux

package windowsmedia

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFindRelativeCaseInsensitive(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "SOURCES")
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	expected := filepath.Join(path, "BOOT.WIM")
	if err := os.WriteFile(expected, []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, ok := findRelativeCaseInsensitive(root, "sources/boot.wim")
	if !ok || got != expected {
		t.Fatalf("got %q, %v; want %q", got, ok, expected)
	}
}

func TestInspectMountedISOARM64(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "sources", "boot.wim"), []byte("boot"))
	writeTestFile(t, filepath.Join(root, "sources", "install.wim"), []byte("install"))
	writeTestFile(t, filepath.Join(root, "efi", "boot", "bootaa64.efi"), []byte("efi"))
	writeTestFile(t, filepath.Join(root, "setup.exe"), []byte("setup"))

	plan, err := inspectMountedISO(root)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Architecture != "ARM64 UEFI" {
		t.Fatalf("architecture=%q", plan.Architecture)
	}
	if plan.NeedsSplit {
		t.Fatal("small install.wim unexpectedly needs splitting")
	}
	if plan.CopyBytes == 0 || plan.RequiredBytes <= plan.CopyBytes {
		t.Fatalf("invalid size plan: copy=%d required=%d", plan.CopyBytes, plan.RequiredBytes)
	}
}

func TestInspectMountedISORejectsOtherOversizedFile(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "sources", "boot.wim"), []byte("boot"))
	writeTestFile(t, filepath.Join(root, "efi", "boot", "bootaa64.efi"), []byte("efi"))
	large := filepath.Join(root, "other.bin")
	if err := os.WriteFile(large, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(large, int64(fat32MaxFileSize+1)); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectMountedISO(root); err == nil {
		t.Fatal("expected oversized-file error")
	}
}

func TestCopyTreeExcludesInstallImage(t *testing.T) {
	source := t.TempDir()
	destination := t.TempDir()
	install := filepath.Join(source, "sources", "install.wim")
	writeTestFile(t, install, []byte("do not copy"))
	writeTestFile(t, filepath.Join(source, "sources", "boot.wim"), []byte("copy me"))
	writeTestFile(t, filepath.Join(source, "efi", "boot", "bootaa64.efi"), []byte("efi"))

	var copied uint64
	if err := copyTree(context.Background(), source, destination, install, func(delta uint64) { copied += delta }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(destination, "sources", "install.wim")); !os.IsNotExist(err) {
		t.Fatalf("excluded file exists or unexpected error: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(destination, "sources", "boot.wim"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "copy me" || copied == 0 {
		t.Fatalf("copy failed: content=%q copied=%d", content, copied)
	}
}

func TestCompareFiles(t *testing.T) {
	left := filepath.Join(t.TempDir(), "left")
	right := filepath.Join(t.TempDir(), "right")
	writeTestFile(t, left, []byte("same"))
	writeTestFile(t, right, []byte("same"))
	if _, err := compareFiles(left, right); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(right, []byte("diff"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := compareFiles(left, right); err == nil {
		t.Fatal("expected mismatch")
	}
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
