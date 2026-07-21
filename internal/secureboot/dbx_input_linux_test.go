//go:build linux

package secureboot

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestStableDBXReaderRejectsSymlinkAndFIFO(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.dbx")
	if err := os.WriteFile(target, []byte("regular DBX bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "linked.dbx")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readStableDBXFile(link, 1024); err == nil {
		t.Fatal("final-component DBX symlink accepted")
	}
	fifo := filepath.Join(directory, "dbx.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readStableDBXFile(fifo, 1024); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("FIFO error=%v", err)
	}
}

func TestStableDBXReaderRejectsInPlaceMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "changing.dbx")
	original := []byte("first DBX snapshot")
	replacement := []byte("other DBX snapshot")
	if len(original) != len(replacement) {
		t.Fatal("test payloads must be the same length")
	}
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := readStableDBXFileWithHook(path, 1024, func(_ *os.File) error {
		return os.WriteFile(path, replacement, 0o600)
	})
	if err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("mutation error=%v", err)
	}
}

func TestStableDBXReaderKeepsOpenedSnapshotAcrossRename(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "selected.dbx")
	replacement := filepath.Join(directory, "replacement.dbx")
	originalBytes := []byte("opened descriptor bytes")
	if err := os.WriteFile(path, originalBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(replacement, []byte("replacement path bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := readStableDBXFileWithHook(path, 1024, func(_ *os.File) error {
		return os.Rename(replacement, path)
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(originalBytes) {
		t.Fatalf("read bytes %q", data)
	}
}
