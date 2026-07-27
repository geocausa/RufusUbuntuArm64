//go:build linux

package persistence

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func testPersistenceDetection(base string) Detection {
	return Detection{
		Family:          FamilyUbuntuCasper,
		BootParameter:   "persistent",
		Filesystem:      "ext4",
		FilesystemLabel: "casper-rw",
		PatchPaths:      []string{base},
	}
}

func TestPatchOneBootFilePatchesRegularConfig(t *testing.T) {
	root := t.TempDir()
	base := "grub.cfg"
	path := filepath.Join(root, base)
	if err := os.WriteFile(path, []byte("linux /casper/vmlinuz boot=casper ---\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	parent, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	if err := patchOneBootFile(parent, base, base, testPersistenceDetection(base)); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "boot=casper persistent ---") {
		t.Fatalf("patched boot configuration = %q", content)
	}
}

func TestPatchOneBootFileRejectsFIFOWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	base := "grub.cfg"
	path := filepath.Join(root, base)
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	parent, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	done := make(chan error, 1)
	go func() {
		done <- patchOneBootFile(parent, base, base, testPersistenceDetection(base))
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "bounded regular file") {
			t.Fatalf("FIFO boot configuration error = %v", err)
		}
	case <-time.After(time.Second):
		writer, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			_ = writer.Close()
		}
		select {
		case <-done:
		case <-time.After(time.Second):
		}
		t.Fatal("opening a FIFO boot configuration blocked")
	}
}
