//go:build linux

package persistence

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func writeDetectionFile(t *testing.T, root, relative, content string) string {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeUbuntuDetectionTree(t *testing.T, root string) {
	t.Helper()
	writeDetectionFile(t, root, ".disk/info", "Ubuntu 24.04 LTS")
	writeDetectionFile(t, root, "casper/vmlinuz", "kernel")
	writeDetectionFile(t, root, "casper/initrd", "initrd")
	writeDetectionFile(t, root, "casper/install-sources.yaml", "version: 1")
	writeDetectionFile(t, root, "boot/grub/grub.cfg", "linux /casper/vmlinuz boot=casper ---\n")
}

func TestDetectPathAcceptsRegularUbuntuTree(t *testing.T) {
	root := t.TempDir()
	writeUbuntuDetectionTree(t, root)
	detection, err := DetectPath(root)
	if err != nil {
		t.Fatal(err)
	}
	if !detection.Ready() || detection.Family != FamilyUbuntuCasper || len(detection.PatchPaths) != 1 {
		t.Fatalf("persistence detection = %#v", detection)
	}
}

func TestDetectUpgradesOSDirFS(t *testing.T) {
	root := t.TempDir()
	writeUbuntuDetectionTree(t, root)
	detection, err := Detect(os.DirFS(root))
	if err != nil {
		t.Fatal(err)
	}
	if !detection.Ready() || detection.Family != FamilyUbuntuCasper {
		t.Fatalf("os.DirFS persistence detection = %#v", detection)
	}
}

func TestDetectPathRejectsSymlinkComponent(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writeUbuntuDetectionTree(t, root)
	if err := os.RemoveAll(filepath.Join(root, "boot")); err != nil {
		t.Fatal(err)
	}
	writeDetectionFile(t, outside, "grub/grub.cfg", "linux /casper/vmlinuz boot=casper ---\n")
	if err := os.Symlink(outside, filepath.Join(root, "boot")); err != nil {
		t.Fatal(err)
	}
	_, err := DetectPath(root)
	if err == nil {
		t.Fatal("symlinked boot directory was accepted")
	}
}

func TestDetectPathRejectsFIFOWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	writeUbuntuDetectionTree(t, root)
	config := filepath.Join(root, "boot", "grub", "grub.cfg")
	if err := os.Remove(config); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(config, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := DetectPath(root)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("FIFO detection error = %v", err)
		}
	case <-time.After(time.Second):
		writer, err := os.OpenFile(config, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			_ = writer.Close()
		}
		select {
		case <-done:
		case <-time.After(time.Second):
		}
		t.Fatal("persistence detection blocked on a FIFO")
	}
}

func TestDetectOSDirFSRejectsFIFOWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	writeUbuntuDetectionTree(t, root)
	config := filepath.Join(root, "boot", "grub", "grub.cfg")
	if err := os.Remove(config); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(config, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := Detect(os.DirFS(root))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("os.DirFS FIFO detection error = %v", err)
		}
	case <-time.After(time.Second):
		writer, err := os.OpenFile(config, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			_ = writer.Close()
		}
		select {
		case <-done:
		case <-time.After(time.Second):
		}
		t.Fatal("os.DirFS persistence detection blocked on a FIFO")
	}
}

func TestDescriptorFSRejectsEscape(t *testing.T) {
	root := t.TempDir()
	fd, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	_, err = (descriptorFS{rootFD: fd}).Open("../outside")
	if err == nil || !errors.Is(err, fs.ErrInvalid) {
		t.Fatalf("escape error = %v", err)
	}
}
