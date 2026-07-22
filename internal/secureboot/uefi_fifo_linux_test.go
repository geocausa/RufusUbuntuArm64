//go:build linux

package secureboot

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestOpenUEFIEntryAcceptsRegularFile(t *testing.T) {
	root := t.TempDir()
	path := writeSyntheticEFI(t, root, "BOOTAA64.EFI", syntheticUEFIPE(imageFileMachineARM64, imageSubsystemEFIApp))
	parent, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	file, err := openUEFIEntry(parent, filepath.Base(path), info, false)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if opened, err := file.Stat(); err != nil || !opened.Mode().IsRegular() {
		t.Fatalf("opened UEFI entry is not regular: info=%v err=%v", opened, err)
	}
}

func TestOpenUEFIEntryAcceptsDirectory(t *testing.T) {
	root := t.TempDir()
	childPath := filepath.Join(root, "EFI")
	if err := os.Mkdir(childPath, 0o755); err != nil {
		t.Fatal(err)
	}
	parent, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	info, err := os.Lstat(childPath)
	if err != nil {
		t.Fatal(err)
	}
	child, err := openUEFIEntry(parent, filepath.Base(childPath), info, true)
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	if opened, err := child.Stat(); err != nil || !opened.IsDir() {
		t.Fatalf("opened UEFI entry is not a directory: info=%v err=%v", opened, err)
	}
}

func TestValidateUEFIMediaRejectsFIFOReplacementWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	relative := "EFI/BOOT/BOOTAA64.EFI"
	path := writeSyntheticEFI(t, root, relative, syntheticUEFIPE(imageFileMachineARM64, imageSubsystemEFIApp))
	done := make(chan error, 1)
	go func() {
		var setupErr error
		_, err := validateUEFIMedia(context.Background(), root, UEFIValidationOptions{Architecture: "arm64"}, func(stage, candidate string) {
			if stage != "entry-before-open" || candidate != relative || setupErr != nil {
				return
			}
			if removeErr := os.Remove(path); removeErr != nil {
				setupErr = removeErr
				return
			}
			setupErr = syscall.Mkfifo(path, 0o600)
		})
		if setupErr != nil {
			done <- setupErr
			return
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || (!strings.Contains(err.Error(), "changed during validation") && !strings.Contains(err.Error(), "regular file")) {
			t.Fatalf("FIFO replacement error = %v", err)
		}
	case <-time.After(time.Second):
		writer, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			_ = writer.Close()
		}
		select {
		case <-done:
		case <-time.After(time.Second):
		}
		t.Fatal("opening a FIFO UEFI executable blocked")
	}
}
