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

func TestValidateUEFIMediaRejectsFIFOReplacementWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	relative := "EFI/BOOT/BOOTAA64.EFI"
	path := writeSyntheticEFI(t, root, relative, syntheticUEFIPE(imageFileMachineARM64, imageSubsystemEFIApp))
	done := make(chan error, 1)
	go func() {
		_, err := validateUEFIMedia(context.Background(), root, UEFIValidationOptions{Architecture: "arm64"}, func(stage, candidate string) {
			if stage != "entry-before-open" || candidate != relative {
				return
			}
			if err := os.Remove(path); err != nil {
				done <- err
				return
			}
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				done <- err
			}
		})
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
