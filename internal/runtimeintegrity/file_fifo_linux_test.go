//go:build linux

package runtimeintegrity

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestGenerateRejectsFIFOReplacementWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	relative := "payload"
	path := filepath.Join(root, relative)
	writeFile(t, root, relative, "data")
	done := make(chan error, 1)
	go func() {
		var setupErr error
		_, err := generate(context.Background(), root, Options{}, func(stage, candidate string) {
			if stage != "file-before-open" || candidate != relative || setupErr != nil {
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
		if err == nil || (!strings.Contains(err.Error(), "regular file") && !strings.Contains(err.Error(), "changed between enumeration")) {
			t.Fatalf("runtime file FIFO error = %v", err)
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
		t.Fatal("opening a FIFO runtime file blocked")
	}
}
