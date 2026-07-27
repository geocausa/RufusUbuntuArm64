//go:build linux

package linuxmedia

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func copyTestEntry(path string, data []byte) Entry {
	digest := sha256.Sum256(data)
	return Entry{
		Path:       filepath.Base(path),
		SourcePath: path,
		Size:       uint64(len(data)),
		Mode:       0o600,
		SHA256:     hex.EncodeToString(digest[:]),
	}
}

func TestCopyEntryWithOpenAcceptsRegularFile(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source")
	destination := filepath.Join(directory, "destination")
	data := []byte("stable payload")
	if err := os.WriteFile(source, data, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := copyEntryWithOpen(context.Background(), copyTestEntry(source, data), destination, openLinuxMediaNoFollow); err != nil {
		t.Fatal(err)
	}
	copied, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(copied) != string(data) {
		t.Fatalf("copied data = %q, want %q", copied, data)
	}
}

func TestCopyEntryWithOpenRejectsReplacement(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source")
	replacement := filepath.Join(directory, "replacement")
	destination := filepath.Join(directory, "destination")
	data := []byte("first")
	if err := os.WriteFile(source, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(replacement, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := copyEntryWithOpen(context.Background(), copyTestEntry(source, data), destination, func(name string) (*os.File, error) {
		if err := os.Rename(replacement, name); err != nil {
			return nil, err
		}
		return openLinuxMediaNoFollow(name)
	})
	if err == nil || !strings.Contains(err.Error(), "identity no longer matches") {
		t.Fatalf("replacement error = %v", err)
	}
}

func TestCopyEntryWithOpenRejectsFIFOWithoutBlocking(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source")
	destination := filepath.Join(directory, "destination")
	data := []byte("first")
	if err := os.WriteFile(source, data, 0o600); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		done <- copyEntryWithOpen(context.Background(), copyTestEntry(source, data), destination, func(name string) (*os.File, error) {
			if err := os.Remove(name); err != nil {
				return nil, err
			}
			if err := syscall.Mkfifo(name, 0o600); err != nil {
				return nil, err
			}
			return openLinuxMediaNoFollow(name)
		})
	}()

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "identity no longer matches") {
			t.Fatalf("FIFO error = %v", err)
		}
	case <-time.After(time.Second):
		writer, err := os.OpenFile(source, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			_ = writer.Close()
		}
		t.Fatal("Linux media copy blocked on a FIFO")
	}
}
