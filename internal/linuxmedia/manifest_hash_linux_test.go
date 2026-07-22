//go:build linux

package linuxmedia

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestHashStableFileWithOpenAcceptsRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "payload")
	data := []byte("stable payload")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	digest, err := hashStableFileWithOpen(context.Background(), path, uint64(len(data)), openLinuxMediaNoFollow)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(data)
	if digest != want {
		t.Fatalf("digest = %x, want %x", digest, want)
	}
}

func TestHashStableFileWithOpenRejectsReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "payload")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := hashStableFileWithOpen(context.Background(), path, 5, func(name string) (*os.File, error) {
		if err := os.Remove(name); err != nil {
			return nil, err
		}
		if err := os.WriteFile(name, []byte("other"), 0o600); err != nil {
			return nil, err
		}
		return openLinuxMediaNoFollow(name)
	})
	if err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("replacement error = %v", err)
	}
}

func TestHashStableFileWithOpenRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "payload")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := hashStableFileWithOpen(context.Background(), path, 5, func(name string) (*os.File, error) {
			if err := os.Remove(name); err != nil {
				return nil, err
			}
			if err := syscall.Mkfifo(name, 0o600); err != nil {
				return nil, err
			}
			return openLinuxMediaNoFollow(name)
		})
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "identity changed") {
			t.Fatalf("FIFO error = %v", err)
		}
	case <-time.After(time.Second):
		writer, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			_ = writer.Close()
		}
		t.Fatal("Linux media hashing blocked on a FIFO")
	}
}
