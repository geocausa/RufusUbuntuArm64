//go:build linux

package qualification

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestReadRegularNoFollowRejectsFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metadata")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegularNoFollow(path, 64); err == nil || !strings.Contains(err.Error(), "bounded real regular file") {
		t.Fatalf("readRegularNoFollow error = %v", err)
	}
}

func TestReadRegularNoFollowRejectsRegularFileReplacementBeforeOpen(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "metadata")
	replacement := filepath.Join(directory, "replacement")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(replacement, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := readRegularNoFollowWithOpen(path, 64, func(openPath string) (*os.File, error) {
		if err := os.Rename(replacement, openPath); err != nil {
			return nil, err
		}
		return openMetadataNoFollow(openPath)
	})
	if err == nil || !strings.Contains(err.Error(), "changed while opening") {
		t.Fatalf("readRegularNoFollowWithOpen error = %v", err)
	}
}

func TestReadRegularNoFollowRejectsFIFOReplacementWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metadata")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := readRegularNoFollowWithOpen(path, 64, func(openPath string) (*os.File, error) {
		if err := os.Remove(openPath); err != nil {
			return nil, err
		}
		if err := syscall.Mkfifo(openPath, 0o600); err != nil {
			return nil, err
		}
		return openMetadataNoFollow(openPath)
	})
	if err == nil || !strings.Contains(err.Error(), "bounded real regular file") {
		t.Fatalf("readRegularNoFollowWithOpen error = %v", err)
	}
}
