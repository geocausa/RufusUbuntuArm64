//go:build linux

package acquisition

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestReadRegularLimitedWithOpenRejectsReplacement(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "state.json")
	replacement := filepath.Join(directory, "replacement.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(replacement, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	open := func(name string) (*os.File, error) {
		if err := os.Rename(replacement, name); err != nil {
			return nil, err
		}
		return openChannelMetadataNoFollow(name)
	}
	_, err := readRegularLimitedWithOpen(path, 64, open)
	if err == nil || !strings.Contains(err.Error(), "changed while it was being opened") {
		t.Fatalf("replacement error = %v", err)
	}
}

func TestReadRegularLimitedWithOpenRejectsFIFOReplacementWithoutBlocking(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "catalog.json")
	fifo := filepath.Join(directory, "replacement.fifo")
	if err := os.WriteFile(path, []byte("metadata"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	open := func(name string) (*os.File, error) {
		if err := os.Rename(fifo, name); err != nil {
			return nil, err
		}
		return openChannelMetadataNoFollow(name)
	}
	_, err := readRegularLimitedWithOpen(path, 64, open)
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("FIFO replacement error = %v", err)
	}
}

func TestOpenChannelMetadataNoFollowRejectsDirectFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metadata.fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := openChannelMetadataNoFollow(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().IsRegular() {
		t.Fatal("FIFO opened as a regular file")
	}
}
