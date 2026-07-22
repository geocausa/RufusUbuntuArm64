//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestReadOperatorFileRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operator-input.fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := readOperatorFile(path, 64)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("FIFO input error = %v", err)
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
		t.Fatal("reading a FIFO operator input blocked")
	}
}
