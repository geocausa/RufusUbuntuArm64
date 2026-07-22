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

func TestReadOperatorFileReadsRegularInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operator-input.json")
	if err := os.WriteFile(path, []byte("metadata"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := readOperatorFile(path, 64)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "metadata" {
		t.Fatalf("operator input = %q", data)
	}
}

func TestReadOperatorFileRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.json")
	link := filepath.Join(directory, "operator-input.json")
	if err := os.WriteFile(target, []byte("metadata"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readOperatorFile(link, 64); err == nil {
		t.Fatal("symlink operator input was accepted")
	}
}

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
