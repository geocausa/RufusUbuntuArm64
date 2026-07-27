//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestRenameNoReplacePublishesFile(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source")
	destination := filepath.Join(directory, "destination")
	if err := os.WriteFile(source, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := renameNoReplace(source, destination); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(source); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source remains after publication: %v", err)
	}
	content, err := os.ReadFile(destination)
	if err != nil || string(content) != "new" {
		t.Fatalf("destination content = %q, err = %v", content, err)
	}
}

func TestRenameNoReplacePublishesDirectory(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source")
	destination := filepath.Join(directory, "destination")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "publication.json"), []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := renameNoReplace(source, destination); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(source); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source directory remains after publication: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(destination, "publication.json"))
	if err != nil || string(content) != "new" {
		t.Fatalf("published directory content = %q, err = %v", content, err)
	}
}

func TestRenameNoReplacePreservesConcurrentFile(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source")
	destination := filepath.Join(directory, "destination")
	if err := os.WriteFile(source, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := renameNoReplace(source, destination); !errors.Is(err, syscall.EEXIST) {
		t.Fatalf("no-replace file error = %v", err)
	}
	for path, expected := range map[string]string{source: "new", destination: "existing"} {
		content, err := os.ReadFile(path)
		if err != nil || string(content) != expected {
			t.Fatalf("%s content = %q, err = %v", path, content, err)
		}
	}
}

func TestRenameNoReplacePreservesConcurrentDirectory(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source")
	destination := filepath.Join(directory, "destination")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "publication.json"), []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := renameNoReplace(source, destination); !errors.Is(err, syscall.EEXIST) {
		t.Fatalf("no-replace directory error = %v", err)
	}
	if content, err := os.ReadFile(filepath.Join(source, "publication.json")); err != nil || string(content) != "new" {
		t.Fatalf("staged directory changed: content=%q err=%v", content, err)
	}
	entries, err := os.ReadDir(destination)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("concurrent directory was replaced: %v", entries)
	}
}
