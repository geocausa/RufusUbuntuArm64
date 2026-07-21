//go:build linux

package runtimeintegrity

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRenameNoReplaceAtPublishesNewDestination(t *testing.T) {
	directoryPath := t.TempDir()
	directory, err := os.Open(directoryPath)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if err := os.WriteFile(filepath.Join(directoryPath, "source"), []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := renameNoReplaceAt(directory, "source", "destination"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(directoryPath, "source")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source still exists after rename: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(directoryPath, "destination"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new" {
		t.Fatalf("destination content = %q", data)
	}
}

func TestRenameNoReplaceAtNeverReplacesDestination(t *testing.T) {
	directoryPath := t.TempDir()
	directory, err := os.Open(directoryPath)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if err := os.WriteFile(filepath.Join(directoryPath, "source"), []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directoryPath, "destination"), []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := renameNoReplaceAt(directory, "source", "destination"); !errors.Is(err, os.ErrExist) {
		t.Fatalf("rename error = %v; want destination-exists refusal", err)
	}
	source, err := os.ReadFile(filepath.Join(directoryPath, "source"))
	if err != nil {
		t.Fatal(err)
	}
	destination, err := os.ReadFile(filepath.Join(directoryPath, "destination"))
	if err != nil {
		t.Fatal(err)
	}
	if string(source) != "new" || string(destination) != "existing" {
		t.Fatalf("source=%q destination=%q", source, destination)
	}
}
