//go:build linux

package qualification

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRenameMetadataNoReplacePublishesNewDestination(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source")
	destination := filepath.Join(directory, "destination")
	if err := os.WriteFile(source, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := renameMetadataNoReplace(source, destination); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(source); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source still exists after rename: %v", err)
	}
	data, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new" {
		t.Fatalf("destination content = %q", data)
	}
}

func TestRenameMetadataNoReplaceNeverReplacesDestination(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source")
	destination := filepath.Join(directory, "destination")
	if err := os.WriteFile(source, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := renameMetadataNoReplace(source, destination); !errors.Is(err, os.ErrExist) {
		t.Fatalf("rename error = %v; want destination-exists refusal", err)
	}
	sourceData, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	destinationData, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(sourceData) != "new" || string(destinationData) != "existing" {
		t.Fatalf("source=%q destination=%q", sourceData, destinationData)
	}
}
