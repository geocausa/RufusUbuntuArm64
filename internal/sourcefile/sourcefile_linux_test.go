//go:build linux

package sourcefile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInspectAndOpenRegular(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "image.img")
	if err := os.WriteFile(path, []byte("image"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolved, identity, err := Inspect(path)
	if err != nil {
		t.Fatal(err)
	}
	file, err := OpenRegular(resolved, identity)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
}

func TestOpenRegularRejectsReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "image.img")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolved, identity, err := Inspect(path)
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(dir, "replacement")
	if err := os.WriteFile(replacement, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if file, err := OpenRegular(resolved, identity); err == nil {
		file.Close()
		t.Fatal("replacement was accepted")
	}
}

func TestOpenRegularRejectsInPlaceChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "image.img")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolved, identity, err := Inspect(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("longer content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if file, err := OpenRegular(resolved, identity); err == nil {
		file.Close()
		t.Fatal("changed image was accepted")
	}
}
