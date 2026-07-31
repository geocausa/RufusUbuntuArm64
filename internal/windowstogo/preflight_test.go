//go:build linux

package windowstogo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFindCaseInsensitiveBindsUniqueRealComponents(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "Windows", "System32", "config")
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(path, "BCD-Template")
	if err := os.WriteFile(want, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := findCaseInsensitive(root, "windows/system32/CONFIG/bcd-template")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got=%q want=%q", got, want)
	}
}

func TestFindCaseInsensitiveRejectsAmbiguityAndSymlinks(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "Windows"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "WINDOWS"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := findCaseInsensitive(root, "windows"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguity error=%v", err)
	}
	root = t.TempDir()
	if err := os.Symlink("/tmp", filepath.Join(root, "Windows")); err != nil {
		t.Fatal(err)
	}
	if _, err := findCaseInsensitive(root, "Windows/file"); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("symlink error=%v", err)
	}
}
