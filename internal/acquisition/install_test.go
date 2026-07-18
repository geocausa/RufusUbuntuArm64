package acquisition

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallDownloadedFileNoReplace(t *testing.T) {
	directory := t.TempDir()
	temp := filepath.Join(directory, ".download.part")
	destination := filepath.Join(directory, "image.iso")
	if err := os.WriteFile(temp, []byte("verified"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("other process"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := installDownloadedFile(temp, destination, false); err == nil || !strings.Contains(err.Error(), "refusing to replace") {
		t.Fatalf("no-replace install error = %v", err)
	}
	content, err := os.ReadFile(destination)
	if err != nil || string(content) != "other process" {
		t.Fatalf("destination was replaced: content=%q err=%v", content, err)
	}
	if content, err := os.ReadFile(temp); err != nil || string(content) != "verified" {
		t.Fatalf("temporary verified file changed: content=%q err=%v", content, err)
	}
}

func TestInstallDownloadedFileLinksVerifiedInode(t *testing.T) {
	directory := t.TempDir()
	temp := filepath.Join(directory, ".download.part")
	destination := filepath.Join(directory, "image.iso")
	if err := os.WriteFile(temp, []byte("verified"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := installDownloadedFile(temp, destination, false); err != nil {
		t.Fatal(err)
	}
	tempInfo, err := os.Stat(temp)
	if err != nil {
		t.Fatal(err)
	}
	destinationInfo, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(tempInfo, destinationInfo) {
		t.Fatal("no-replace install did not publish the verified temporary inode")
	}
}

func TestInstallDownloadedFileReplace(t *testing.T) {
	directory := t.TempDir()
	temp := filepath.Join(directory, ".download.part")
	destination := filepath.Join(directory, "image.iso")
	if err := os.WriteFile(temp, []byte("verified"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := installDownloadedFile(temp, destination, true); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(destination)
	if err != nil || string(content) != "verified" {
		t.Fatalf("replacement content=%q err=%v", content, err)
	}
	if _, err := os.Stat(temp); !os.IsNotExist(err) {
		t.Fatalf("temporary name remains after replacement: %v", err)
	}
}
