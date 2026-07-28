//go:build linux

package persistence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPatchBootTreeLaterFailurePreservesOwnedPartialEvidence(t *testing.T) {
	root := t.TempDir()
	firstPath := filepath.Join(root, "boot", "grub", "grub.cfg")
	secondPath := filepath.Join(root, "boot", "grub", "loopback.cfg")
	if err := os.MkdirAll(filepath.Dir(firstPath), 0o755); err != nil {
		t.Fatal(err)
	}
	firstOriginal := "linux /casper/vmlinuz $cmdline --- quiet\n"
	if err := os.WriteFile(firstPath, []byte(firstOriginal), 0o640); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.cfg")
	outsideOriginal := "linux /casper/vmlinuz $cmdline --- outside\n"
	if err := os.WriteFile(outside, []byte(outsideOriginal), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, secondPath); err != nil {
		t.Fatal(err)
	}
	detection := readyUbuntuDetection()
	detection.PatchPaths = []string{"boot/grub/grub.cfg", "boot/grub/loopback.cfg"}

	patched, err := PatchBootTree(root, detection)
	if err == nil {
		t.Fatal("later symbolic-link patch failure reported success")
	}
	if patched != nil {
		t.Fatalf("failed multi-file patch returned success evidence: %v", patched)
	}
	firstCurrent, err := os.ReadFile(firstPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstCurrent) != "linux /casper/vmlinuz $cmdline persistent --- quiet\n" {
		t.Fatalf("first owned patch evidence = %q", firstCurrent)
	}
	outsideCurrent, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(outsideCurrent) != outsideOriginal {
		t.Fatalf("outside symbolic-link target changed: %q", outsideCurrent)
	}
	info, err := os.Lstat(secondPath)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("later symbolic-link path changed: info=%v err=%v", info, err)
	}
	entries, err := os.ReadDir(filepath.Dir(firstPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".rufusarm64-") {
			t.Fatalf("temporary boot patch remains after failure: %s", entry.Name())
		}
	}
}
