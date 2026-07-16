//go:build linux

package persistence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPatchBootConfigPreservesLineEndingsAndInsertionPoint(t *testing.T) {
	detection := readyDetection()
	detection.Family = FamilyUbuntuCasper
	detection.BootParameter = "persistent"
	input := "menuentry Ubuntu {\r\n\tlinux /casper/vmlinuz boot=casper quiet splash ---\r\n}\r\n"
	got, changes, err := PatchBootConfig(input, detection)
	if err != nil {
		t.Fatal(err)
	}
	if changes != 1 {
		t.Fatalf("changes=%d", changes)
	}
	want := "\tlinux /casper/vmlinuz boot=casper quiet splash persistent ---\r\n"
	if !strings.Contains(got, want) || strings.Count(got, "\r\n") != 3 {
		t.Fatalf("patched content:\n%q", got)
	}
}

func TestPatchBootConfigLeavesUnrelatedAndEnabledLines(t *testing.T) {
	detection := readyDetection()
	detection.Family = FamilyDebianLive
	detection.BootParameter = "persistence"
	input := "append boot=live components persistence\nlinux /vmlinuz root=/dev/sda1\n# append boot=live\n"
	got, changes, err := PatchBootConfig(input, detection)
	if err != nil {
		t.Fatal(err)
	}
	if changes != 0 || got != input {
		t.Fatalf("unexpected patch: changes=%d content=%q", changes, got)
	}
}

func TestPatchBootTreeAtomicallyPatchesDetectedPath(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "boot", "grub", "grub.cfg")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("linux /casper/vmlinuz boot=casper quiet ---\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	detection := Detection{
		Family:          FamilyUbuntuCasper,
		BootParameter:   "persistent",
		Filesystem:      "ext4",
		FilesystemLabel: "casper-rw",
		PatchPaths:      []string{"boot/grub/grub.cfg"},
	}
	patched, err := PatchBootTree(root, detection)
	if err != nil {
		t.Fatal(err)
	}
	if len(patched) != 1 || patched[0] != "boot/grub/grub.cfg" {
		t.Fatalf("patched=%v", patched)
	}
	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "linux /casper/vmlinuz boot=casper quiet persistent ---\n" {
		t.Fatalf("content=%q", content)
	}
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
}

func TestPatchBootTreeRejectsSymlinkFinalPath(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "boot", "grub"), 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.cfg")
	if err := os.WriteFile(outside, []byte("linux boot=casper\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "boot", "grub", "grub.cfg")); err != nil {
		t.Fatal(err)
	}
	detection := Detection{Family: FamilyUbuntuCasper, BootParameter: "persistent", Filesystem: "ext4", FilesystemLabel: "casper-rw", PatchPaths: []string{"boot/grub/grub.cfg"}}
	if _, err := PatchBootTree(root, detection); err == nil {
		t.Fatal("symlink boot configuration accepted")
	}
	content, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "linux boot=casper\n" {
		t.Fatal("outside file was changed")
	}
}

func TestPatchBootTreeRejectsSymlinkParent(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "grub.cfg"), []byte("linux boot=casper\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "boot"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "boot", "grub")); err != nil {
		t.Fatal(err)
	}
	detection := Detection{Family: FamilyUbuntuCasper, BootParameter: "persistent", Filesystem: "ext4", FilesystemLabel: "casper-rw", PatchPaths: []string{"boot/grub/grub.cfg"}}
	if _, err := PatchBootTree(root, detection); err == nil {
		t.Fatal("symlink parent accepted")
	}
}

func TestPatchBootTreePatchesRootConfiguration(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "syslinux.cfg")
	if err := os.WriteFile(configPath, []byte("append boot=live components\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	detection := Detection{Family: FamilyDebianLive, BootParameter: "persistence", Filesystem: "ext4", FilesystemLabel: "persistence", PersistenceConfig: "/ union\n", PatchPaths: []string{"syslinux.cfg"}}
	if _, err := PatchBootTree(root, detection); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "append boot=live components persistence\n" {
		t.Fatalf("content=%q", content)
	}
}

func TestPatchBootConfigInsertsBeforeInlineComment(t *testing.T) {
	detection := Detection{Family: FamilyDebianLive, BootParameter: "persistence", Filesystem: "ext4", FilesystemLabel: "persistence", PersistenceConfig: "/ union\n", PatchPaths: []string{"syslinux.cfg"}}
	got, changes, err := PatchBootConfig("append boot=live components # keep this\n", detection)
	if err != nil {
		t.Fatal(err)
	}
	if changes != 1 || got != "append boot=live components persistence # keep this\n" {
		t.Fatalf("changes=%d content=%q", changes, got)
	}
	got, changes, err = PatchBootConfig("append root=/dev/null # boot=live\n", detection)
	if err != nil {
		t.Fatal(err)
	}
	if changes != 0 || got != "append root=/dev/null # boot=live\n" {
		t.Fatalf("comment marker caused patch: changes=%d content=%q", changes, got)
	}
}
