//go:build linux

package trustedexec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveAtAcceptsTrustedExecutable(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "lsblk")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := resolveAt("lsblk", []string{root}, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	if got != path {
		t.Fatalf("got %s want %s", got, path)
	}
}

func TestResolveAtAcceptsTrustedQEMUImg(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "qemu-img")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := resolveAt("qemu-img", []string{root}, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	if got != path {
		t.Fatalf("got %s want %s", got, path)
	}
}

func TestResolveAtRejectsUnsafeInputs(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "lsblk")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveAt("lsblk", []string{root}, uint32(os.Getuid())); err == nil || !strings.Contains(err.Error(), "not executable") {
		t.Fatalf("non-executable utility error = %v", err)
	}
	if _, err := resolveAt("sh", []string{root}, uint32(os.Getuid())); err == nil || !strings.Contains(err.Error(), "not allowlisted") {
		t.Fatalf("non-allowlisted utility error = %v", err)
	}
	if _, err := resolveAt("../lsblk", []string{root}, uint32(os.Getuid())); err == nil {
		t.Fatal("path traversal was accepted")
	}
}

func TestResolveAtRejectsWritableExecutable(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "lsblk")
	if err := os.WriteFile(path, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveAt("lsblk", []string{root}, uint32(os.Getuid())); err == nil || !strings.Contains(err.Error(), "group/world writable") {
		t.Fatalf("writable utility error = %v", err)
	}
}

func TestResolveAtRejectsUnexpectedOwner(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "lsblk")
	if err := os.WriteFile(path, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveAt("lsblk", []string{root}, uint32(os.Getuid()+1)); err == nil || !strings.Contains(err.Error(), "owned by uid") {
		t.Fatalf("unexpected-owner error = %v", err)
	}
}

func TestResolveAtRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "lsblk")
	if err := os.WriteFile(target, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "lsblk")); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveAt("lsblk", []string{root}, uint32(os.Getuid())); err == nil || !strings.Contains(err.Error(), "outside trusted roots") {
		t.Fatalf("symlink-escape error = %v", err)
	}
}
