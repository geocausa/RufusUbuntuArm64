//go:build linux

package trustedexec

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveAtAcceptsTrustedMount(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "mount")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := resolveAt("mount", []string{root}, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	if got != path {
		t.Fatalf("got %s want %s", got, path)
	}
}
