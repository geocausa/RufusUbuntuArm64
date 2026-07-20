//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStaticFormatterHasNarrowLintianOverride(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "packaging", "rufusarm64.lintian-overrides"))
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	line := "rufusarm64: statically-linked-binary [usr/lib/rufusarm64/rufusarm64-nonbootable-format]"
	if count := strings.Count(string(content), line); count != 1 {
		t.Fatalf("static formatter override count=%d, want exactly one", count)
	}
}
