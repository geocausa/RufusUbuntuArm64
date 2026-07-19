//go:build linux

package linuxmedia

import (
	"os"
	"strings"
	"testing"
)

func TestSelectionIdentityCallbackRunsOnlyBeforeFirstErase(t *testing.T) {
	data, err := os.ReadFile("create.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	callback := "opts.BeforeDestructive(isoFile)"
	if count := strings.Count(source, callback); count != 1 {
		t.Fatalf("selection callback count = %d, want 1", count)
	}
	checkStart := strings.Index(source, "checkTarget := func() error {")
	firstCheck := strings.Index(source[checkStart:], "if err := checkTarget();")
	if checkStart < 0 || firstCheck < 0 {
		t.Fatal("target-check anchors not found")
	}
	if strings.Contains(source[checkStart:checkStart+firstCheck], callback) {
		t.Fatal("mutable selection identity remains in the repeated open-device check")
	}
	erase := strings.Index(source, `runPersistent(ctx, emit, "wipefs"`)
	if gate := strings.Index(source, callback); erase < 0 || gate < 0 || gate > erase {
		t.Fatal("selection callback is not before the first erase path")
	}
}
