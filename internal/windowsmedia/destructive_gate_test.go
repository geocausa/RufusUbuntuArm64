//go:build linux

package windowsmedia

import (
	"os"
	"strings"
	"testing"
)

func TestSelectionIdentityCallbackRunsOnlyBeforeFirstErase(t *testing.T) {
	data, err := os.ReadFile("windowsmedia.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	callback := "opts.BeforeDestructive(isoFile)"
	if count := strings.Count(source, callback); count != 1 {
		t.Fatalf("selection callback count = %d, want 1", count)
	}
	checkStart := strings.Index(source, "checkTarget := func() error {")
	runnerStart := strings.Index(source, "runOnTarget := func")
	if checkStart < 0 || runnerStart <= checkStart {
		t.Fatal("target-check anchors not found")
	}
	if strings.Contains(source[checkStart:runnerStart], callback) {
		t.Fatal("mutable selection identity remains in the repeated open-device check")
	}
	erase := strings.Index(source, `runOnTarget("wipefs"`)
	if gate := strings.Index(source, callback); erase < 0 || gate < 0 || gate > erase {
		t.Fatal("selection callback is not immediately before the first erase path")
	}
}
