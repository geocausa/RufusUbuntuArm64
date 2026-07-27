//go:build linux

package main

import (
	"os"
	"strings"
	"testing"
)

func TestCommandSourceHasNoFixedDiskOverride(t *testing.T) {
	data, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, forbidden := range []string{"allow-fixed", "allowFixed", "ValidateTarget(resolved, selected, true)", "RevalidateTarget(resolved, identity, true)"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("FreeDOS command contains forbidden fixed-disk path %q", forbidden)
		}
	}
	for _, required := range []string{
		"safety.ValidateTarget(resolved, selected, false)",
		"safety.RevalidateTarget(resolved, identity, false)",
		"safety.RevalidateOpenBoundTarget(resolved, kernelDeviceID, false)",
		"freedos.ExecuteLinuxDevice",
		"safety.CancellationContext",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("FreeDOS command is missing required safety boundary %q", required)
		}
	}
}
