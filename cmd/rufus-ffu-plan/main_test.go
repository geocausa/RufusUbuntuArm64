//go:build linux

package main

import (
	"strings"
	"testing"
)

func TestRunRequiresImage(t *testing.T) {
	if err := run(nil); err == nil || !strings.Contains(err.Error(), "--image is required") {
		t.Fatalf("error=%v", err)
	}
}

func TestRunHasNoTargetOption(t *testing.T) {
	err := run([]string{"--target", "/dev/sda", "--image", "fixture.ffu"})
	if err == nil || !strings.Contains(err.Error(), "flag provided but not defined: -target") {
		t.Fatalf("error=%v", err)
	}
}

func TestRunRejectsPositionalArgumentsBeforeOpeningSource(t *testing.T) {
	err := run([]string{"--image", "fixture.ffu", "unexpected"})
	if err == nil || !strings.Contains(err.Error(), "unexpected positional arguments") {
		t.Fatalf("error=%v", err)
	}
}

func TestHumanBytes(t *testing.T) {
	tests := map[uint64]string{
		0:          "0 B",
		1023:       "1023 B",
		1024:       "1.0 KiB",
		1048576:    "1.0 MiB",
		1073741824: "1.0 GiB",
	}
	for value, want := range tests {
		if got := humanBytes(value); got != want {
			t.Fatalf("humanBytes(%d)=%q want=%q", value, got, want)
		}
	}
}
