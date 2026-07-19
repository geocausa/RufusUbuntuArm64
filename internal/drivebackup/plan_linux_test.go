//go:build linux

package drivebackup

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestInspectDestinationReturnsBoundedPlan(t *testing.T) {
	output := filepath.Join(t.TempDir(), "drive.img")
	info, err := InspectDestination(output, "/dev/rufusarm64-nonexistent-source", 4096)
	if err != nil {
		t.Fatal(err)
	}
	if info.Path != output {
		t.Fatalf("path = %q, want %q", info.Path, output)
	}
	if info.Directory != filepath.Dir(output) {
		t.Fatalf("directory = %q, want %q", info.Directory, filepath.Dir(output))
	}
	if info.RequiredBytes != 4096 || info.AvailableBytes < info.RequiredBytes {
		t.Fatalf("unexpected capacity plan: %+v", info)
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("planning created the destination: %v", err)
	}
}

func TestInspectDestinationRefusesInvalidOrExistingOutput(t *testing.T) {
	directory := t.TempDir()
	existing := filepath.Join(directory, "existing.img")
	if err := os.WriteFile(existing, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		output   string
		required uint64
	}{
		{name: "zero size", output: filepath.Join(directory, "zero.img")},
		{name: "oversize", output: filepath.Join(directory, "large.img"), required: math.MaxInt64 + 1},
		{name: "existing", output: existing, required: 1},
		{name: "relative", output: "drive.img", required: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := InspectDestination(test.output, "/dev/rufusarm64-nonexistent-source", test.required); err == nil {
				t.Fatal("invalid destination plan was accepted")
			}
		})
	}
	got, err := os.ReadFile(existing)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "preserve" {
		t.Fatalf("existing output changed: %q", got)
	}
}
