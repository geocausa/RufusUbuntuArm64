//go:build linux

package windowsmedia

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInspectMountedInstallPayloadReturnsExactStandalonePayload(t *testing.T) {
	root := t.TempDir()
	mustWritePayloadFixture(t, root, "sources/install.esd")
	mustWritePayloadFixture(t, root, "sources/boot.wim")
	mustWritePayloadFixture(t, root, "efi/boot/bootaa64.efi")

	payload, err := InspectMountedInstallPayload(root)
	if err != nil {
		t.Fatal(err)
	}
	if payload.Kind != "ESD" || payload.PrimaryPath != filepath.Join(root, "sources", "install.esd") ||
		payload.BootWIMPath != filepath.Join(root, "sources", "boot.wim") || !payload.HasARM64 || len(payload.ReferencePaths) != 0 {
		t.Fatalf("payload=%#v", payload)
	}
}

func TestInspectMountedInstallPayloadReturnsCompleteSplitSet(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{
		"sources/install.swm", "sources/install2.swm", "sources/install3.swm",
		"sources/boot.wim", "efi/boot/bootaa64.efi",
	} {
		mustWritePayloadFixture(t, root, path)
	}
	payload, err := InspectMountedInstallPayload(root)
	if err != nil {
		t.Fatal(err)
	}
	if payload.Kind != "SWM" || payload.PrimaryPath != filepath.Join(root, "sources", "install.swm") || len(payload.ReferencePaths) != 3 {
		t.Fatalf("payload=%#v", payload)
	}
	for index, name := range []string{"install.swm", "install2.swm", "install3.swm"} {
		if payload.ReferencePaths[index] != filepath.Join(root, "sources", name) {
			t.Fatalf("reference %d=%q", index, payload.ReferencePaths[index])
		}
	}
}

func mustWritePayloadFixture(t *testing.T, root, relative string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
}
