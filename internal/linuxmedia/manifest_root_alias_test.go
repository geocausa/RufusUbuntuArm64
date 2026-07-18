//go:build linux

package linuxmedia

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestInspectOmittedRootAliasDoesNotReserveFATName(t *testing.T) {
	source := t.TempDir()
	writeMediaFile(t, source, "efi/boot/bootaa64.efi", "boot")
	writeMediaFile(t, source, "casper/vmlinuz", "kernel")
	writeMediaFile(t, source, "Ubuntu", "real payload")
	if err := os.Symlink(".", filepath.Join(source, "ubuntu")); err != nil {
		t.Fatal(err)
	}

	manifest, err := Inspect(context.Background(), source, Options{
		Architecture: "arm64",
		RequireUEFI:  true,
		RequireFAT32: true,
	})
	if err != nil {
		t.Fatalf("omitted root alias must not collide with a real destination path: %v", err)
	}
	if manifest.OmittedRootAliases != 1 {
		t.Fatalf("omitted root aliases = %d, want 1", manifest.OmittedRootAliases)
	}
	var found bool
	for _, entry := range manifest.Entries {
		if entry.Path == "Ubuntu" && entry.SHA256 != "" {
			found = true
		}
		if entry.Path == "ubuntu" || len(entry.Path) > len("ubuntu/") && entry.Path[:len("ubuntu/")] == "ubuntu/" {
			t.Fatalf("root alias was materialized unexpectedly: %+v", entry)
		}
	}
	if !found {
		t.Fatal("real case-distinct payload was not preserved")
	}
}
