//go:build linux

package drivebackup

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDestinationRevalidationRejectsReplacedParent(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "destination")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	plan, err := prepareDestination(
		filepath.Join(parent, "drive.img"),
		"/dev/rufusarm64-nonexistent-source",
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.directory.Close()

	moved := filepath.Join(root, "destination-moved")
	if err := os.Rename(parent, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := plan.revalidatePath(); err == nil {
		t.Fatal("replaced destination directory was accepted")
	}
}
