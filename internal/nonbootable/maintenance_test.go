//go:build linux

package nonbootable

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNoFormatterMaintenanceApplicatorRemains(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	for _, path := range []string{
		filepath.Join(root, ".github", "workflows", "apply-nonbootable-fd-binding.yml"),
		filepath.Join(root, ".github", "scripts", "apply_nonbootable_fd_binding.py"),
		filepath.Join(root, ".github", "workflows", "apply-nonbootable-options-guard.yml"),
		filepath.Join(root, ".github", "workflows", "apply-nonbootable-plan-contract.yml"),
		filepath.Join(root, ".github", "workflows", "apply-nonbootable-gofmt.yml"),
		filepath.Join(root, ".github", "workflows", "apply-nonbootable-gtk-package.yml"),
		filepath.Join(root, ".github", "workflows", "apply-nonbootable-gtk-hardening.yml"),
		filepath.Join(root, ".github", "workflows", "apply-nonbootable-gtk-hardening-v2.yml"),
		filepath.Join(root, ".github", "scripts", "apply_nonbootable_gtk_hardening.py"),
	} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("temporary formatter maintenance applicator remains at %s", path)
		}
	}
}
