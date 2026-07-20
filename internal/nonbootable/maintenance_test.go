//go:build linux

package nonbootable

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNoDescriptorBindingApplicatorRemains(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	for _, path := range []string{
		filepath.Join(root, ".github", "workflows", "apply-nonbootable-fd-binding.yml"),
		filepath.Join(root, ".github", "scripts", "apply_nonbootable_fd_binding.py"),
	} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("temporary descriptor-binding applicator remains at %s", path)
		}
	}
}
