package freedos

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFeasibilityGateHasNoPrematureProductExposure(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	for _, path := range []string{
		filepath.Join(root, "cmd", "rufus-freedos"),
		filepath.Join(root, "cmd", "rufus-freedos-format"),
		filepath.Join(root, "gui", "rufusarm64_freedos.py"),
		filepath.Join(root, "gui", "rufusarm64_freedos_dialog.py"),
		filepath.Join(root, "packaging", "io.github.geocausa.RufusArm64.freedos.policy"),
	} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("FreeDOS feasibility work exposed product code before the gate was complete: %s", path)
		}
	}
}

func TestNoFreeDOSResearchApplicatorRemains(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	for _, path := range []string{
		filepath.Join(root, ".github", "workflows", "map-freedos-bootcode.yml"),
		filepath.Join(root, ".github", "workflows", "apply-freedos-staticcheck.yml"),
		filepath.Join(root, ".github", "scripts", "apply_freedos_bootcode_provenance.py"),
		filepath.Join(root, ".github", "scripts", "finalize_freedos_bootcode_provenance.py"),
		filepath.Join(root, "docs", "freedos-rufus-bootcode-map.txt"),
	} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("temporary FreeDOS research applicator remains at %s", path)
		}
	}
}
