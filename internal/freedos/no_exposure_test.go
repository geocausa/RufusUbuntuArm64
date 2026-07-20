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
