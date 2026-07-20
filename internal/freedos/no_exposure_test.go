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
		filepath.Join(root, ".github", "workflows", "map-freedos-payload.yml"),
		filepath.Join(root, ".github", "workflows", "apply-freedos-payload.yml"),
		filepath.Join(root, ".github", "workflows", "verify-freedos-payload.yml"),
		filepath.Join(root, ".github", "workflows", "extract-freecom-license.yml"),
		filepath.Join(root, ".github", "workflows", "finalize-freedos-payload.yml"),
		filepath.Join(root, ".github", "workflows", "sync-freedos-payload-stage2.yml"),
		filepath.Join(root, ".github", "workflows", "diagnose-freedos-media.yml"),
		filepath.Join(root, ".github", "scripts", "finalize_freedos_payload.py"),
		filepath.Join(root, "docs", "freedos-payload-map.txt"),
		filepath.Join(root, "docs", "freedos-finalizer-diagnostic.txt"),
		filepath.Join(root, "docs", "freedos-sync-diagnostic.txt"),
		filepath.Join(root, "docs", "freedos-media-diagnostic.txt"),
	} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("temporary FreeDOS research applicator remains at %s", path)
		}
	}
}
