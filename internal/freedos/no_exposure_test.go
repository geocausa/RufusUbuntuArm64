package freedos

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommandStageAllowsOnlyGuardedNonGUIExposure(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	command := filepath.Join(root, "cmd", "rufus-freedos-format", "main.go")
	if info, err := os.Stat(command); err != nil || info.IsDir() {
		t.Fatalf("guarded FreeDOS formatter command is missing: %v", err)
	}
	for _, path := range []string{
		filepath.Join(root, "cmd", "rufus-freedos"),
		filepath.Join(root, "gui", "rufusarm64_freedos.py"),
		filepath.Join(root, "gui", "rufusarm64_freedos_dialog.py"),
		filepath.Join(root, "packaging", "io.github.geocausa.RufusArm64.freedos.policy"),
	} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("FreeDOS command stage exposed an unreviewed product path: %s", path)
		}
	}

	policyPath := filepath.Join(root, "packaging", "io.github.geocausa.RufusArm64.policy")
	policy, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(policy)
	for _, required := range []string{
		`<action id="io.github.geocausa.RufusArm64.format-freedos">`,
		`<annotate key="org.freedesktop.policykit.exec.path">/usr/lib/rufusarm64/rufusarm64-freedos-format</annotate>`,
		`<allow_any>no</allow_any>`,
		`<allow_inactive>no</allow_inactive>`,
		`<allow_active>auth_admin</allow_active>`,
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("dedicated FreeDOS Polkit boundary is missing %q", required)
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
		filepath.Join(root, ".github", "workflows", "freedos-command-diagnostic.yml"),
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
