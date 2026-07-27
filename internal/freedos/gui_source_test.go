package freedos

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGraphicalFreeDOSExposureContract(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	read := func(path string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return string(data)
	}

	integrated := read("gui/rufusarm64_integrated.py")
	dialog := read("gui/rufusarm64_freedos_dialog.py")
	logic := read("gui/rufusarm64_freedos.py")
	build := read("scripts/build-deb.sh")
	tests := read("scripts/test.sh")
	guide := read("docs/freedos-user-guide.md")

	for _, required := range []string{
		"install_freedos(RufusWindow)",
		`Gtk.Button(label="FreeDOS…")`,
		`FREEDOS_FORMATTER = "/usr/lib/rufusarm64/rufusarm64-freedos-format"`,
		"build_dry_run_command",
		"normalize_report(json.loads(stdout), reviewed)",
		`self.parent_window.active_job = "freedos-format"`,
		"WRITE FREEDOS",
		"not boot ARM64",
		"UEFI-only",
	} {
		if !strings.Contains(integrated+dialog, required) {
			t.Fatalf("graphical FreeDOS integration is missing %q", required)
		}
	}

	for _, required := range []string{
		"Fast creation I/O",
		"required boot/FAT32 data",
		"use Check USB for an",
		MediaVerificationScope,
	} {
		if !strings.Contains(logic, required) {
			t.Fatalf("graphical FreeDOS logic is missing fast creation contract %q", required)
		}
	}
	for _, forbidden := range []string{"--allow-fixed", "--no-unmount", "Writing the full device", "Reading back the full device", "total device I/O"} {
		if strings.Contains(logic, forbidden) {
			t.Fatalf("graphical FreeDOS logic contains forbidden or obsolete contract %q", forbidden)
		}
	}
	for _, required := range []string{
		`"${ROOT_DIR}/gui/rufusarm64_freedos.py"`,
		`"${ROOT_DIR}/gui/rufusarm64_freedos_dialog.py"`,
		`"${PACKAGE_DIR}/usr/lib/rufusarm64/rufusarm64_freedos.py"`,
		`"${PACKAGE_DIR}/usr/lib/rufusarm64/rufusarm64_freedos_dialog.py"`,
		`"${ROOT_DIR}/docs/freedos-user-guide.md"`,
	} {
		if !strings.Contains(build, required) {
			t.Fatalf("Debian package builder is missing graphical FreeDOS contract %q", required)
		}
	}
	for _, required := range []string{
		"gui/rufusarm64_freedos.py",
		"gui/rufusarm64_freedos_dialog.py",
		`usr/lib/rufusarm64/rufusarm64_freedos.py`,
		`usr/lib/rufusarm64/rufusarm64_freedos_dialog.py`,
		`usr/share/doc/rufusarm64/freedos-user-guide.md`,
	} {
		if !strings.Contains(tests, required) {
			t.Fatalf("package audit is missing graphical FreeDOS contract %q", required)
		}
	}
	for _, required := range []string{
		"x86-compatible processors",
		"BIOS or UEFI Legacy/CSM",
		"not an ARM64 boot path",
		"There is no fixed-disk override",
		"Unallocated data clusters are intentionally not overwritten",
		"Use **Check USB**",
	} {
		if !strings.Contains(guide, required) {
			t.Fatalf("FreeDOS user guide is missing %q", required)
		}
	}
}
