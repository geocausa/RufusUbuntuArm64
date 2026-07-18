#!/usr/bin/env python3
import pathlib

root = pathlib.Path(__file__).resolve().parents[1]

# The installed launcher must always open the same main application.
launcher = root / "packaging/rufusarm64"
launcher.write_text('''#!/bin/sh
# Persistence is integrated into the main RufusArm64 window.
if [ "${1:-}" = "--persistence" ]; then
  shift
fi
exec /usr/bin/python3 /usr/lib/rufusarm64/rufusarm64.py "$@"
''')

# Keep the desktop shortcut, but route it to the same application.
desktop = root / "packaging/io.github.geocausa.RufusArm64.desktop"
text = desktop.read_text()
old = "Exec=rufusarm64 --persistence\n"
if text.count(old) != 1:
    raise SystemExit(f"desktop persistence action anchor count {text.count(old)}")
desktop.write_text(text.replace(old, "Exec=rufusarm64\n", 1))

# Update the package validation contract from the removed second-window button
# to the unified main-window behavior.
test = root / "scripts/test.sh"
text = test.read_text()
old = '''grep -q 'Open Persistent USB Creator' "${installed_gui}"
'''
new = '''grep -q 'Gtk.Expander(label="Persistent storage")' "${installed_gui}"
grep -q 'Keep files and settings across reboots' "${installed_gui}"
if grep -q 'Open Persistent USB Creator' "${installed_gui}"; then
  echo "Packaged GUI must not expose the removed secondary persistence window" >&2
  exit 1
fi
if grep -q 'rufusarm64_persistence.py' "${extract_dir}/usr/bin/rufusarm64"; then
  echo "Installed launcher must keep persistence in the main application" >&2
  exit 1
fi
grep -q '^Exec=rufusarm64$' "${extract_dir}/usr/share/applications/io.github.geocausa.RufusArm64.desktop"
'''
if text.count(old) != 1:
    raise SystemExit(f"package contract anchor count {text.count(old)}")
test.write_text(text.replace(old, new, 1))

# Extend source regression coverage for the installed launcher contract.
source_test = root / "gui/test_unified_persistence_ui.py"
text = source_test.read_text()
insert = '''
    def test_packaged_launcher_keeps_one_application(self):
        launcher = pathlib.Path("packaging/rufusarm64").read_text(encoding="utf-8")
        desktop = pathlib.Path("packaging/io.github.geocausa.RufusArm64.desktop").read_text(encoding="utf-8")
        self.assertNotIn("rufusarm64_persistence.py", launcher)
        self.assertIn("rufusarm64.py", launcher)
        self.assertIn("Exec=rufusarm64\\n", desktop)
        self.assertNotIn("Exec=rufusarm64 --persistence", desktop)
'''
marker = '\n\nif __name__ == "__main__":'
if text.count(marker) != 1:
    raise SystemExit("test marker missing")
source_test.write_text(text.replace(marker, insert + marker, 1))
