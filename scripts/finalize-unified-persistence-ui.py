#!/usr/bin/env python3
import pathlib

root = pathlib.Path(__file__).resolve().parents[1]
path = root / "gui/rufusarm64.py"
text = path.read_text()
old = 'layout_summary = f"GPT / UEFI / FAT32 boot + {human_bytes(self.persistence_plan["size"])} ext4 persistence"'
new = 'layout_summary = f"GPT / UEFI / FAT32 boot + {human_bytes(self.persistence_plan[\'size\'])} ext4 persistence"'
if text.count(old) != 1:
    raise SystemExit(f"layout quote anchor count {text.count(old)}")
text = text.replace(old, new, 1)

anchor = '''        if not os.path.isfile(PKEXEC) or not os.access(PKEXEC, os.X_OK):
            self.cancel_path = None
            self.active_job = ""
            self.set_busy(False)
            self.message("Ubuntu administrator authentication (pkexec) is not installed.", Gtk.MessageType.ERROR)
            return
        try:
'''
replacement = '''        if not os.path.isfile(PKEXEC) or not os.access(PKEXEC, os.X_OK):
            self.cancel_path = None
            self.active_job = ""
            self.set_busy(False)
            self.message("Ubuntu administrator authentication (pkexec) is not installed.", Gtk.MessageType.ERROR)
            return
        if persistence_requested and not os.access(PERSISTENCE_HELPER, os.X_OK):
            self.cancel_path = None
            self.active_job = ""
            self.set_busy(False)
            self.message("The package-owned persistence helper is not installed or executable.", Gtk.MessageType.ERROR)
            return
        try:
'''
if text.count(anchor) != 1:
    raise SystemExit(f"helper preflight anchor count {text.count(anchor)}")
text = text.replace(anchor, replacement, 1)
path.write_text(text)

test = root / "gui/test_unified_persistence_ui.py"
source = test.read_text()
insert = '''
    def test_persistence_helper_is_checked_before_launch(self):
        self.assertIn("persistence_requested and not os.access(PERSISTENCE_HELPER, os.X_OK)", self.source)
        self.assertIn("package-owned persistence helper is not installed or executable", self.source)

    def test_layout_fstring_uses_python_310_compatible_quotes(self):
        self.assertIn("self.persistence_plan['size']", self.source)
'''
marker = '\n\nif __name__ == "__main__":'
if source.count(marker) != 1:
    raise SystemExit("test marker missing")
test.write_text(source.replace(marker, insert + marker, 1))
