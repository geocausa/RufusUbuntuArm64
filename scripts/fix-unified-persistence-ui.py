#!/usr/bin/env python3
import pathlib

root = pathlib.Path(__file__).resolve().parents[1]
path = root / "gui/rufusarm64.py"
text = path.read_text()
old = "self.apply_inspection(self.inspection)"
count = text.count(old)
if count != 2:
    raise SystemExit(f"expected two stale callbacks, found {count}")
text = text.replace(old, "self.update_layout(self.inspection)")
path.write_text(text)

test = root / "gui/test_unified_persistence_ui.py"
source = test.read_text()
needle = "        self.assertIn('completion_checklist()', self.source)\n"
replacement = needle + "        self.assertNotIn('self.apply_inspection(', self.source)\n        self.assertGreaterEqual(self.source.count('self.update_layout(self.inspection)'), 2)\n"
if source.count(needle) != 1:
    raise SystemExit("test anchor missing")
test.write_text(source.replace(needle, replacement, 1))
