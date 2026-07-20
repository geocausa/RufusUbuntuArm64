from pathlib import Path


dialog = Path("gui/rufusarm64_nonbootable_dialog.py")
text = dialog.read_text(encoding="utf-8")
old_path = 'NONBOOTABLE_FORMATTER = "/usr/bin/rufusarm64-nonbootable-format"'
new_path = 'NONBOOTABLE_FORMATTER = "/usr/lib/rufusarm64/rufusarm64-nonbootable-format"'
if text.count(old_path) != 1:
    raise SystemExit("formatter path marker is not unique")
text = text.replace(old_path, new_path, 1)
start = text.index("    def current_choices(self):\n")
end = text.index("\n    def selection_changed", start)
replacement = (
    "    def current_choices(self):\n"
    "        scheme = self.scheme.get_active_id() or \"gpt\"\n"
    "        filesystem = self.filesystem.get_active_id() or \"fat32\"\n"
    "        label = self.volume_label.get_text()\n"
    "        if filesystem == \"fat32\":\n"
    "            label = label.upper()\n"
    "        return scheme, filesystem, label\n"
)
dialog.write_text(text[:start] + replacement + text[end:], encoding="utf-8")

tests = Path("gui/test_nonbootable_format.py")
text = tests.read_text(encoding="utf-8")
text = text.replace(
    "/usr/bin/rufusarm64-nonbootable-format",
    "/usr/lib/rufusarm64/rufusarm64-nonbootable-format",
)
tests.write_text(text, encoding="utf-8")

structure = Path("gui/test_nonbootable_dialog.py")
text = structure.read_text(encoding="utf-8")
marker = '        self.assertIn("/usr/lib/rufusarm64/rufusarm64-nonbootable-format", self.policy_source)\n'
assertion = '        self.assertIn(\'NONBOOTABLE_FORMATTER = "/usr/lib/rufusarm64/rufusarm64-nonbootable-format"\', self.dialog_source)\n'
if text.count(marker) != 1:
    raise SystemExit("policy assertion marker is not unique")
structure.write_text(text.replace(marker, marker + assertion, 1), encoding="utf-8")
