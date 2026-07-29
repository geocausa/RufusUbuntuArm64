#!/usr/bin/env python3
from pathlib import Path

applicator = Path("scripts/apply_unicode_blkid_readback.py")
exec(compile(applicator.read_text(encoding="utf-8"), str(applicator), "exec"), {
    "__name__": "__main__",
    "__file__": str(applicator),
})


def replace_once(path, old, new):
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one guarded match, found {count}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_once(
    "gui/rufusarm64_persistence_logic.py",
    '''def normalize_boot_label(value):
    label = str(value or "RUFUS-LIVE").strip().upper() or "RUFUS-LIVE"
    if not LABEL_PATTERN.fullmatch(label):
''',
    '''def normalize_boot_label(value):
    raw = "" if value is None else str(value)
    label = raw if raw != "" else "RUFUS-LIVE"
    if label.strip() != label:
        raise ValueError("The boot volume label must not have leading or trailing whitespace.")
    label = label.upper()
    if not LABEL_PATTERN.fullmatch(label):
''',
)
replace_once(
    "gui/test_persistence_logic.py",
    '''    def test_label_validation(self):
        self.assertEqual(normalize_boot_label("rufus-live"), "RUFUS-LIVE")
        with self.assertRaises(ValueError):
            normalize_boot_label("TOO-LONG-LABEL")
''',
    '''    def test_label_validation(self):
        self.assertEqual(normalize_boot_label("rufus-live"), "RUFUS-LIVE")
        self.assertEqual(normalize_boot_label(""), "RUFUS-LIVE")
        for value in ("TOO-LONG-LABEL", " rufus-live", "rufus-live ", "RUFUS/USB"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    normalize_boot_label(value)
''',
)

print("Persistent FAT label review aligned successfully")
