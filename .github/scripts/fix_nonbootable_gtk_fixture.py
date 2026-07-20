from pathlib import Path

path = Path("gui/test_nonbootable_format.py")
text = path.read_text(encoding="utf-8")
old = '        "warnings": ["This operation erases the complete selected drive."],\n'
new = (
    '        "warnings": [\n'
    '            "This operation erases the complete selected drive.",\n'
    '            "The resulting media is data-only and is not claimed bootable.",\n'
    '        ],\n'
)
if text.count(old) != 1:
    raise SystemExit("sample warning fixture marker is not unique")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
