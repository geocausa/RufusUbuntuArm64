#!/usr/bin/env python3
from pathlib import Path

# This wrapper corrects historical filename and automatic-label assumptions
# before executing the guarded product applicator.
applicator = Path("scripts/apply_unicode_volume_labels.py")
source = applicator.read_text(encoding="utf-8")
old = "internal/linuxmedia/extracted_loop_test.go"
new = "internal/linuxmedia/extracted_ntfs_loop_test.go"
if source.count(old) != 2:
    raise SystemExit(f"expected two NTFS loop path references, found {source.count(old)}")
source = source.replace(old, new)

auto_anchor = '''    if filesystem == "fat32":
        label = label.upper()
'''
auto_replacement = '''    if filesystem == "auto":
        try:
            return normalize_volume_label(label, "fat32")
        except ValueError:
            pass
    if filesystem == "fat32":
        label = label.upper()
'''
if source.count(auto_anchor) != 1:
    raise SystemExit(f"expected one automatic-label anchor, found {source.count(auto_anchor)}")
source = source.replace(auto_anchor, auto_replacement, 1)
exec(compile(source, str(applicator), "exec"), {"__name__": "__main__", "__file__": str(applicator)})
