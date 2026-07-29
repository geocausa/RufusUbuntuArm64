#!/usr/bin/env python3
from pathlib import Path

applicator = Path("scripts/apply_unicode_volume_labels.py")
source = applicator.read_text(encoding="utf-8")
old = "internal/linuxmedia/extracted_loop_test.go"
new = "internal/linuxmedia/extracted_ntfs_loop_test.go"
if source.count(old) != 2:
    raise SystemExit(f"expected two NTFS loop path references, found {source.count(old)}")
source = source.replace(old, new)
exec(compile(source, str(applicator), "exec"), {"__name__": "__main__", "__file__": str(applicator)})
