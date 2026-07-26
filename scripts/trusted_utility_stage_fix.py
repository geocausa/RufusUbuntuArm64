#!/usr/bin/env python3
"""Adjust repeated test anchors while preserving unique production anchors."""

from pathlib import Path

path = Path("scripts/trusted_utility_stage.py")
text = path.read_text(encoding="utf-8")
anchor = '''def replace_once(path, old, new, label):
    source = path.read_text(encoding="utf-8")
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one source anchor, found {count}")
    path.write_text(source.replace(old, new), encoding="utf-8")
'''
replacement = anchor + '''

def replace_first(path, old, new, label):
    source = path.read_text(encoding="utf-8")
    if old not in source:
        raise SystemExit(f"{label}: source anchor is missing")
    path.write_text(source.replace(old, new, 1), encoding="utf-8")
'''
if text.count(anchor) != 1:
    raise SystemExit("replace helper anchor changed")
text = text.replace(anchor, replacement)
for label in (
    "first device PATH injection",
    "second device PATH injection",
    "backing disk utility injection",
    "umount utility injection",
):
    marker = f'        "{label}",\n    )'
    end = text.find(marker)
    if end < 0:
        raise SystemExit(f"missing repeated-anchor call: {label}")
    start = text.rfind("    replace_once(\n", 0, end)
    if start < 0:
        raise SystemExit(f"missing replace_once call: {label}")
    text = text[:start] + text[start:].replace("    replace_once(\n", "    replace_first(\n", 1)
path.write_text(text, encoding="utf-8")
