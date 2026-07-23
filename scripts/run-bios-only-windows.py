#!/usr/bin/env python3
from pathlib import Path

patch_path = Path("scripts/apply-bios-only-windows.py")
text = patch_path.read_text(encoding="utf-8")
old = '''replace_once(
    "gui/rufusarm64.py",
    ''' + "'''" + '''        return {
        "metadata": {},
        "capabilities": {
''' + "'''" + ''',
    ''' + "'''" + '''        return {
        "metadata": {},
        "default_partition_scheme": "",
        "default_target_system": "",
        "capabilities": {
''' + "'''" + ''',
)'''
new = '''replace_once(
    "gui/rufusarm64.py",
    ''' + "'''" + '''    return {
        "metadata": {},
        "capabilities": {
''' + "'''" + ''',
    ''' + "'''" + '''    return {
        "metadata": {},
        "default_partition_scheme": "",
        "default_target_system": "",
        "capabilities": {
''' + "'''" + ''',
)'''
if text.count(old) != 1:
    raise SystemExit("could not adapt fallback-analysis dictionary anchor")
text = text.replace(old, new, 1)
exec(compile(text, str(patch_path), "exec"), {"__name__": "__main__", "__file__": str(patch_path)})
