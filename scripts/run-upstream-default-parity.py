#!/usr/bin/env python3
from pathlib import Path

patch_path = Path("scripts/apply-upstream-default-parity.py")
text = patch_path.read_text(encoding="utf-8")
text = text.replace(
    'raise SystemExit(f"{path}: expected one replacement, found {count}")',
    'raise SystemExit(f"{path}: expected one replacement for {old.splitlines()[0]!r}, found {count}")',
    1,
)

old = '''replace_once("gui/rufusarm64.py", '        self.persistence_enabled.set_active(False)\\n', '        self.persistence_enabled.set_active(DEFAULT_PERSISTENCE_ENABLED)\\n')'''
new = '''persistence_path = Path("gui/rufusarm64.py")
persistence_text = persistence_path.read_text(encoding="utf-8")
persistence_old = "        self.persistence_enabled.set_active(False)\\n"
persistence_new = "        self.persistence_enabled.set_active(DEFAULT_PERSISTENCE_ENABLED)\\n"
if persistence_text.count(persistence_old) != 2:
    raise SystemExit(f"gui/rufusarm64.py: expected two persistence-default replacements, found {persistence_text.count(persistence_old)}")
persistence_path.write_text(persistence_text.replace(persistence_old, persistence_new), encoding="utf-8")'''
if text.count(old) != 1:
    raise SystemExit("default-parity adapter could not find the persistence replacement")
text = text.replace(old, new, 1)

old = '''for _ in range(2):
    replace_once(
        "gui/rufusarm64.py",
        ''' + "'''" + '''            if self.partition_combo.get_active_id() in {"gpt", "mbr"}:
                self.windows_partition_scheme = self.partition_combo.get_active_id()
            if self.target_system_combo.get_active_id() in {"uefi", "bios"}:
                self.windows_target_system = self.target_system_combo.get_active_id()
''' + "'''" + ''',
        ''' + "'''" + '''            if self.partition_combo.get_active_id() in {"auto", "gpt", "mbr"}:
                self.windows_partition_scheme = self.partition_combo.get_active_id()
            if self.target_system_combo.get_active_id() in {"auto", "uefi", "bios"}:
                self.windows_target_system = self.target_system_combo.get_active_id()
''' + "'''" + ''',
    )'''
new = '''layout_path = Path("gui/rufusarm64.py")
layout_text = layout_path.read_text(encoding="utf-8")
layout_old = ''' + "'''" + '''            if self.partition_combo.get_active_id() in {"gpt", "mbr"}:
                self.windows_partition_scheme = self.partition_combo.get_active_id()
            if self.target_system_combo.get_active_id() in {"uefi", "bios"}:
                self.windows_target_system = self.target_system_combo.get_active_id()
''' + "'''" + '''
layout_new = ''' + "'''" + '''            if self.partition_combo.get_active_id() in {"auto", "gpt", "mbr"}:
                self.windows_partition_scheme = self.partition_combo.get_active_id()
            if self.target_system_combo.get_active_id() in {"auto", "uefi", "bios"}:
                self.windows_target_system = self.target_system_combo.get_active_id()
''' + "'''" + '''
if layout_text.count(layout_old) != 2:
    raise SystemExit(f"gui/rufusarm64.py: expected two layout-state replacements, found {layout_text.count(layout_old)}")
layout_path.write_text(layout_text.replace(layout_old, layout_new), encoding="utf-8")'''
if text.count(old) != 1:
    raise SystemExit("default-parity adapter could not find the layout-state loop")
text = text.replace(old, new, 1)

exec(compile(text, str(patch_path), "exec"), {"__name__": "__main__", "__file__": str(patch_path)})
