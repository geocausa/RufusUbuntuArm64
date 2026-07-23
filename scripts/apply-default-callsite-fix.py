#!/usr/bin/env python3
from pathlib import Path


def replace_once(path, old, new):
    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one replacement for {old.splitlines()[0]!r}, found {count}")
    file_path.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_once(
    "gui/rufusarm64.py",
    '''                partition_scheme = normalize_partition_scheme(self.partition_combo.get_active_id() or "gpt")
                target_system = normalize_target_system(self.target_system_combo.get_active_id() or "uefi")
                if target_system == "bios" and partition_scheme != "mbr":
                    raise ValueError("BIOS/CSM requires the MBR partition scheme.")
                filesystem = normalize_filesystem(self.filesystem_combo.get_active_id() or "auto")
                cluster_size = normalize_cluster_size(self.cluster_combo.get_active_id() or "auto")
''',
    '''                partition_scheme = normalize_partition_scheme(self.partition_combo.get_active_id() or DEFAULT_WINDOWS_PARTITION_SCHEME)
                target_system = normalize_target_system(self.target_system_combo.get_active_id() or DEFAULT_WINDOWS_TARGET_SYSTEM)
                if target_system == "bios" and partition_scheme == "gpt":
                    raise ValueError("BIOS/CSM cannot be combined with the GPT partition scheme.")
                filesystem = normalize_filesystem(self.filesystem_combo.get_active_id() or DEFAULT_WINDOWS_FILESYSTEM)
                cluster_size = normalize_cluster_size(self.cluster_combo.get_active_id() or DEFAULT_WINDOWS_CLUSTER_SIZE)
''',
)
replace_once(
    "gui/rufusarm64.py",
    '''        else:
            partition_scheme = "gpt"
            target_system = "uefi"
            filesystem = "auto"
            cluster_size = "auto"
            driver_folder = ""
            dbx_file = ""
            label = "RUFUSARM64"
            quick_format = True
            bad_block_check = False
''',
    '''        else:
            # Windows-only controls must never leak saved choices into raw or
            # persistent workflows. The privileged helper treats auto values as
            # neutral and rejects explicit Windows options for non-Windows media.
            partition_scheme = DEFAULT_WINDOWS_PARTITION_SCHEME
            target_system = DEFAULT_WINDOWS_TARGET_SYSTEM
            filesystem = DEFAULT_WINDOWS_FILESYSTEM
            cluster_size = DEFAULT_WINDOWS_CLUSTER_SIZE
            driver_folder = ""
            dbx_file = ""
            label = "RUFUSARM64"
            quick_format = DEFAULT_QUICK_FORMAT
            bad_block_check = DEFAULT_BAD_BLOCK_CHECK
''',
)
replace_once(
    "gui/test_default_parity.py",
    '''        self.assertIn('settings.get("bad_block_check", DEFAULT_BAD_BLOCK_CHECK)', source)
        self.assertIn('set_active(DEFAULT_PERSISTENCE_ENABLED)', source)
''',
    '''        self.assertIn('settings.get("bad_block_check", DEFAULT_BAD_BLOCK_CHECK)', source)
        self.assertIn('set_active(DEFAULT_PERSISTENCE_ENABLED)', source)
        self.assertIn('partition_scheme = DEFAULT_WINDOWS_PARTITION_SCHEME', source)
        self.assertIn('target_system = DEFAULT_WINDOWS_TARGET_SYSTEM', source)
        self.assertNotIn(''' + "'''" + '''        else:
            partition_scheme = "gpt"
            target_system = "uefi"
''' + "'''" + ''', source)
        self.assertIn('target_system == "bios" and partition_scheme == "gpt"', source)
''',
)
