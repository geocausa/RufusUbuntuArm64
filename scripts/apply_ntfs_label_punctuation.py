#!/usr/bin/env python3
from pathlib import Path


def replace_once(path, old, new):
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one guarded match, found {count}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_once(
    "gui/rufusarm64_logic.py",
    '''    if any(char in '"*/:<>?\\\\|' for char in label):
        raise ValueError("The NTFS volume label contains an unsupported character.")
    if _utf16_code_units(label) > 32:
''',
    '''    if _utf16_code_units(label) > 32:
''',
)
replace_once(
    "gui/test_logic.py",
    '''        self.assertEqual(normalize_volume_label("Rufus_日本", "ntfs"), "Rufus_日本")
''',
    '''        self.assertEqual(normalize_volume_label("Rufus_日本", "ntfs"), "Rufus_日本")
        self.assertEqual(normalize_volume_label('Rufus:*?/\\\\|<>"', "ntfs"), 'Rufus:*?/\\\\|<>"')
''',
)
replace_once(
    "internal/windowsmedia/windowsmedia_test.go",
    '''\tntfs := "Rufus_日本"
\tgot, err := normalizeVolumeLabel(ntfs, "ntfs")
\tif err != nil || got != ntfs {
\t\tt.Fatalf("NTFS label=%q err=%v", got, err)
\t}
''',
    '''\tfor _, ntfs := range []string{"Rufus_日本", `Rufus:*?/\\\\|<>"`} {
\t\tgot, err := normalizeVolumeLabel(ntfs, "ntfs")
\t\tif err != nil || got != ntfs {
\t\t\tt.Fatalf("NTFS label=%q err=%v", got, err)
\t\t}
\t}
''',
)
replace_once(
    "internal/nonbootable/backend_loop_test.go",
    'label: "Rufus-Été"',
    'label: "Rufus:*?-Été"',
)
replace_once(
    "internal/linuxmedia/extracted_ntfs_loop_test.go",
    '"Rufus-Été-MBR"',
    '"Rufus:*?-Été-MBR"',
)
replace_once(
    "internal/linuxmedia/extracted_ntfs_loop_test.go",
    '"Rufus-Été-GPT"',
    '"Rufus:*?-Été-GPT"',
)

print("NTFS punctuation parity applied successfully")
