#!/usr/bin/env python3
"""Apply the one-shot VHD/VHDX reserve contract repair, then remove this file."""

from pathlib import Path


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label} is missing or ambiguous: {count} matches")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_once(
    Path("gui/rufusarm64_device_qualify.py"),
    "    elif minimum <= 0 or minimum > required:\n",
    "    elif minimum > required:\n",
    "GTK container minimum guard",
)

replace_once(
    Path("gui/test_device_backup.py"),
    '                "container_minimum_bytes": 2 * 1024 * 1024,\n',
    '                "container_minimum_bytes": 0,\n',
    "GTK container plan fixture",
)
replace_once(
    Path("gui/test_device_backup.py"),
    '        self.assertIn("Destination filesystem: /home/user", summary)\n',
    '        self.assertIn("Destination filesystem: /home/user", summary)\n'
    '        self.assertNotIn("Minimum container estimate", summary)\n',
    "GTK summary assertion",
)

replace_once(
    Path("docs/rufusarm64-device-backup.1"),
    """source. Raw capture requires the source capacity. VHD and VHDX dry-run planning
uses QEMU's fully allocated bound for conservative free-space admission; the
smaller sparse-container estimate is informational only. Mounted removable
""",
    """source. Raw capture requires the source capacity. VHD and VHDX dry-run planning
requires the complete source capacity plus a 12.5% policy reserve, with a
minimum 64 MiB margin. No sparse-size saving is promised. Mounted removable
""",
    "manual allocation paragraph",
)
replace_once(
    Path("docs/rufusarm64-device-backup.1"),
    """Validate source metadata, format support, converter availability, destination
storage, conservative free-space bounds, and collision state without opening
""",
    """Validate source metadata, format support, converter availability, destination
storage, the explicit conservative reserve, and collision state without opening
""",
    "manual dry-run paragraph",
)
