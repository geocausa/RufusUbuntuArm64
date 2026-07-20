from pathlib import Path


logic = Path("gui/rufusarm64_nonbootable.py")
text = logic.read_text(encoding="utf-8")
text = text.replace("import os\n", "from datetime import datetime\nimport os\nimport unicodedata\n", 1)
marker = '''FILESYSTEM_DISPLAYS = {
    "fat32": "FAT32",
    "exfat": "exFAT",
    "ntfs": "NTFS",
    "ext4": "ext4",
}
'''
addition = marker + '''FILESYSTEM_TOOLS = {
    "fat32": ["sfdisk", "blockdev", "mkfs.vfat", "fsck.vfat"],
    "exfat": ["sfdisk", "blockdev", "mkfs.exfat", "fsck.exfat"],
    "ntfs": ["sfdisk", "blockdev", "mkfs.ntfs", "ntfsfix"],
    "ext4": ["sfdisk", "blockdev", "mkfs.ext4", "e2fsck"],
}
PARTITION_TYPES = {
    ("gpt", "fat32"): "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
    ("gpt", "exfat"): "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
    ("gpt", "ntfs"): "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
    ("gpt", "ext4"): "0FC63DAF-8483-4772-8E79-3D69D8477DE4",
    ("mbr", "fat32"): "0c",
    ("mbr", "exfat"): "07",
    ("mbr", "ntfs"): "07",
    ("mbr", "ext4"): "83",
}
SAFETY_WARNINGS = [
    "This operation erases the complete selected drive.",
    "The resulting media is data-only and is not claimed bootable.",
]
ALIGNMENT_BYTES = 1024 * 1024
TAIL_RESERVE_BYTES = 1024 * 1024
MAX_FAT32_BYTES = 2 * 1024 * 1024 * 1024 * 1024
'''
if text.count(marker) != 1:
    raise SystemExit("filesystem display marker is not unique")
text = text.replace(marker, addition, 1)

old = '''    status = _text(value.get("status"), "Formatting report is missing its status.")
    if status not in STATUSES:
        raise ValueError("Formatting report contains an invalid status.")
    if value.get("bootable") is not False:
        raise ValueError("Formatting report must not claim bootable media.")

    plan = _normalize_plan_fields(value.get("plan"))
'''
new = '''    status = _text(value.get("status"), "Formatting report is missing its status.")
    if status not in STATUSES:
        raise ValueError("Formatting report contains an invalid status.")
    if value.get("bootable") is not False:
        raise ValueError("Formatting report must not claim bootable media.")
    started_at = _timestamp(value.get("started_at"), "start time")
    completed_at = _timestamp(value.get("completed_at"), "completion time")
    if completed_at < started_at:
        raise ValueError("Formatting report completion time precedes its start time.")

    plan = _normalize_plan_fields(value.get("plan"))
'''
if text.count(old) != 1:
    raise SystemExit("report status marker is not unique")
text = text.replace(old, new, 1)

old = '''            "bootable": False,
        }
    )
'''
new = '''            "bootable": False,
            "started_at": value["started_at"],
            "completed_at": value["completed_at"],
        }
    )
'''
if text.count(old) != 1:
    raise SystemExit("report normalized marker is not unique")
text = text.replace(old, new, 1)

old = '''    device_path = _text(plan.get("device_path"), "Formatting plan is missing its device path.")
    if not device_path.startswith("/dev/"):
        raise ValueError("Formatting plan contains an invalid device path.")
'''
new = '''    device_path = _text(plan.get("device_path"), "Formatting plan is missing its device path.")
    if not os.path.isabs(device_path) or not device_path.startswith("/dev/") or os.path.normpath(device_path) != device_path:
        raise ValueError("Formatting plan contains an invalid device path.")
'''
if text.count(old) != 1:
    raise SystemExit("device path marker is not unique")
text = text.replace(old, new, 1)

old = '''    start = _positive_integer(plan.get("partition_start_bytes"), "partition start")
    size = _positive_integer(plan.get("partition_size_bytes"), "partition size")
    if start % sector_size or size % sector_size or start + size > device_size:
        raise ValueError("Formatting plan contains invalid partition geometry.")
    if _integer(plan.get("partition_number"), "partition number") != 1:
        raise ValueError("Formatting plan must contain exactly one data partition.")
    partition_type = _text(plan.get("partition_type"), "Formatting plan is missing its partition type.")
    tools = plan.get("required_tools")
    warnings = plan.get("warnings")
    if not isinstance(tools, list) or len(tools) != 4 or not all(isinstance(item, str) and item for item in tools):
        raise ValueError("Formatting plan contains an invalid required-tool contract.")
    if not isinstance(warnings, list) or not warnings or not all(isinstance(item, str) and item for item in warnings):
        raise ValueError("Formatting plan is missing its safety warnings.")
'''
new = '''    start = _positive_integer(plan.get("partition_start_bytes"), "partition start")
    size = _positive_integer(plan.get("partition_size_bytes"), "partition size")
    expected_start = ((ALIGNMENT_BYTES + sector_size - 1) // sector_size) * sector_size
    usable_end = ((device_size - TAIL_RESERVE_BYTES) // sector_size) * sector_size
    expected_size = usable_end - expected_start
    if start != expected_start or size != expected_size or start + size > device_size:
        raise ValueError("Formatting plan contains non-canonical partition geometry.")
    if filesystem == "fat32" and size > MAX_FAT32_BYTES:
        raise ValueError("Formatting plan exceeds the FAT32 compatibility boundary.")
    if scheme == "mbr" and (start + size) // sector_size > 1 << 32:
        raise ValueError("Formatting plan exceeds the MBR address space.")
    if _integer(plan.get("partition_number"), "partition number") != 1:
        raise ValueError("Formatting plan must contain exactly one data partition.")
    partition_type = _text(plan.get("partition_type"), "Formatting plan is missing its partition type.")
    if partition_type != PARTITION_TYPES[(scheme, filesystem)]:
        raise ValueError("Formatting plan contains an inconsistent partition type.")
    label = _normalize_label(plan.get("label"), filesystem)
    tools = plan.get("required_tools")
    warnings = plan.get("warnings")
    if tools != FILESYSTEM_TOOLS[filesystem]:
        raise ValueError("Formatting plan contains an invalid required-tool contract.")
    if warnings != SAFETY_WARNINGS:
        raise ValueError("Formatting plan safety warnings are incomplete or altered.")
'''
if text.count(old) != 1:
    raise SystemExit("plan contract marker is not unique")
text = text.replace(old, new, 1)
text = text.replace('        "label": str(plan.get("label") or ""),\n', '        "label": label,\n', 1)

marker = '''def _mapping(value, message):
'''
helpers = '''def _normalize_label(value, filesystem):
    if not isinstance(value, str):
        raise ValueError("Formatting label must be text.")
    if value.strip() != value:
        raise ValueError("Formatting label must not have leading or trailing whitespace.")
    if any(unicodedata.category(character) == "Cc" for character in value):
        raise ValueError("Formatting label must not contain control characters.")
    if filesystem == "fat32":
        if value != value.upper():
            raise ValueError("FAT32 label must be canonical uppercase text.")
        allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-")
        if any(character not in allowed for character in value) or len(value.encode("utf-8")) > 11:
            raise ValueError("FAT32 label violates its canonical on-disk contract.")
    elif filesystem == "ext4":
        if len(value.encode("utf-8")) > 16:
            raise ValueError("ext4 label exceeds 16 bytes.")
    else:
        limit = 15 if filesystem == "exfat" else 32
        units = len(value.encode("utf-16-le")) // 2
        if units > limit:
            raise ValueError(f"{FILESYSTEM_DISPLAYS[filesystem]} label exceeds {limit} UTF-16 code units.")
    return value


def _timestamp(value, label):
    text = _text(value, f"Formatting report is missing its {label}.")
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Formatting report has an invalid {label}.") from exc


'''
if text.count(marker) != 1:
    raise SystemExit("mapping marker is not unique")
text = text.replace(marker, helpers + marker, 1)
logic.write_text(text, encoding="utf-8")

tests = Path("gui/test_nonbootable_format.py")
text = tests.read_text(encoding="utf-8")
old = '''            lambda value: value["plan"].__setitem__("bootable", True),
            lambda value: value["partition_table"].__setitem__("size_sectors", 1),
            lambda value: value.__setitem__("identity", "other-device"),
            lambda value: value.__setitem__("confirmation", "FORMAT /dev/sdb AS FAT32 USING GPT WITHOUT A LABEL"),
'''
new = '''            lambda value: value["plan"].__setitem__("bootable", True),
            lambda value: value["plan"].__setitem__("partition_type", "0FC63DAF-8483-4772-8E79-3D69D8477DE4"),
            lambda value: value["plan"].__setitem__("required_tools", ["sfdisk", "blockdev", "mkfs.ext4", "e2fsck"]),
            lambda value: value["plan"].__setitem__("warnings", ["This operation erases the complete selected drive."]),
            lambda value: value["plan"].__setitem__("label", "data"),
            lambda value: value["partition_table"].__setitem__("size_sectors", 1),
            lambda value: value.__setitem__("identity", "other-device"),
            lambda value: value.__setitem__("confirmation", "FORMAT /dev/sdb AS FAT32 USING GPT WITHOUT A LABEL"),
'''
if text.count(old) != 1:
    raise SystemExit("tamper test marker is not unique")
text = text.replace(old, new, 1)
old = '''        altered = copy.deepcopy(report)
        altered["filesystem"]["type"] = "ext4"
        with self.assertRaises(ValueError):
            normalize_report(altered, reviewed)
'''
new = '''        altered = copy.deepcopy(report)
        altered["filesystem"]["type"] = "ext4"
        with self.assertRaises(ValueError):
            normalize_report(altered, reviewed)

        altered = copy.deepcopy(report)
        altered["completed_at"] = "2026-07-19T23:59:59Z"
        with self.assertRaises(ValueError):
            normalize_report(altered, reviewed)
'''
if text.count(old) != 1:
    raise SystemExit("report tamper marker is not unique")
tests.write_text(text.replace(old, new, 1), encoding="utf-8")
