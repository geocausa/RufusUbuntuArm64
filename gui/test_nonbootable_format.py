import copy
import unittest

from rufusarm64_nonbootable import (
    build_dry_run_command,
    build_run_command,
    confirmation_phrase,
    normalize_plan,
    normalize_report,
    report_summary,
)


DEVICE_SIZE = 8 * 1024 * 1024 * 1024
PARTITION_SIZE = DEVICE_SIZE - 2 * 1024 * 1024


def sample_plan():
    plan = {
        "schema": 1,
        "mode": "non-bootable",
        "bootable": False,
        "destructive": True,
        "device_path": "/dev/sdb",
        "expected_identity": "identity-token",
        "device_size_bytes": DEVICE_SIZE,
        "logical_sector_size": 512,
        "scheme": "gpt",
        "filesystem": "fat32",
        "filesystem_display": "FAT32",
        "label": "DATA",
        "partition_number": 1,
        "partition_start_bytes": 1024 * 1024,
        "partition_size_bytes": PARTITION_SIZE,
        "partition_type": "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
        "required_tools": ["sfdisk", "blockdev", "mkfs.vfat", "fsck.vfat"],
        "warnings": [
            "This operation erases the complete selected drive.",
            "The resulting media is data-only and is not claimed bootable.",
        ],
    }
    table = {
        "schema": 1,
        "scheme": "gpt",
        "device_path": "/dev/sdb",
        "sector_size": 512,
        "partition_number": 1,
        "start_sector": 2048,
        "size_sectors": PARTITION_SIZE // 512,
        "partition_type": plan["partition_type"],
        "filesystem": "fat32",
        "filesystem_display": "FAT32",
        "label": "DATA",
    }
    return {
        "device": {"path": "/dev/sdb", "size": DEVICE_SIZE, "vendor": "Test", "model": "USB"},
        "identity": "identity-token",
        "plan": plan,
        "partition_table": table,
        "confirmation": "FORMAT /dev/sdb AS FAT32 USING GPT LABEL DATA",
    }


class NonBootableFormatContractTests(unittest.TestCase):
    def test_commands_keep_dry_run_unprivileged_and_execution_identity_bound(self):
        dry = build_dry_run_command(
            "/usr/lib/rufusarm64/rufusarm64-nonbootable-format",
            "/dev/sdb",
            "identity-token",
            "gpt",
            "fat32",
            "DATA",
        )
        self.assertEqual(dry[0], "/usr/lib/rufusarm64/rufusarm64-nonbootable-format")
        self.assertIn("--dry-run", dry)
        self.assertIn("--json", dry)
        self.assertNotIn("pkexec", " ".join(dry))

        run = build_run_command(
            "/usr/bin/pkexec",
            "/usr/lib/rufusarm64/rufusarm64-nonbootable-format",
            "/dev/sdb",
            "identity-token",
            "gpt",
            "fat32",
            "DATA",
            "/run/user/1000/rufusarm64.cancel",
        )
        self.assertEqual(run[:2], ["/usr/bin/pkexec", "/usr/lib/rufusarm64/rufusarm64-nonbootable-format"])
        self.assertIn("--expected-identity", run)
        self.assertIn("--cancel-file", run)
        self.assertIn("--yes", run)
        self.assertIn("--json", run)
        self.assertNotIn("--allow-fixed", run)
        self.assertNotIn("--no-unmount", run)

    def test_plan_requires_exact_geometry_table_and_confirmation(self):
        payload = sample_plan()
        normalized = normalize_plan(payload)
        self.assertEqual(confirmation_phrase(normalized), payload["confirmation"])

        for mutation in (
            lambda value: value["plan"].__setitem__("bootable", True),
            lambda value: value["plan"].__setitem__("partition_type", "0FC63DAF-8483-4772-8E79-3D69D8477DE4"),
            lambda value: value["plan"].__setitem__("required_tools", ["sfdisk", "blockdev", "mkfs.ext4", "e2fsck"]),
            lambda value: value["plan"].__setitem__("warnings", ["This operation erases the complete selected drive."]),
            lambda value: value["plan"].__setitem__("label", "data"),
            lambda value: value["partition_table"].__setitem__("size_sectors", 1),
            lambda value: value.__setitem__("identity", "other-device"),
            lambda value: value.__setitem__("confirmation", "FORMAT /dev/sdb AS FAT32 USING GPT WITHOUT A LABEL"),
        ):
            altered = copy.deepcopy(payload)
            mutation(altered)
            with self.assertRaises(ValueError):
                normalize_plan(altered)

    def test_success_report_must_match_reviewed_filesystem(self):
        reviewed = sample_plan()
        report = {
            "schema": 1,
            "mode": "non-bootable",
            "status": "passed",
            "plan": copy.deepcopy(reviewed["plan"]),
            "partition_table": copy.deepcopy(reviewed["partition_table"]),
            "filesystem": {
                "path": "/dev/sdb1",
                "type": "fat32",
                "label": "DATA",
                "uuid": "ABCD-1234",
                "size_bytes": PARTITION_SIZE,
                "read_only": False,
                "parent_path": "/dev/sdb",
            },
            "started_at": "2026-07-20T00:00:00Z",
            "completed_at": "2026-07-20T00:01:00Z",
            "media_changed": True,
            "reusable": True,
            "bootable": False,
        }
        normalized = normalize_report(report, reviewed)
        self.assertEqual(normalized["status"], "passed")
        self.assertIn("not bootable", report_summary(normalized))

        altered = copy.deepcopy(report)
        altered["filesystem"]["type"] = "ext4"
        with self.assertRaises(ValueError):
            normalize_report(altered, reviewed)

        altered = copy.deepcopy(report)
        altered["completed_at"] = "2026-07-19T23:59:59Z"
        with self.assertRaises(ValueError):
            normalize_report(altered, reviewed)

    def test_cancelled_report_distinguishes_untouched_and_changed_media(self):
        reviewed = sample_plan()
        base = {
            "schema": 1,
            "mode": "non-bootable",
            "status": "cancelled",
            "plan": copy.deepcopy(reviewed["plan"]),
            "partition_table": copy.deepcopy(reviewed["partition_table"]),
            "started_at": "2026-07-20T00:00:00Z",
            "completed_at": "2026-07-20T00:00:01Z",
            "media_changed": False,
            "reusable": False,
            "bootable": False,
            "failure": {"phase": "preflight", "message": "cancelled", "media_changed": False},
        }
        untouched = normalize_report(base, reviewed)
        self.assertIn("was not changed", report_summary(untouched))

        changed = copy.deepcopy(base)
        changed["media_changed"] = True
        changed["failure"] = {"phase": "format", "message": "cancelled", "media_changed": True}
        normalized = normalize_report(changed, reviewed)
        self.assertIn("must be reformatted", report_summary(normalized))


if __name__ == "__main__":
    unittest.main()
