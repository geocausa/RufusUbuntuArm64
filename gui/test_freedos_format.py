import copy
import unittest

from rufusarm64_freedos import (
    FREEDOS_WARNINGS,
    VERIFICATION_SCOPE,
    build_dry_run_command,
    build_run_command,
    confirmation_phrase,
    normalize_plan,
    normalize_report,
    plan_summary,
    report_summary,
)


DEVICE_SIZE = 8 * 1024 * 1024 * 1024
SECTOR_SIZE = 512
START_SECTOR = 2048
TAIL_SECTORS = 2048
PARTITION_SECTORS = DEVICE_SIZE // SECTOR_SIZE - START_SECTOR - TAIL_SECTORS
PARTITION_SIZE = PARTITION_SECTORS * SECTOR_SIZE
MUTATION_BYTES = 10 * 1024 * 1024
UNTOUCHED_BYTES = DEVICE_SIZE - MUTATION_BYTES


def sample_plan():
    media = {
        "schema": 1,
        "disk_size_bytes": DEVICE_SIZE,
        "logical_sector_size": SECTOR_SIZE,
        "partition_start_sector": START_SECTOR,
        "partition_sector_count": PARTITION_SECTORS,
        "sectors_per_cluster": 8,
        "sectors_per_track": 63,
        "heads": 255,
        "label": "FREEDOS",
    }
    plan = {
        "schema": 2,
        "mode": "freedos",
        "bootable": True,
        "destructive": True,
        "target_cpu": "x86",
        "firmware": "BIOS or UEFI Legacy/CSM",
        "distribution": "FreeDOS 1.4",
        "device_path": "/dev/sdb",
        "expected_identity": "identity-token",
        "device_size_bytes": DEVICE_SIZE,
        "logical_sector_size": SECTOR_SIZE,
        "partition_number": 1,
        "partition_start_bytes": START_SECTOR * SECTOR_SIZE,
        "partition_size_bytes": PARTITION_SIZE,
        "partition_type": "0c",
        "filesystem": "FAT32",
        "label": "FREEDOS",
        "mutation_bytes": MUTATION_BYTES,
        "verification_bytes": MUTATION_BYTES,
        "untouched_bytes": UNTOUCHED_BYTES,
        "media": media,
        "warnings": list(FREEDOS_WARNINGS),
    }
    return {
        "device": {
            "path": "/dev/sdb",
            "size": DEVICE_SIZE,
            "vendor": "Test",
            "model": "USB",
        },
        "identity": "identity-token",
        "plan": plan,
        "confirmation": "WRITE FREEDOS 1.4 TO /dev/sdb FOR X86 BIOS LEGACY",
    }


class FreeDOSFormatContractTests(unittest.TestCase):
    def test_commands_keep_planning_unprivileged_and_execution_guarded(self):
        dry = build_dry_run_command(
            "/usr/lib/rufusarm64/rufusarm64-freedos-format",
            "/dev/sdb",
            "identity-token",
            "FREEDOS",
        )
        self.assertEqual(dry[0], "/usr/lib/rufusarm64/rufusarm64-freedos-format")
        self.assertIn("--dry-run", dry)
        self.assertIn("--json", dry)
        self.assertNotIn("pkexec", " ".join(dry))

        run = build_run_command(
            "/usr/bin/pkexec",
            "/usr/lib/rufusarm64/rufusarm64-freedos-format",
            "/dev/sdb",
            "identity-token",
            "FREEDOS",
            "/run/user/1000/rufusarm64-freedos.cancel",
        )
        self.assertEqual(run[:2], ["/usr/bin/pkexec", "/usr/lib/rufusarm64/rufusarm64-freedos-format"])
        self.assertIn("--expected-identity", run)
        self.assertIn("--cancel-file", run)
        self.assertIn("--yes", run)
        self.assertIn("--json", run)
        self.assertNotIn("--allow-fixed", run)
        self.assertNotIn("--no-unmount", run)

    def test_plan_requires_exact_platform_geometry_extent_warning_and_confirmation_contract(self):
        payload = sample_plan()
        normalized = normalize_plan(payload)
        self.assertEqual(confirmation_phrase(normalized), payload["confirmation"])
        summary = plan_summary(normalized)
        self.assertIn("Fast creation I/O", summary)
        self.assertIn("unallocated data remains untouched", summary)
        self.assertIn("Check USB", summary)
        self.assertNotIn("writes the full", summary)

        mutations = (
            lambda value: value["plan"].__setitem__("target_cpu", "arm64"),
            lambda value: value["plan"].__setitem__("firmware", "UEFI"),
            lambda value: value["plan"].__setitem__("bootable", False),
            lambda value: value["plan"].__setitem__("partition_type", "ef"),
            lambda value: value["plan"]["media"].__setitem__("partition_start_sector", 4096),
            lambda value: value["plan"]["media"].__setitem__("sectors_per_cluster", 16),
            lambda value: value["plan"].__setitem__("mutation_bytes", MUTATION_BYTES + 1),
            lambda value: value["plan"].__setitem__("verification_bytes", MUTATION_BYTES + 1),
            lambda value: value["plan"].__setitem__("untouched_bytes", UNTOUCHED_BYTES - 1),
            lambda value: value["plan"].__setitem__("warnings", FREEDOS_WARNINGS[:-1]),
            lambda value: value["plan"].__setitem__("label", "freedos"),
            lambda value: value.__setitem__("identity", "other-device"),
            lambda value: value.__setitem__("confirmation", "WRITE FREEDOS TO /dev/sdb"),
        )
        for mutation in mutations:
            altered = copy.deepcopy(payload)
            mutation(altered)
            with self.assertRaises(ValueError):
                normalize_plan(altered)

    def test_success_report_requires_required_extent_readback_and_exact_reviewed_plan(self):
        reviewed = sample_plan()
        report = {
            "schema": 2,
            "status": "succeeded",
            "phase": "complete",
            "plan": copy.deepcopy(reviewed["plan"]),
            "started_at": "2026-07-20T00:00:00Z",
            "completed_at": "2026-07-20T00:01:00Z",
            "bytes_written": MUTATION_BYTES,
            "bytes_verified": MUTATION_BYTES,
            "verification_scope": VERIFICATION_SCOPE,
            "sha256": "a" * 64,
            "media_changed": True,
            "verified": True,
            "reusable": True,
        }
        normalized = normalize_report(report, reviewed)
        self.assertEqual(normalized["status"], "succeeded")
        summary = report_summary(normalized)
        self.assertIn("x86 BIOS", summary)
        self.assertIn("not boot ARM64", summary)
        self.assertIn("Required boot/filesystem extents", summary)
        self.assertIn("Unallocated data was not used as a device test", summary)

        for mutation in (
            lambda value: value.__setitem__("bytes_written", MUTATION_BYTES - 1),
            lambda value: value.__setitem__("bytes_verified", MUTATION_BYTES - 1),
            lambda value: value.__setitem__("verification_scope", "whole-device"),
            lambda value: value.__setitem__("sha256", "A" * 64),
            lambda value: value.__setitem__("verified", False),
            lambda value: value.__setitem__("reusable", False),
            lambda value: value["plan"].__setitem__("label", "OTHER"),
        ):
            altered = copy.deepcopy(report)
            mutation(altered)
            with self.assertRaises(ValueError):
                normalize_report(altered, reviewed)

    def test_cancelled_and_failed_reports_distinguish_untouched_and_changed_media(self):
        reviewed = sample_plan()
        untouched = {
            "schema": 2,
            "status": "cancelled",
            "phase": "prepare",
            "plan": copy.deepcopy(reviewed["plan"]),
            "started_at": "2026-07-20T00:00:00Z",
            "completed_at": "2026-07-20T00:00:01Z",
            "bytes_written": 0,
            "bytes_verified": 0,
            "verification_scope": VERIFICATION_SCOPE,
            "media_changed": False,
            "verified": False,
            "reusable": False,
            "failure_reason": "cancelled",
        }
        self.assertIn("was not changed", report_summary(normalize_report(untouched, reviewed)))

        changed = copy.deepcopy(untouched)
        changed.update(
            {
                "status": "failed",
                "phase": "write",
                "bytes_written": 4096,
                "media_changed": True,
                "failure_reason": "short write",
            }
        )
        self.assertIn("not reusable", report_summary(normalize_report(changed, reviewed)))


if __name__ == "__main__":
    unittest.main()
