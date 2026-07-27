import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "gui"))

from rufusarm64_freedos import FREEDOS_WARNINGS, validate_progress_against_plan


MIB = 1024 * 1024
GIB = 1024 * MIB
DEVICE_SIZE = 30 * GIB
MUTATION_BYTES = 18 * MIB
VERIFICATION_BYTES = 18 * MIB
PARTITION_START = 1 * MIB
TAIL_RESERVE = 1 * MIB
PARTITION_SIZE = DEVICE_SIZE - PARTITION_START - TAIL_RESERVE
EXPECTED_TOTAL = MUTATION_BYTES + VERIFICATION_BYTES


def reviewed_plan():
    identity = "lexar-hardware-fixture"
    plan = {
        "schema": 2,
        "mode": "freedos",
        "bootable": True,
        "destructive": True,
        "target_cpu": "x86",
        "firmware": "BIOS or UEFI Legacy/CSM",
        "distribution": "FreeDOS 1.4",
        "device_path": "/dev/sdz",
        "expected_identity": identity,
        "device_size_bytes": DEVICE_SIZE,
        "logical_sector_size": 512,
        "partition_number": 1,
        "partition_start_bytes": PARTITION_START,
        "partition_size_bytes": PARTITION_SIZE,
        "partition_type": "0c",
        "filesystem": "FAT32",
        "label": "FREEDOS",
        "mutation_bytes": MUTATION_BYTES,
        "verification_bytes": VERIFICATION_BYTES,
        "untouched_bytes": DEVICE_SIZE - MUTATION_BYTES,
        "media": {
            "schema": 1,
            "disk_size_bytes": DEVICE_SIZE,
            "logical_sector_size": 512,
            "partition_start_sector": PARTITION_START // 512,
            "partition_sector_count": PARTITION_SIZE // 512,
            "sectors_per_cluster": 32,
            "sectors_per_track": 63,
            "heads": 255,
            "label": "FREEDOS",
        },
        "warnings": list(FREEDOS_WARNINGS),
    }
    return {
        "device": {"path": "/dev/sdz", "size": DEVICE_SIZE, "vendor": "Lexar", "model": "JumpDrive"},
        "identity": identity,
        "plan": plan,
        "confirmation": "WRITE FREEDOS 1.4 TO /dev/sdz FOR X86 BIOS LEGACY",
    }


def progress(phase, done, total, overall_done, overall_total=EXPECTED_TOTAL):
    return {
        "schema": 1,
        "type": "progress",
        "phase": phase,
        "done": done,
        "total": total,
        "overall_done": overall_done,
        "overall_total": overall_total,
        "elapsed_ms": 1000,
        "bytes_per_second": MIB,
        "eta_seconds": 10,
    }


class FreeDOSExtentProgressContractTests(unittest.TestCase):
    def test_large_device_accepts_small_reviewed_extent_total(self):
        value = validate_progress_against_plan(
            progress("write", MIB, MUTATION_BYTES, MIB),
            reviewed_plan(),
        )
        self.assertEqual(value["overall_total"], EXPECTED_TOTAL)
        self.assertNotEqual(value["overall_total"], DEVICE_SIZE * 2)

    def test_stale_full_device_total_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "required-extent I/O total"):
            validate_progress_against_plan(
                progress("write", MIB, MUTATION_BYTES, MIB, DEVICE_SIZE * 2),
                reviewed_plan(),
            )

    def test_write_phase_is_bound_to_mutation_total(self):
        with self.assertRaisesRegex(ValueError, "reviewed mutation total"):
            validate_progress_against_plan(
                progress("write", MIB, DEVICE_SIZE, MIB),
                reviewed_plan(),
            )

    def test_readback_phase_is_bound_to_verification_total(self):
        value = validate_progress_against_plan(
            progress(
                "readback",
                2 * MIB,
                VERIFICATION_BYTES,
                MUTATION_BYTES + 2 * MIB,
            ),
            reviewed_plan(),
        )
        self.assertEqual(value["total"], VERIFICATION_BYTES)


if __name__ == "__main__":
    unittest.main()
