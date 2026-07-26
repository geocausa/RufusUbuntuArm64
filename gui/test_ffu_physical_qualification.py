import copy
import unittest

from rufusarm64_ffu_physical_qualification import (
    ffu_physical_qualification_summary,
    normalize_ffu_physical_qualification,
)
from test_ffu_restore_logic import valid_ffu_restore_output


def valid_physical_record():
    restore = valid_ffu_restore_output()
    review = copy.deepcopy(restore["review"])
    review["execution_attempted"] = False
    target = review["target_plan"]
    return {
        "schema": 1,
        "mode": "ffu-physical-qualification",
        "source_commit": "1" * 40,
        "package": {
            "filename": "rufusarm64_0.14.0~rc1_arm64.deb",
            "version": "0.14.0~rc1",
            "sha256": "2" * 64,
        },
        "vendor_image": {
            "filename": "vendor.ffu",
            "size_bytes": review["source_identity"]["Size"],
            "sha256": "3" * 64,
            "publisher": "Example Hardware Vendor",
        },
        "review": review,
        "restore": restore,
        "host": {
            "architecture": "aarch64",
            "os_release": "Ubuntu 24.04.2 LTS",
            "kernel_release": "6.8.0-test-arm64",
            "model": "ARM64 qualification host",
        },
        "target": {
            "identity": target["expected_target_identity"],
            "capacity_bytes": target["target_size_bytes"],
            "make_model": "Disposable USB target",
            "serial_or_asset_tag": "LAB-FFU-001",
            "transport": "USB",
        },
        "firmware": {
            "system_model": "Vendor ARM64 device",
            "firmware_version": "1.2.3",
            "secure_boot": "unknown",
        },
        "boot": {
            "attempted": False,
            "booted": False,
            "same_restored_media": False,
            "tester": "Maintainer",
            "date": "2026-07-26",
            "firmware_entry": "Not attempted",
            "observations": "Restore evidence sealed before physical boot testing.",
        },
        "evidence": [],
    }


class FFUPhysicalQualificationTests(unittest.TestCase):
    def test_verified_restore_remains_pending_until_physical_boot(self):
        result = normalize_ffu_physical_qualification(valid_physical_record())
        self.assertEqual(result["decision"], "pending-boot")
        self.assertFalse(result["universal_support_claimed"])
        self.assertEqual(len(result["qualification_sha256"]), 64)
        self.assertIn("still pending", ffu_physical_qualification_summary(result))

    def test_one_exact_boot_with_hashed_evidence_qualifies(self):
        record = valid_physical_record()
        record["boot"].update({
            "attempted": True,
            "booted": True,
            "same_restored_media": True,
            "firmware_entry": "Windows Boot Manager",
            "observations": "Reached the vendor operating-system first-boot screen.",
        })
        record["evidence"] = [{
            "name": "firmware-boot-photo.jpg",
            "kind": "photo",
            "sha256": "4" * 64,
            "description": "Photo of the exact target reaching the firmware-selected boot screen.",
        }]
        result = normalize_ffu_physical_qualification(record)
        self.assertEqual(result["decision"], "qualified")
        summary = ffu_physical_qualification_summary(result)
        self.assertIn("passed", summary)
        self.assertIn("does not establish universal", summary)

    def test_partial_restore_can_never_qualify(self):
        record = valid_physical_record()
        execution = record["restore"]["execution"]
        execution.update({
            "status": "partially-modified",
            "operation_count_completed": 0,
            "mutation_bytes_written": 4096,
            "authorization_consumed": True,
            "source_lease_revalidated": True,
            "target_session_revalidated": True,
            "mutation_started": True,
            "write_completed": False,
            "sync_completed": False,
            "readback_completed": False,
            "cancellation_observed": True,
            "cancelled_before_mutation": False,
            "cancelled_after_mutation": True,
            "target_may_be_partially_modified": True,
            "execution_succeeded": False,
            "error_observed": True,
            "error_stage": "write-context",
        })
        result = normalize_ffu_physical_qualification(record)
        self.assertEqual(result["decision"], "no-go-restore")
        self.assertIn("NO-GO", ffu_physical_qualification_summary(result))

    def test_target_substitution_is_rejected(self):
        record = valid_physical_record()
        record["target"]["identity"] += "-changed"
        with self.assertRaises(ValueError):
            normalize_ffu_physical_qualification(record)

    def test_boot_requires_attempt_same_media_and_hashed_evidence(self):
        record = valid_physical_record()
        record["boot"]["booted"] = True
        with self.assertRaises(ValueError):
            normalize_ffu_physical_qualification(record)

        record = valid_physical_record()
        record["boot"].update({
            "attempted": True,
            "booted": True,
            "same_restored_media": True,
        })
        with self.assertRaises(ValueError):
            normalize_ffu_physical_qualification(record)

    def test_qualification_digest_binds_manual_observations(self):
        first = valid_physical_record()
        second = copy.deepcopy(first)
        second["boot"]["observations"] = "Different observation."
        self.assertNotEqual(
            normalize_ffu_physical_qualification(first)["qualification_sha256"],
            normalize_ffu_physical_qualification(second)["qualification_sha256"],
        )


if __name__ == "__main__":
    unittest.main()
