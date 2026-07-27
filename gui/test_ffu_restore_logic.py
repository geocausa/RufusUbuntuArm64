import copy
import hashlib
import unittest

from rufusarm64_ffu_restore_logic import (
    build_ffu_restore_command,
    ffu_restore_summary,
    normalize_ffu_restore_output,
)
from test_logic import valid_ffu_review_payload


def valid_ffu_restore_output():
    review = valid_ffu_review_payload()
    review["execution_attempted"] = True
    target = review["target_plan"]
    full = review["full_flash_plan"]
    preflight = review["target_preflight"]
    source_sha = "3" * 64
    target_sha = "4" * 64
    confirmation_sha = "5" * 64
    authorization_sha = "6" * 64
    write_order_sha = "a" * 64
    result_sha = "0" * 64
    phrase = review["exact_confirmation_phrase"]
    mutation = target["mutation_bytes"]
    size = target["target_size_bytes"]
    identity = target["expected_target_identity"]

    source = {
        "schema": 1,
        "mode": "ffu-authenticated-source-lease",
        "source_identity": copy.deepcopy(review["source_identity"]),
        "source_file_size": review["source_identity"]["Size"],
        "full_flash_target_preflight_sha256": preflight["plan_sha256"],
        "full_flash_validation_plan_sha256": full["plan_sha256"],
        "restore_target_plan_sha256": target["plan_sha256"],
        "authenticated_integrity_sha256": target["authenticated_integrity_plan_sha256"],
        "target_device_path": target["device_path"],
        "expected_target_identity": identity,
        "target_size_bytes": size,
        "kernel_read_lease_required": True,
        "kernel_read_lease_held": True,
        "source_identity_revalidated": True,
        "full_flash_validation_reproduced": True,
        "target_preflight_bound": True,
        "fallback_allowed": False,
        "target_access_permitted": False,
        "execution_supported": False,
        "plan_sha256": source_sha,
        "warnings": [],
        "limitations": [],
    }
    target_session = {
        "schema": 1,
        "mode": "ffu-exclusive-target-session",
        "source_lease_evidence_sha256": source_sha,
        "full_flash_target_preflight_sha256": preflight["plan_sha256"],
        "full_flash_validation_plan_sha256": full["plan_sha256"],
        "restore_target_plan_sha256": target["plan_sha256"],
        "authenticated_integrity_sha256": target["authenticated_integrity_plan_sha256"],
        "device_path": target["device_path"],
        "expected_target_identity": identity,
        "rediscovered_target_identity": identity,
        "target_size_bytes": size,
        "logical_sector_size_bytes": target["logical_sector_size_bytes"],
        "physical_sector_size_bytes": target["physical_sector_size_bytes"],
        "store_block_size_bytes": target["store_block_size_bytes"],
        "expected_kernel_device_id": preflight["kernel_device_id"],
        "observed_kernel_device_id": preflight["kernel_device_id"],
        "major_minor": preflight["major_minor"],
        "mutation_bytes": mutation,
        "source_lease_held": True,
        "target_opened_read_write": True,
        "kernel_exclusive_open": True,
        "no_follow_open": True,
        "mounted_targets_absent": True,
        "guarded_unmount_performed": False,
        "target_descriptor_verified": True,
        "target_policy_revalidated": True,
        "target_geometry_revalidated": True,
        "source_outside_target_confirmed": True,
        "fixed_disk_override_allowed": False,
        "target_access_acquired": True,
        "mutation_permitted": False,
        "execution_supported": False,
        "plan_sha256": target_sha,
        "warnings": [],
        "limitations": [],
    }
    confirmation = {
        "schema": 1,
        "mode": "ffu-exact-destructive-confirmation",
        "target_session_evidence_sha256": target_sha,
        "source_lease_evidence_sha256": source_sha,
        "full_flash_target_preflight_sha256": preflight["plan_sha256"],
        "full_flash_validation_plan_sha256": full["plan_sha256"],
        "restore_target_plan_sha256": target["plan_sha256"],
        "authenticated_integrity_sha256": target["authenticated_integrity_plan_sha256"],
        "device_path": target["device_path"],
        "expected_target_identity": identity,
        "target_size_bytes": size,
        "mutation_bytes": mutation,
        "expected_confirmation_phrase": phrase,
        "confirmation_phrase_sha256": hashlib.sha256(phrase.encode()).hexdigest(),
        "confirmation_exact_match": True,
        "confirmation_consumed": True,
        "source_lease_held": True,
        "target_session_held": True,
        "target_access_acquired": True,
        "guarded_unmount_performed": False,
        "mutation_permitted": False,
        "execution_supported": False,
        "plan_sha256": confirmation_sha,
        "warnings": [],
        "limitations": [],
    }
    authorization = {
        "schema": 1,
        "mode": "ffu-single-phase-mutation-authorization",
        "confirmation_evidence_sha256": confirmation_sha,
        "target_session_evidence_sha256": target_sha,
        "source_lease_evidence_sha256": source_sha,
        "full_flash_target_preflight_sha256": preflight["plan_sha256"],
        "write_order_plan_sha256": write_order_sha,
        "full_flash_validation_plan_sha256": full["plan_sha256"],
        "restore_target_plan_sha256": target["plan_sha256"],
        "descriptor_plan_sha256": review["descriptor_plan_sha256"],
        "authenticated_integrity_sha256": target["authenticated_integrity_plan_sha256"],
        "catalog_sha256": target["catalog_sha256"],
        "hash_table_sha256": target["hash_table_sha256"],
        "device_path": target["device_path"],
        "expected_target_identity": identity,
        "target_size_bytes": size,
        "store_block_size_bytes": target["store_block_size_bytes"],
        "operation_count": 1,
        "mutation_bytes": mutation,
        "confirmation_phrase": phrase,
        "confirmation_satisfied": True,
        "source_lease_held": True,
        "target_session_held": True,
        "target_access_acquired": True,
        "single_phase_write_order_resolved": True,
        "staged_gpt_profile_allowed": False,
        "guarded_unmount_performed": False,
        "one_shot_execution_required": True,
        "authorization_consumed": False,
        "mutation_permitted": True,
        "execution_supported": False,
        "plan_sha256": authorization_sha,
        "warnings": [],
        "limitations": [],
    }
    execution = {
        "schema": 1,
        "mode": "ffu-single-phase-execution",
        "status": "verified",
        "mutation_authorization_sha256": authorization_sha,
        "confirmation_evidence_sha256": confirmation_sha,
        "target_session_evidence_sha256": target_sha,
        "source_lease_evidence_sha256": source_sha,
        "write_order_plan_sha256": write_order_sha,
        "full_flash_validation_plan_sha256": full["plan_sha256"],
        "restore_target_plan_sha256": target["plan_sha256"],
        "descriptor_plan_sha256": review["descriptor_plan_sha256"],
        "authenticated_integrity_sha256": target["authenticated_integrity_plan_sha256"],
        "device_path": target["device_path"],
        "expected_target_identity": identity,
        "target_size_bytes": size,
        "operation_count_planned": 1,
        "operation_count_completed": 1,
        "mutation_bytes_planned": mutation,
        "mutation_bytes_written": mutation,
        "authorization_consumed": True,
        "source_lease_revalidated": True,
        "target_session_revalidated": True,
        "mutation_started": True,
        "write_completed": True,
        "sync_completed": True,
        "readback_completed": True,
        "cancellation_observed": False,
        "cancelled_before_mutation": False,
        "cancelled_after_mutation": False,
        "target_may_be_partially_modified": False,
        "execution_succeeded": True,
        "error_observed": False,
        "error_stage": "",
        "result_sha256": result_sha,
        "warnings": [],
        "limitations": [],
    }
    return {
        "review": review,
        "source_lease": source,
        "target_session": target_session,
        "confirmation": confirmation,
        "mutation_authorization": authorization,
        "execution": execution,
    }


class FFURestoreLogicTests(unittest.TestCase):
    def test_restore_command_uses_only_reviewed_values(self):
        review = valid_ffu_review_payload()
        command = build_ffu_restore_command(
            "/usr/bin/pkexec",
            "/usr/lib/rufusarm64/rufusarm64-helper",
            review,
            review["exact_confirmation_phrase"],
        )
        self.assertEqual(command[:4], [
            "/usr/bin/pkexec",
            "/usr/lib/rufusarm64/rufusarm64-helper",
            "ffu",
            "restore",
        ])
        self.assertEqual(command[command.index("--expected-review-binding") + 1], review["review_binding_sha256"])
        self.assertEqual(command[command.index("--confirm") + 1], review["exact_confirmation_phrase"])
        for forbidden in ("--allow-fixed", "--unmount", "--yes"):
            self.assertNotIn(forbidden, command)

    def test_restore_command_refuses_mounts_and_confirmation_changes(self):
        review = valid_ffu_review_payload()
        with self.assertRaises(ValueError):
            build_ffu_restore_command("/usr/bin/pkexec", "/helper", review, review["exact_confirmation_phrase"] + " ")
        mounted = copy.deepcopy(review)
        mounted["target_preflight"]["mounted_targets"] = [{
            "device_path": "/dev/sdz1",
            "mountpoint": "/media/geoca/FFU",
        }]
        mounted["target_preflight"]["unmount_required"] = True
        with self.assertRaises(ValueError):
            build_ffu_restore_command("/usr/bin/pkexec", "/helper", mounted, mounted["exact_confirmation_phrase"])

    def test_verified_restore_output_is_fully_correlated(self):
        payload = valid_ffu_restore_output()
        expected = copy.deepcopy(payload["review"])
        expected["execution_attempted"] = False
        result = normalize_ffu_restore_output(payload, expected)
        self.assertEqual(result["outcome"], "verified")
        self.assertEqual(result["mutation_bytes_written"], result["mutation_bytes_planned"])
        summary = ffu_restore_summary(result)
        self.assertIn("completed and verified", summary)
        self.assertIn(result["result_sha256"], summary)

    def test_restore_output_rejects_evidence_substitution(self):
        base = valid_ffu_restore_output()
        expected = copy.deepcopy(base["review"])
        expected["execution_attempted"] = False
        mutations = []
        changed = copy.deepcopy(base)
        changed["source_lease"]["plan_sha256"] = "9" * 64
        mutations.append(changed)
        changed = copy.deepcopy(base)
        changed["target_session"]["observed_kernel_device_id"] += 1
        mutations.append(changed)
        changed = copy.deepcopy(base)
        changed["confirmation"]["expected_confirmation_phrase"] += " "
        mutations.append(changed)
        changed = copy.deepcopy(base)
        changed["mutation_authorization"]["staged_gpt_profile_allowed"] = True
        mutations.append(changed)
        changed = copy.deepcopy(base)
        changed["execution"]["mutation_bytes_written"] -= 1
        mutations.append(changed)
        changed = copy.deepcopy(base)
        changed["review"]["review_binding_sha256"] = "1" * 64
        mutations.append(changed)
        for changed in mutations:
            with self.subTest(changed=changed):
                with self.assertRaises(ValueError):
                    normalize_ffu_restore_output(changed, expected)

    def test_not_started_result_proves_no_bytes_written(self):
        payload = valid_ffu_restore_output()
        execution = payload["execution"]
        execution.update({
            "status": "not-started",
            "operation_count_completed": 0,
            "mutation_bytes_written": 0,
            "authorization_consumed": False,
            "source_lease_revalidated": False,
            "target_session_revalidated": False,
            "mutation_started": False,
            "write_completed": False,
            "sync_completed": False,
            "readback_completed": False,
            "cancellation_observed": True,
            "cancelled_before_mutation": True,
            "cancelled_after_mutation": False,
            "target_may_be_partially_modified": False,
            "execution_succeeded": False,
            "error_observed": True,
            "error_stage": "preflight-context",
        })
        result = normalize_ffu_restore_output(payload)
        self.assertEqual(result["outcome"], "unchanged")
        self.assertIn("did not begin", ffu_restore_summary(result))

    def test_partial_result_never_hides_target_risk(self):
        payload = valid_ffu_restore_output()
        execution = payload["execution"]
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
        result = normalize_ffu_restore_output(payload)
        self.assertEqual(result["outcome"], "partially-modified")
        summary = ffu_restore_summary(result)
        self.assertIn("DANGER", summary)
        self.assertIn("Do not boot", summary)


if __name__ == "__main__":
    unittest.main()
