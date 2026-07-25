#!/usr/bin/env python3
"""Pure graphical FFU restore command and result contracts."""

import copy
import hashlib

from rufusarm64_logic import (
    _ffu_absolute_path,
    _ffu_mapping,
    _ffu_positive_int,
    _ffu_sha256,
    human_bytes,
    normalize_ffu_review,
)


_STABLE_REVIEW_FIELDS = (
    "trust_store_root",
    "trust_generation",
    "trust_sequence",
    "trust_bundle_sha256",
    "trust_metadata_policy_path",
    "publisher_policy_path",
    "review_binding_sha256",
    "source_path",
    "source_size",
    "descriptor_plan_sha256",
    "target_path",
    "target_identity",
    "target_size",
    "logical_sector_size",
    "physical_sector_size",
    "mutation_bytes",
    "exact_confirmation_phrase",
)


def _required_bool(mapping, key, expected, label):
    if mapping.get(key) is not expected:
        raise ValueError(f"The FFU restore returned an invalid {label} state.")


def _required_equal(mapping, key, expected, label):
    if mapping.get(key) != expected:
        raise ValueError(f"The FFU restore evidence disagrees on {label}.")


def _required_sha(mapping, key, expected, label):
    actual = _ffu_sha256(mapping.get(key), label)
    if actual != expected:
        raise ValueError(f"The FFU restore evidence disagrees on {label}.")
    return actual


def _required_envelope(mapping, mode, label):
    mapping = _ffu_mapping(mapping, label)
    if mapping.get("schema") != 1 or mapping.get("mode") != mode:
        raise ValueError(f"The FFU restore returned an unsupported {label} envelope.")
    return mapping


def _normalize_restore_review(payload):
    payload = _ffu_mapping(payload, "reproduced review")
    if payload.get("execution_attempted") is not True:
        raise ValueError("The privileged FFU result did not mark execution as attempted.")
    review_copy = copy.deepcopy(payload)
    review_copy["execution_attempted"] = False
    return normalize_ffu_review(review_copy)


def build_ffu_restore_command(pkexec, helper, review_payload, confirmation):
    """Build the privileged restore command from one completed read-only review."""
    pkexec = _ffu_absolute_path(pkexec, "administrator authentication")
    helper = _ffu_absolute_path(helper, "FFU helper")
    review = normalize_ffu_review(review_payload)
    if review["unmount_required"] or review["mounted_targets"]:
        raise ValueError(
            "The reviewed FFU target is mounted. Unmount it outside RufusArm64, refresh the drive list, and review it again."
        )
    if not isinstance(confirmation, str) or confirmation != review["exact_confirmation_phrase"]:
        raise ValueError(
            "The destructive confirmation must exactly match the reviewed target and capacity."
        )
    return [
        pkexec,
        helper,
        "ffu",
        "restore",
        "--experimental-ffu",
        "--image",
        review["source_path"],
        "--device",
        review["target_path"],
        "--expected-identity",
        review["target_identity"],
        "--target-size",
        str(review["target_size"]),
        "--logical-sector-size",
        str(review["logical_sector_size"]),
        "--physical-sector-size",
        str(review["physical_sector_size"]),
        "--trust-store",
        review["trust_store_root"],
        "--trust-metadata-policy",
        review["trust_metadata_policy_path"],
        "--publisher-policy",
        review["publisher_policy_path"],
        "--confirm",
        confirmation,
        "--expected-review-binding",
        review["review_binding_sha256"],
        "--json",
    ]


def _correlate_reproduced_review(actual_payload, actual, expected_payload):
    if expected_payload is None:
        return
    expected = normalize_ffu_review(expected_payload)
    for key in _STABLE_REVIEW_FIELDS:
        if actual[key] != expected[key]:
            raise ValueError(
                f"The FFU source, trust policy, or target changed after review ({key})."
            )
    actual_raw = _ffu_mapping(actual_payload, "reproduced review")
    expected_raw = _ffu_mapping(expected_payload, "expected review")
    for key in (
        "source_identity",
        "trust_metadata_policy_identity",
        "publisher_policy_identity",
    ):
        if actual_raw.get(key) != expected_raw.get(key):
            raise ValueError(
                "The FFU source or policy file identity changed after review."
            )
    actual_preflight = _ffu_mapping(actual_raw.get("target_preflight"), "reproduced target preflight")
    expected_preflight = _ffu_mapping(expected_raw.get("target_preflight"), "expected target preflight")
    for key in ("kernel_device_id", "major_minor"):
        if actual_preflight.get(key) != expected_preflight.get(key):
            raise ValueError("The FFU target kernel identity changed after review.")


def normalize_ffu_restore_output(payload, expected_review_payload=None):
    """Validate the complete privileged FFU evidence chain and execution state."""
    payload = _ffu_mapping(payload, "restore response")
    review_payload = _ffu_mapping(payload.get("review"), "reproduced review")
    review = _normalize_restore_review(review_payload)
    _correlate_reproduced_review(review_payload, review, expected_review_payload)

    raw_target = _ffu_mapping(review_payload.get("target_plan"), "restore target plan")
    raw_full = _ffu_mapping(review_payload.get("full_flash_plan"), "full-flash plan")
    raw_preflight = _ffu_mapping(review_payload.get("target_preflight"), "target preflight")
    target_plan_sha = _ffu_sha256(raw_target.get("plan_sha256"), "target plan")
    full_plan_sha = _ffu_sha256(raw_full.get("plan_sha256"), "full-flash plan")
    preflight_sha = _ffu_sha256(raw_preflight.get("plan_sha256"), "target preflight")
    integrity_sha = _ffu_sha256(
        raw_target.get("authenticated_integrity_plan_sha256"),
        "authenticated integrity",
    )
    descriptor_sha = review["descriptor_plan_sha256"]

    source = _required_envelope(
        payload.get("source_lease"), "ffu-authenticated-source-lease", "source lease"
    )
    _required_equal(source, "source_identity", review_payload.get("source_identity"), "source identity")
    _required_equal(source, "source_file_size", review["source_size"], "source size")
    _required_sha(source, "full_flash_target_preflight_sha256", preflight_sha, "source-lease preflight")
    _required_sha(source, "full_flash_validation_plan_sha256", full_plan_sha, "source-lease full-flash plan")
    _required_sha(source, "restore_target_plan_sha256", target_plan_sha, "source-lease target plan")
    _required_sha(source, "authenticated_integrity_sha256", integrity_sha, "source-lease integrity")
    for key, expected, label in (
        ("target_device_path", review["target_path"], "source-lease target path"),
        ("expected_target_identity", review["target_identity"], "source-lease target identity"),
        ("target_size_bytes", review["target_size"], "source-lease target capacity"),
    ):
        _required_equal(source, key, expected, label)
    for key, expected, label in (
        ("kernel_read_lease_required", True, "mandatory source lease"),
        ("kernel_read_lease_held", True, "held source lease"),
        ("source_identity_revalidated", True, "source identity revalidation"),
        ("full_flash_validation_reproduced", True, "full-flash reproduction"),
        ("target_preflight_bound", True, "source-to-target binding"),
        ("fallback_allowed", False, "source-lease fallback"),
        ("target_access_permitted", False, "premature target access"),
        ("execution_supported", False, "source-lease execution"),
    ):
        _required_bool(source, key, expected, label)
    source_sha = _ffu_sha256(source.get("plan_sha256"), "source lease")

    target = _required_envelope(
        payload.get("target_session"), "ffu-exclusive-target-session", "target session"
    )
    _required_sha(target, "source_lease_evidence_sha256", source_sha, "target-session source lease")
    _required_sha(target, "full_flash_target_preflight_sha256", preflight_sha, "target-session preflight")
    _required_sha(target, "full_flash_validation_plan_sha256", full_plan_sha, "target-session full-flash plan")
    _required_sha(target, "restore_target_plan_sha256", target_plan_sha, "target-session target plan")
    _required_sha(target, "authenticated_integrity_sha256", integrity_sha, "target-session integrity")
    for key, expected, label in (
        ("device_path", review["target_path"], "target-session path"),
        ("expected_target_identity", review["target_identity"], "target-session expected identity"),
        ("rediscovered_target_identity", review["target_identity"], "target-session rediscovered identity"),
        ("target_size_bytes", review["target_size"], "target-session capacity"),
        ("logical_sector_size_bytes", review["logical_sector_size"], "target-session logical sector size"),
        ("physical_sector_size_bytes", review["physical_sector_size"], "target-session physical sector size"),
        ("expected_kernel_device_id", raw_preflight.get("kernel_device_id"), "expected kernel identity"),
        ("observed_kernel_device_id", raw_preflight.get("kernel_device_id"), "observed kernel identity"),
        ("major_minor", raw_preflight.get("major_minor"), "kernel major:minor identity"),
        ("mutation_bytes", review["mutation_bytes"], "target-session mutation scope"),
    ):
        _required_equal(target, key, expected, label)
    for key, expected, label in (
        ("source_lease_held", True, "target-session source lease"),
        ("target_opened_read_write", True, "target read-write open"),
        ("kernel_exclusive_open", True, "exclusive target open"),
        ("no_follow_open", True, "no-follow target open"),
        ("mounted_targets_absent", True, "target mount exclusion"),
        ("guarded_unmount_performed", False, "automatic unmount"),
        ("target_descriptor_verified", True, "target descriptor verification"),
        ("target_policy_revalidated", True, "target policy revalidation"),
        ("target_geometry_revalidated", True, "target geometry revalidation"),
        ("source_outside_target_confirmed", True, "source-outside-target check"),
        ("fixed_disk_override_allowed", False, "fixed-disk override"),
        ("target_access_acquired", True, "target access acquisition"),
        ("mutation_permitted", False, "premature target mutation"),
        ("execution_supported", False, "target-session execution"),
    ):
        _required_bool(target, key, expected, label)
    target_sha = _ffu_sha256(target.get("plan_sha256"), "target session")

    confirmation = _required_envelope(
        payload.get("confirmation"),
        "ffu-exact-destructive-confirmation",
        "destructive confirmation",
    )
    _required_sha(confirmation, "target_session_evidence_sha256", target_sha, "confirmation target session")
    _required_sha(confirmation, "source_lease_evidence_sha256", source_sha, "confirmation source lease")
    _required_sha(confirmation, "full_flash_target_preflight_sha256", preflight_sha, "confirmation preflight")
    _required_sha(confirmation, "full_flash_validation_plan_sha256", full_plan_sha, "confirmation full-flash plan")
    _required_sha(confirmation, "restore_target_plan_sha256", target_plan_sha, "confirmation target plan")
    _required_sha(confirmation, "authenticated_integrity_sha256", integrity_sha, "confirmation integrity")
    for key, expected, label in (
        ("device_path", review["target_path"], "confirmation target path"),
        ("expected_target_identity", review["target_identity"], "confirmation target identity"),
        ("target_size_bytes", review["target_size"], "confirmation target capacity"),
        ("mutation_bytes", review["mutation_bytes"], "confirmation mutation scope"),
        ("expected_confirmation_phrase", review["exact_confirmation_phrase"], "confirmation phrase"),
    ):
        _required_equal(confirmation, key, expected, label)
    phrase_sha = hashlib.sha256(review["exact_confirmation_phrase"].encode("utf-8")).hexdigest()
    _required_sha(confirmation, "confirmation_phrase_sha256", phrase_sha, "confirmation phrase")
    for key, expected, label in (
        ("confirmation_exact_match", True, "exact confirmation"),
        ("confirmation_consumed", True, "confirmation consumption"),
        ("source_lease_held", True, "confirmation source lease"),
        ("target_session_held", True, "confirmation target session"),
        ("target_access_acquired", True, "confirmation target access"),
        ("guarded_unmount_performed", False, "automatic unmount"),
        ("mutation_permitted", False, "premature confirmation mutation"),
        ("execution_supported", False, "confirmation execution"),
    ):
        _required_bool(confirmation, key, expected, label)
    confirmation_sha = _ffu_sha256(confirmation.get("plan_sha256"), "confirmation evidence")

    authorization = _required_envelope(
        payload.get("mutation_authorization"),
        "ffu-single-phase-mutation-authorization",
        "mutation authorization",
    )
    _required_sha(authorization, "confirmation_evidence_sha256", confirmation_sha, "authorization confirmation")
    _required_sha(authorization, "target_session_evidence_sha256", target_sha, "authorization target session")
    _required_sha(authorization, "source_lease_evidence_sha256", source_sha, "authorization source lease")
    _required_sha(authorization, "full_flash_target_preflight_sha256", preflight_sha, "authorization preflight")
    write_order_sha = _ffu_sha256(authorization.get("write_order_plan_sha256"), "write-order plan")
    _required_sha(authorization, "full_flash_validation_plan_sha256", full_plan_sha, "authorization full-flash plan")
    _required_sha(authorization, "restore_target_plan_sha256", target_plan_sha, "authorization target plan")
    _required_sha(authorization, "descriptor_plan_sha256", descriptor_sha, "authorization descriptor plan")
    _required_sha(authorization, "authenticated_integrity_sha256", integrity_sha, "authorization integrity")
    _required_sha(authorization, "catalog_sha256", _ffu_sha256(raw_target.get("catalog_sha256"), "catalog"), "authorization catalog")
    _required_sha(authorization, "hash_table_sha256", _ffu_sha256(raw_target.get("hash_table_sha256"), "hash table"), "authorization hash table")
    operation_count = _ffu_positive_int(authorization, "operation_count", "operation count")
    for key, expected, label in (
        ("device_path", review["target_path"], "authorization target path"),
        ("expected_target_identity", review["target_identity"], "authorization target identity"),
        ("target_size_bytes", review["target_size"], "authorization target capacity"),
        ("mutation_bytes", review["mutation_bytes"], "authorization mutation scope"),
        ("confirmation_phrase", review["exact_confirmation_phrase"], "authorization confirmation phrase"),
    ):
        _required_equal(authorization, key, expected, label)
    for key, expected, label in (
        ("confirmation_satisfied", True, "authorization confirmation"),
        ("source_lease_held", True, "authorization source lease"),
        ("target_session_held", True, "authorization target session"),
        ("target_access_acquired", True, "authorization target access"),
        ("single_phase_write_order_resolved", True, "single-phase write order"),
        ("staged_gpt_profile_allowed", False, "staged GPT profile"),
        ("guarded_unmount_performed", False, "automatic unmount"),
        ("one_shot_execution_required", True, "one-shot execution"),
        ("authorization_consumed", False, "premature authorization consumption"),
        ("mutation_permitted", True, "mutation authorization"),
        ("execution_supported", False, "authorization execution"),
    ):
        _required_bool(authorization, key, expected, label)
    authorization_sha = _ffu_sha256(authorization.get("plan_sha256"), "mutation authorization")

    execution = _required_envelope(
        payload.get("execution"), "ffu-single-phase-execution", "execution result"
    )
    for key, expected, label in (
        ("mutation_authorization_sha256", authorization_sha, "execution authorization"),
        ("confirmation_evidence_sha256", confirmation_sha, "execution confirmation"),
        ("target_session_evidence_sha256", target_sha, "execution target session"),
        ("source_lease_evidence_sha256", source_sha, "execution source lease"),
        ("write_order_plan_sha256", write_order_sha, "execution write order"),
        ("full_flash_validation_plan_sha256", full_plan_sha, "execution full-flash plan"),
        ("restore_target_plan_sha256", target_plan_sha, "execution target plan"),
        ("descriptor_plan_sha256", descriptor_sha, "execution descriptor plan"),
        ("authenticated_integrity_sha256", integrity_sha, "execution integrity"),
    ):
        _required_sha(execution, key, expected, label)
    for key, expected, label in (
        ("device_path", review["target_path"], "execution target path"),
        ("expected_target_identity", review["target_identity"], "execution target identity"),
        ("target_size_bytes", review["target_size"], "execution target capacity"),
        ("operation_count_planned", operation_count, "planned operation count"),
        ("mutation_bytes_planned", review["mutation_bytes"], "planned mutation bytes"),
    ):
        _required_equal(execution, key, expected, label)

    status = str(execution.get("status") or "")
    if status not in {"verified", "not-started", "partially-modified", "written-unverified"}:
        raise ValueError("The FFU restore returned an unknown execution status.")
    operations_completed = _ffu_positive_int(
        execution, "operation_count_completed", "completed operation count", allow_zero=True
    )
    bytes_written = _ffu_positive_int(
        execution, "mutation_bytes_written", "written mutation bytes", allow_zero=True
    )
    if operations_completed > operation_count or bytes_written > review["mutation_bytes"]:
        raise ValueError("The FFU restore returned impossible execution accounting.")
    result_sha = _ffu_sha256(execution.get("result_sha256"), "execution result")
    cancellation = execution.get("cancellation_observed") is True
    cancelled_before = execution.get("cancelled_before_mutation") is True
    cancelled_after = execution.get("cancelled_after_mutation") is True
    if cancellation:
        if cancelled_before == cancelled_after:
            raise ValueError("The FFU restore returned inconsistent cancellation evidence.")
    elif cancelled_before or cancelled_after:
        raise ValueError("The FFU restore returned cancellation phase without cancellation.")

    if status == "verified":
        for key, expected, label in (
            ("authorization_consumed", True, "authorization consumption"),
            ("source_lease_revalidated", True, "source revalidation"),
            ("target_session_revalidated", True, "target revalidation"),
            ("mutation_started", True, "mutation start"),
            ("write_completed", True, "write completion"),
            ("sync_completed", True, "target synchronization"),
            ("readback_completed", True, "target readback"),
            ("cancellation_observed", False, "cancellation"),
            ("cancelled_before_mutation", False, "pre-mutation cancellation"),
            ("cancelled_after_mutation", False, "post-mutation cancellation"),
            ("target_may_be_partially_modified", False, "partial target state"),
            ("execution_succeeded", True, "execution success"),
            ("error_observed", False, "execution error"),
        ):
            _required_bool(execution, key, expected, label)
        if execution.get("error_stage") != "" or operations_completed != operation_count or bytes_written != review["mutation_bytes"]:
            raise ValueError("The verified FFU result has inconsistent completion evidence.")
        outcome = "verified"
    else:
        _required_bool(execution, "execution_succeeded", False, "failed execution success")
        _required_bool(execution, "error_observed", True, "failed execution error")
        if not str(execution.get("error_stage") or "").strip():
            raise ValueError("The failed FFU result is missing its error stage.")
        mutation_started = execution.get("mutation_started") is True
        partial = execution.get("target_may_be_partially_modified") is True
        if status == "not-started":
            if mutation_started or bytes_written != 0 or partial or cancelled_after:
                raise ValueError("The not-started FFU result reports target mutation.")
            outcome = "unchanged"
        elif status == "partially-modified":
            if not mutation_started or bytes_written == 0 or not partial:
                raise ValueError("The partial FFU result is missing mutation evidence.")
            outcome = "partially-modified"
        else:
            if (
                not mutation_started
                or bytes_written != review["mutation_bytes"]
                or operations_completed != operation_count
                or execution.get("write_completed") is not True
                or execution.get("sync_completed") is not True
                or execution.get("readback_completed") is True
                or not partial
            ):
                raise ValueError("The written-unverified FFU result is inconsistent.")
            outcome = "written-unverified"

    return {
        "outcome": outcome,
        "status": status,
        "target_path": review["target_path"],
        "target_identity": review["target_identity"],
        "target_size": review["target_size"],
        "mutation_bytes_planned": review["mutation_bytes"],
        "mutation_bytes_written": bytes_written,
        "operation_count_planned": operation_count,
        "operation_count_completed": operations_completed,
        "cancellation_observed": cancellation,
        "cancelled_before_mutation": cancelled_before,
        "cancelled_after_mutation": cancelled_after,
        "target_may_be_partially_modified": execution.get("target_may_be_partially_modified") is True,
        "error_stage": str(execution.get("error_stage") or ""),
        "result_sha256": result_sha,
        "review_binding_sha256": review["review_binding_sha256"],
        "execution": dict(execution),
    }


def ffu_restore_summary(result):
    """Return user-facing text that never hides a possibly modified target."""
    result = _ffu_mapping(result, "normalized restore result")
    outcome = result.get("outcome")
    target = result.get("target_path") or "the selected target"
    written = human_bytes(result.get("mutation_bytes_written") or 0)
    planned = human_bytes(result.get("mutation_bytes_planned") or 0)
    if outcome == "verified":
        headline = "FFU restoration completed and verified."
        guidance = "The target was synchronized, read back, and matched the authenticated FFU payload."
    elif outcome == "unchanged":
        headline = "FFU restoration did not begin."
        guidance = "The evidence says no target bytes were written. Review the error and run a fresh read-only review before retrying."
    elif outcome == "written-unverified":
        headline = "WARNING: the FFU was written but could not be verified."
        guidance = "Treat the target as unsafe and incomplete. Do not boot it; perform a fresh full restoration."
    elif outcome == "partially-modified":
        headline = "DANGER: the FFU restore stopped after writing began."
        guidance = "The target may be partially modified. Do not boot or reuse it; perform a fresh full restoration."
    else:
        raise ValueError("Unknown normalized FFU restore outcome.")
    lines = [
        headline,
        f"Target: {target}",
        f"Written: {written} of {planned}",
        f"Execution status: {result.get('status', '')}",
    ]
    if result.get("error_stage"):
        lines.append(f"Failure stage: {result['error_stage']}")
    if result.get("cancellation_observed"):
        phase = "after mutation began" if result.get("cancelled_after_mutation") else "before mutation"
        lines.append(f"Cancellation was observed {phase}.")
    lines.extend((guidance, f"Result evidence: {result.get('result_sha256', '')}"))
    return "\n".join(lines)
