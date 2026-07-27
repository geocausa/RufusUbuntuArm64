#!/usr/bin/env python3
"""Pure evidence contracts for one exact physical FFU qualification run."""

import datetime as _datetime
import hashlib
import json
import re

from rufusarm64_ffu_restore_logic import normalize_ffu_restore_output


_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_EVIDENCE_KINDS = {
    "diagnostic-log",
    "firmware-screen",
    "photo",
    "serial-console",
    "other",
}
_SECURE_BOOT_STATES = {"enabled", "disabled", "unknown"}


def _mapping(value, label):
    if not isinstance(value, dict):
        raise ValueError(f"The FFU physical qualification is missing {label}.")
    return value


def _text(mapping, key, label):
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"The FFU physical qualification has an invalid {label}.")
    return value.strip()


def _exact_text(mapping, key, label):
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"The FFU physical qualification has an invalid {label}.")
    return value


def _positive_int(mapping, key, label):
    value = mapping.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"The FFU physical qualification has an invalid {label}.")
    return value


def _required_bool(mapping, key, label):
    value = mapping.get(key)
    if value is not True and value is not False:
        raise ValueError(f"The FFU physical qualification has an invalid {label} state.")
    return value


def _sha256(mapping, key, label):
    value = _text(mapping, key, label).lower()
    if not _HEX64.fullmatch(value):
        raise ValueError(f"The FFU physical qualification has an invalid {label}.")
    return value


def _commit(mapping):
    value = _text(mapping, "source_commit", "source commit").lower()
    if not _HEX40.fullmatch(value):
        raise ValueError("The FFU physical qualification has an invalid source commit.")
    return value


def _date(mapping):
    value = _text(mapping, "date", "boot-test date")
    try:
        _datetime.date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("The FFU physical qualification has an invalid boot-test date.") from exc
    return value


def _canonical_sha256(value):
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _normalize_evidence(value):
    if not isinstance(value, list):
        raise ValueError("The FFU physical qualification evidence list is invalid.")
    normalized = []
    names = set()
    for item in value:
        item = _mapping(item, "evidence item")
        name = _text(item, "name", "evidence name")
        if name in names:
            raise ValueError("The FFU physical qualification repeats an evidence name.")
        names.add(name)
        kind = _text(item, "kind", "evidence kind")
        if kind not in _EVIDENCE_KINDS:
            raise ValueError("The FFU physical qualification has an unsupported evidence kind.")
        normalized.append({
            "name": name,
            "kind": kind,
            "sha256": _sha256(item, "sha256", "evidence SHA-256"),
            "description": _text(item, "description", "evidence description"),
        })
    return normalized


def normalize_ffu_physical_qualification(record):
    """Validate and correlate one exact restore and physical boot record."""
    record = _mapping(record, "record")
    if record.get("schema") != 1 or record.get("mode") != "ffu-physical-qualification":
        raise ValueError("The FFU physical qualification uses an unsupported envelope.")

    review = _mapping(record.get("review"), "review evidence")
    restore = _mapping(record.get("restore"), "restore evidence")
    restored = normalize_ffu_restore_output(restore, review)

    package = _mapping(record.get("package"), "package evidence")
    vendor_image = _mapping(record.get("vendor_image"), "vendor-image evidence")
    host = _mapping(record.get("host"), "host evidence")
    target = _mapping(record.get("target"), "physical target evidence")
    firmware = _mapping(record.get("firmware"), "firmware evidence")
    boot = _mapping(record.get("boot"), "boot evidence")

    source_commit = _commit(record)
    package_record = {
        "filename": _text(package, "filename", "package filename"),
        "version": _text(package, "version", "package version"),
        "sha256": _sha256(package, "sha256", "package SHA-256"),
    }
    image_record = {
        "filename": _text(vendor_image, "filename", "vendor-image filename"),
        "size_bytes": _positive_int(vendor_image, "size_bytes", "vendor-image size"),
        "sha256": _sha256(vendor_image, "sha256", "vendor-image SHA-256"),
        "publisher": _text(vendor_image, "publisher", "vendor-image publisher"),
    }
    source_identity = _mapping(review.get("source_identity"), "reviewed source identity")
    review_size = _positive_int(source_identity, "Size", "reviewed FFU source size")
    if image_record["size_bytes"] != review_size:
        raise ValueError("The recorded vendor-image size disagrees with the reviewed FFU source.")

    architecture = _text(host, "architecture", "host architecture").lower()
    if architecture not in {"aarch64", "arm64"}:
        raise ValueError("Physical FFU qualification must run on an ARM64 host.")
    host_record = {
        "architecture": architecture,
        "os_release": _text(host, "os_release", "host operating-system release"),
        "kernel_release": _text(host, "kernel_release", "host kernel release"),
        "model": _text(host, "model", "host model"),
    }

    target_record = {
        "identity": _exact_text(target, "identity", "physical target identity"),
        "capacity_bytes": _positive_int(target, "capacity_bytes", "physical target capacity"),
        "make_model": _text(target, "make_model", "physical target make/model"),
        "serial_or_asset_tag": _text(target, "serial_or_asset_tag", "physical target serial or asset tag"),
        "transport": _text(target, "transport", "physical target transport"),
    }
    if target_record["identity"] != restored["target_identity"]:
        raise ValueError("The physical target identity disagrees with the verified restore evidence.")
    if target_record["capacity_bytes"] != restored["target_size"]:
        raise ValueError("The physical target capacity disagrees with the verified restore evidence.")

    secure_boot = _text(firmware, "secure_boot", "Secure Boot state").lower()
    if secure_boot not in _SECURE_BOOT_STATES:
        raise ValueError("The FFU physical qualification has an unsupported Secure Boot state.")
    firmware_record = {
        "system_model": _text(firmware, "system_model", "firmware system model"),
        "firmware_version": _text(firmware, "firmware_version", "firmware version"),
        "secure_boot": secure_boot,
    }

    attempted = _required_bool(boot, "attempted", "boot attempted")
    booted = _required_bool(boot, "booted", "boot result")
    same_media = _required_bool(boot, "same_restored_media", "same restored media")
    if booted and not attempted:
        raise ValueError("The FFU physical qualification reports a boot without a boot attempt.")
    if same_media and not attempted:
        raise ValueError("The FFU physical qualification binds media without a boot attempt.")
    boot_record = {
        "attempted": attempted,
        "booted": booted,
        "same_restored_media": same_media,
        "tester": _text(boot, "tester", "tester"),
        "date": _date(boot),
        "firmware_entry": _text(boot, "firmware_entry", "firmware boot entry"),
        "observations": _text(boot, "observations", "boot observations"),
    }

    evidence = _normalize_evidence(record.get("evidence"))
    if attempted and not evidence:
        raise ValueError("A physical boot attempt requires at least one hashed evidence item.")

    if restored["outcome"] != "verified":
        decision = "no-go-restore"
    elif not attempted:
        decision = "pending-boot"
    elif booted and same_media and evidence:
        decision = "qualified"
    else:
        decision = "no-go-boot"

    normalized = {
        "schema": 1,
        "mode": "ffu-physical-qualification-result",
        "decision": decision,
        "source_commit": source_commit,
        "package": package_record,
        "vendor_image": image_record,
        "host": host_record,
        "target": target_record,
        "firmware": firmware_record,
        "boot": boot_record,
        "evidence": evidence,
        "restore": {
            "outcome": restored["outcome"],
            "status": restored["status"],
            "target_path": restored["target_path"],
            "target_identity": restored["target_identity"],
            "target_size": restored["target_size"],
            "mutation_bytes_planned": restored["mutation_bytes_planned"],
            "mutation_bytes_written": restored["mutation_bytes_written"],
            "operation_count_planned": restored["operation_count_planned"],
            "operation_count_completed": restored["operation_count_completed"],
            "result_sha256": restored["result_sha256"],
            "review_binding_sha256": restored["review_binding_sha256"],
        },
        "scope": (
            "One exact source commit, package, authenticated vendor FFU, physical target, "
            "ARM64 host, firmware configuration, and observed boot attempt."
        ),
        "universal_support_claimed": False,
    }
    normalized["qualification_sha256"] = _canonical_sha256(normalized)
    return normalized


def ffu_physical_qualification_summary(result):
    """Return bounded publication text for one normalized qualification result."""
    result = _mapping(result, "normalized result")
    decision = result.get("decision")
    if decision == "qualified":
        headline = "Physical FFU qualification passed for the recorded exact configuration."
    elif decision == "pending-boot":
        headline = "The FFU restore is verified, but firmware boot qualification is still pending."
    elif decision == "no-go-boot":
        headline = "NO-GO: the verified FFU target did not pass the recorded firmware boot attempt."
    elif decision == "no-go-restore":
        headline = "NO-GO: the FFU restore evidence is not a verified complete restoration."
    else:
        raise ValueError("Unknown physical FFU qualification decision.")
    restore = _mapping(result.get("restore"), "normalized restore result")
    firmware = _mapping(result.get("firmware"), "normalized firmware result")
    return "\n".join((
        headline,
        f"Target: {restore.get('target_path', '')}",
        f"Restore evidence: {restore.get('result_sha256', '')}",
        f"Firmware: {firmware.get('system_model', '')} / {firmware.get('firmware_version', '')}",
        f"Qualification evidence: {result.get('qualification_sha256', '')}",
        "This record applies only to the exact recorded combination and does not establish universal FFU support.",
    ))
