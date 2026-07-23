"""Pure contracts for the guarded graphical FreeDOS formatting workflow."""

from datetime import datetime
import json
import os
import re


FREEDOS_WARNINGS = [
    "This operation erases the complete selected drive.",
    "The resulting media runs only on x86-compatible processors.",
    "The resulting media requires BIOS or UEFI Legacy/CSM firmware and is not for UEFI-only systems.",
    "Software verification cannot prove that a particular physical PC will boot the media.",
]
STATUSES = {"succeeded", "failed", "cancelled"}
PHASES = {"plan", "prepare", "write", "flush", "readback", "finish", "complete"}
PROGRESS_PREFIX = "RUFUSARM64_PROGRESS "
PROGRESS_PHASE_LABELS = {
    "prepare": "Preparing the target",
    "write": "Writing required boot and filesystem regions",
    "flush": "Flushing device buffers",
    "readback": "Verifying required boot and filesystem regions",
    "finish": "Finalizing and revalidating",
    "complete": "Complete",
}
SECTOR_SIZE = 512
PARTITION_START_SECTOR = 2048
TAIL_RESERVE_SECTORS = 2048
PARTITION_TYPE = "0c"
FILESYSTEM = "FAT32"
DISTRIBUTION = "FreeDOS 1.4"
TARGET_CPU = "x86"
FIRMWARE = "BIOS or UEFI Legacy/CSM"
VERIFICATION_SCOPE = "required-filesystem-extents"


def build_dry_run_command(binary, device, identity, label):
    """Build the unprivileged identity-bound planning command."""
    _validate_request(binary, device, identity, label)
    return [
        binary,
        "--device",
        device,
        "--expected-identity",
        identity,
        "--label",
        label,
        "--dry-run",
        "--json",
    ]


def build_run_command(pkexec, binary, device, identity, label, cancel_file):
    """Build the reviewed Polkit execution command without escape hatches."""
    if not os.path.isabs(str(pkexec or "")):
        raise ValueError("Ubuntu administrator authentication is unavailable.")
    _validate_request(binary, device, identity, label)
    cancel_file = str(cancel_file or "")
    if not os.path.isabs(cancel_file) or not cancel_file.startswith("/run/user/"):
        raise ValueError("A private cancellation channel beneath /run/user is required.")
    return [
        pkexec,
        binary,
        "--device",
        device,
        "--expected-identity",
        identity,
        "--label",
        label,
        "--cancel-file",
        cancel_file,
        "--yes",
        "--json",
    ]


def confirmation_phrase(payload):
    """Return the exact helper-generated destructive confirmation phrase."""
    value = normalize_plan(payload)
    return value["confirmation"]


def normalize_plan(payload):
    """Validate and normalize one unprivileged FreeDOS plan."""
    value = _mapping(payload, "FreeDOS formatting returned an invalid plan.")
    device = _mapping(value.get("device"), "FreeDOS plan is missing device details.")
    identity = _text(value.get("identity"), "FreeDOS plan is missing the device identity.")
    plan = _normalize_plan_fields(value.get("plan"))

    device_path = _text(device.get("path"), "FreeDOS plan contains an invalid device path.")
    device_size = _positive_integer(device.get("size"), "device capacity")
    if device_path != plan["device_path"] or device_size != plan["device_size_bytes"]:
        raise ValueError("FreeDOS plan device details do not match its guarded plan.")
    if identity != plan["expected_identity"]:
        raise ValueError("FreeDOS plan identity does not match its guarded plan.")

    expected = _phrase_from_fields(plan)
    returned = _text(value.get("confirmation"), "FreeDOS plan is missing its confirmation phrase.")
    if returned != expected:
        raise ValueError("FreeDOS plan returned an inconsistent confirmation phrase.")

    normalized_device = dict(device)
    normalized_device.update({"path": device_path, "size": device_size})
    return {
        "device": normalized_device,
        "identity": identity,
        "plan": plan,
        "confirmation": returned,
    }


def normalize_report(payload, reviewed_plan=None):
    """Validate a final execution report against the exact reviewed plan."""
    value = _mapping(payload, "FreeDOS formatting returned an invalid report.")
    if _integer(value.get("schema"), "report schema") != 2:
        raise ValueError("FreeDOS report uses an unsupported schema.")
    status = _text(value.get("status"), "FreeDOS report is missing its status.")
    phase = _text(value.get("phase"), "FreeDOS report is missing its phase.")
    if status not in STATUSES or phase not in PHASES:
        raise ValueError("FreeDOS report contains an invalid status or phase.")

    plan = _normalize_plan_fields(value.get("plan"))
    if reviewed_plan is not None:
        reviewed = normalize_plan(reviewed_plan)
        if plan != reviewed["plan"]:
            raise ValueError("FreeDOS report does not match the reviewed plan.")

    started_at = _timestamp(value.get("started_at"), "start time")
    completed_at = _timestamp(value.get("completed_at"), "completion time")
    if completed_at < started_at:
        raise ValueError("FreeDOS report completion time precedes its start time.")

    bytes_written = _nonnegative_integer(value.get("bytes_written"), "bytes written")
    bytes_verified = _nonnegative_integer(value.get("bytes_verified"), "bytes verified")
    verification_scope = _text(value.get("verification_scope"), "FreeDOS report is missing its verification scope.")
    media_changed = _boolean(value.get("media_changed"), "media-changed state")
    verified = _boolean(value.get("verified"), "verification state")
    reusable = _boolean(value.get("reusable"), "reusable state")
    sha256 = str(value.get("sha256") or "")
    failure_reason = str(value.get("failure_reason") or "").strip()

    if verification_scope != VERIFICATION_SCOPE:
        raise ValueError("FreeDOS report verification scope was altered.")
    if sha256 and not re.fullmatch(r"[0-9a-f]{64}", sha256):
        raise ValueError("FreeDOS report contains an invalid SHA-256 digest.")
    if bytes_written > plan["mutation_bytes"] or bytes_verified > plan["verification_bytes"]:
        raise ValueError("FreeDOS report exceeds the reviewed required-extent totals.")
    if not media_changed and (bytes_written != 0 or bytes_verified != 0):
        raise ValueError("Unchanged FreeDOS media cannot report accepted or verified bytes.")
    if verified and (
        not media_changed
        or bytes_written != plan["mutation_bytes"]
        or bytes_verified != plan["verification_bytes"]
        or not sha256
    ):
        raise ValueError("Verified FreeDOS state contradicts the required-extent report.")

    if status == "succeeded":
        if (
            phase != "complete"
            or not media_changed
            or not verified
            or not reusable
            or bytes_written != plan["mutation_bytes"]
            or bytes_verified != plan["verification_bytes"]
            or not sha256
            or failure_reason
        ):
            raise ValueError("Successful FreeDOS report has inconsistent completion state.")
    else:
        if reusable or not failure_reason:
            raise ValueError("Incomplete FreeDOS report must be non-reusable and explain the failure.")
        if phase == "complete":
            raise ValueError("Incomplete FreeDOS report cannot claim the complete phase.")

    normalized = dict(value)
    normalized.update(
        {
            "schema": 2,
            "status": status,
            "phase": phase,
            "plan": plan,
            "started_at": value["started_at"],
            "completed_at": value["completed_at"],
            "bytes_written": bytes_written,
            "bytes_verified": bytes_verified,
            "verification_scope": VERIFICATION_SCOPE,
            "sha256": sha256,
            "media_changed": media_changed,
            "verified": verified,
            "reusable": reusable,
            "failure_reason": failure_reason,
        }
    )
    return normalized


def normalize_progress(payload):
    """Validate one bounded helper progress record."""
    value = _mapping(payload, "FreeDOS progress record is invalid.")
    if _integer(value.get("schema"), "progress schema") != 1 or value.get("type") != "progress":
        raise ValueError("FreeDOS progress record uses an unsupported schema or type.")
    phase = _text(value.get("phase"), "FreeDOS progress record is missing its phase.")
    if phase not in PROGRESS_PHASE_LABELS:
        raise ValueError("FreeDOS progress record contains an invalid phase.")
    done = _nonnegative_integer(value.get("done"), "progress byte count")
    total = _nonnegative_integer(value.get("total"), "progress phase total")
    overall_done = _nonnegative_integer(value.get("overall_done"), "overall completed byte count")
    overall_total = _positive_integer(value.get("overall_total"), "overall byte total")
    elapsed_ms = _nonnegative_integer(value.get("elapsed_ms"), "progress elapsed time")
    rate = _nonnegative_integer(value.get("bytes_per_second"), "progress transfer rate")
    eta = value.get("eta_seconds")
    if eta is not None:
        eta = _nonnegative_integer(eta, "progress ETA")
    if done > total or overall_done > overall_total:
        raise ValueError("FreeDOS progress exceeds its reviewed byte totals.")
    if phase in {"write", "readback"} and total <= 0:
        raise ValueError("FreeDOS byte-bearing progress phase has no total.")
    if phase not in {"write", "readback"} and (done != 0 or total != 0):
        raise ValueError("FreeDOS non-byte progress phase claimed byte accounting.")
    normalized = dict(value)
    normalized.update(
        {
            "schema": 1,
            "type": "progress",
            "phase": phase,
            "done": done,
            "total": total,
            "overall_done": overall_done,
            "overall_total": overall_total,
            "elapsed_ms": elapsed_ms,
            "bytes_per_second": rate,
            "eta_seconds": eta,
        }
    )
    return normalized


def decode_progress_line(line):
    """Decode only explicitly prefixed helper progress; diagnostics remain diagnostics."""
    text = str(line or "").strip()
    if not text.startswith(PROGRESS_PREFIX):
        return None
    try:
        payload = json.loads(text[len(PROGRESS_PREFIX) :])
    except json.JSONDecodeError as exc:
        raise ValueError("FreeDOS helper returned malformed progress JSON.") from exc
    return normalize_progress(payload)


def progress_summary(payload):
    """Render current phase, overall percentage, rate, elapsed time, and ETA."""
    value = normalize_progress(payload)
    percent = value["overall_done"] * 100.0 / value["overall_total"]
    rate = _human_bytes(value["bytes_per_second"]) + "/s" if value["bytes_per_second"] else "measuring speed"
    elapsed = _human_duration(value["elapsed_ms"] // 1000)
    eta = _human_duration(value["eta_seconds"]) + " remaining" if value["eta_seconds"] is not None else "estimating time"
    return (
        f"{PROGRESS_PHASE_LABELS[value['phase']]}: {percent:.1f}% — "
        f"{_human_bytes(value['overall_done'])} of {_human_bytes(value['overall_total'])}; "
        f"{rate}; {elapsed} elapsed; {eta}"
    )


def plan_summary(payload):
    """Render the exact pre-authentication platform and layout boundary."""
    value = normalize_plan(payload)
    device = value["device"]
    plan = value["plan"]
    name = " ".join(
        part
        for part in (
            str(device.get("vendor") or "").strip(),
            str(device.get("model") or "").strip(),
        )
        if part
    ) or plan["device_path"]
    warnings = "\n".join(f"• {item}" for item in plan["warnings"])
    total_io = plan["mutation_bytes"] + plan["verification_bytes"]
    return (
        f"Target: {name} ({plan['device_path']}), {_human_bytes(plan['device_size_bytes'])}.\n"
        f"Media: {plan['distribution']}, one active FAT32-LBA partition, label \"{plan['label']}\".\n"
        f"Partition: starts at {_human_bytes(plan['partition_start_bytes'])}; "
        f"size {_human_bytes(plan['partition_size_bytes'])}.\n"
        f"Fast creation I/O: writes {_human_bytes(plan['mutation_bytes'])} of required boot/FAT32 data and "
        f"reads {_human_bytes(plan['verification_bytes'])} back ({_human_bytes(total_io)} total). "
        f"{_human_bytes(plan['untouched_bytes'])} of unallocated data remains untouched; use Check USB for an "
        f"exhaustive whole-device test.\n"
        f"Platform: x86 only; BIOS or UEFI Legacy/CSM only. Not ARM64 or UEFI-only.\n{warnings}"
    )


def report_summary(payload):
    """Render a conservative final media-state summary."""
    value = normalize_report(payload)
    if value["status"] == "succeeded":
        return (
            f"Verified {DISTRIBUTION} media is ready for x86 BIOS or UEFI Legacy/CSM systems. "
            f"Required boot/filesystem extents were read back; extent-set SHA-256: {value['sha256']}. "
            "Unallocated data was not used as a device test. It will not boot ARM64 or UEFI-only computers; "
            "physical boot remains unproven."
        )
    if value["status"] == "cancelled" and not value["media_changed"]:
        return "FreeDOS creation was cancelled before erasure; the selected drive was not changed."
    state = (
        "The drive was changed and is not reusable until successfully recreated or reformatted."
        if value["media_changed"]
        else "The drive was not changed."
    )
    verb = "cancelled" if value["status"] == "cancelled" else "failed"
    return f"FreeDOS creation {verb} during {value['phase']}. {state} {value['failure_reason']}"


def _normalize_plan_fields(payload):
    plan = _mapping(payload, "FreeDOS plan is missing its guarded plan.")
    if _integer(plan.get("schema"), "plan schema") != 2 or plan.get("mode") != "freedos":
        raise ValueError("FreeDOS plan uses an unsupported schema or mode.")
    if plan.get("bootable") is not True or plan.get("destructive") is not True:
        raise ValueError("FreeDOS plan contains an invalid safety envelope.")

    device_path = _canonical_device_path(plan.get("device_path"))
    identity = _text(plan.get("expected_identity"), "FreeDOS plan is missing its expected identity.")
    device_size = _positive_integer(plan.get("device_size_bytes"), "device capacity")
    sector_size = _positive_integer(plan.get("logical_sector_size"), "logical sector size")
    if sector_size != SECTOR_SIZE:
        raise ValueError("FreeDOS media requires 512-byte logical sectors.")

    target_cpu = _text(plan.get("target_cpu"), "FreeDOS plan is missing its CPU boundary.")
    firmware = _text(plan.get("firmware"), "FreeDOS plan is missing its firmware boundary.")
    distribution = _text(plan.get("distribution"), "FreeDOS plan is missing its distribution.")
    if target_cpu != TARGET_CPU or firmware != FIRMWARE or distribution != DISTRIBUTION:
        raise ValueError("FreeDOS plan platform or distribution boundary was altered.")

    if _integer(plan.get("partition_number"), "partition number") != 1:
        raise ValueError("FreeDOS plan must contain exactly one partition.")
    start = _positive_integer(plan.get("partition_start_bytes"), "partition start")
    size = _positive_integer(plan.get("partition_size_bytes"), "partition size")
    if start != PARTITION_START_SECTOR * SECTOR_SIZE:
        raise ValueError("FreeDOS partition does not begin at the reviewed 1 MiB boundary.")
    if start + size + TAIL_RESERVE_SECTORS * SECTOR_SIZE != device_size:
        raise ValueError("FreeDOS partition does not preserve the reviewed 1 MiB tail reservation.")
    if plan.get("partition_type") != PARTITION_TYPE or plan.get("filesystem") != FILESYSTEM:
        raise ValueError("FreeDOS partition or filesystem contract was altered.")

    mutation_bytes = _positive_integer(plan.get("mutation_bytes"), "mutation byte total")
    verification_bytes = _positive_integer(plan.get("verification_bytes"), "verification byte total")
    untouched_bytes = _positive_integer(plan.get("untouched_bytes"), "untouched byte total")
    if mutation_bytes != verification_bytes:
        raise ValueError("FreeDOS write and verification extent totals differ.")
    if mutation_bytes >= device_size or mutation_bytes + untouched_bytes != device_size:
        raise ValueError("FreeDOS extent accounting does not preserve unallocated data space.")

    label = _normalize_label(plan.get("label"))
    media = _normalize_media(plan.get("media"), device_size, label)
    if media["partition_start_sector"] * SECTOR_SIZE != start:
        raise ValueError("FreeDOS nested media start does not match the device plan.")
    if media["partition_sector_count"] * SECTOR_SIZE != size:
        raise ValueError("FreeDOS nested media size does not match the device plan.")

    warnings = plan.get("warnings")
    if warnings != FREEDOS_WARNINGS:
        raise ValueError("FreeDOS plan safety warnings are incomplete or altered.")

    return {
        "schema": 2,
        "mode": "freedos",
        "bootable": True,
        "destructive": True,
        "target_cpu": TARGET_CPU,
        "firmware": FIRMWARE,
        "distribution": DISTRIBUTION,
        "device_path": device_path,
        "expected_identity": identity,
        "device_size_bytes": device_size,
        "logical_sector_size": SECTOR_SIZE,
        "partition_number": 1,
        "partition_start_bytes": start,
        "partition_size_bytes": size,
        "partition_type": PARTITION_TYPE,
        "filesystem": FILESYSTEM,
        "label": label,
        "mutation_bytes": mutation_bytes,
        "verification_bytes": verification_bytes,
        "untouched_bytes": untouched_bytes,
        "media": media,
        "warnings": list(warnings),
    }


def _normalize_media(payload, device_size, label):
    media = _mapping(payload, "FreeDOS plan is missing its deterministic media contract.")
    if _integer(media.get("schema"), "media schema") != 1:
        raise ValueError("FreeDOS media uses an unsupported schema.")
    disk_size = _positive_integer(media.get("disk_size_bytes"), "media size")
    sector_size = _positive_integer(media.get("logical_sector_size"), "media sector size")
    start_sector = _positive_integer(media.get("partition_start_sector"), "media partition start")
    sector_count = _positive_integer(media.get("partition_sector_count"), "media partition size")
    sectors_per_cluster = _positive_integer(media.get("sectors_per_cluster"), "sectors per cluster")
    sectors_per_track = _positive_integer(media.get("sectors_per_track"), "sectors per track")
    heads = _positive_integer(media.get("heads"), "head count")
    media_label = _normalize_label(media.get("label"))

    if disk_size != device_size or sector_size != SECTOR_SIZE:
        raise ValueError("FreeDOS media size or sector binding is inconsistent.")
    if start_sector != PARTITION_START_SECTOR:
        raise ValueError("FreeDOS media partition start was altered.")
    if start_sector + sector_count + TAIL_RESERVE_SECTORS != disk_size // SECTOR_SIZE:
        raise ValueError("FreeDOS media geometry does not preserve the reviewed reservations.")
    if sectors_per_cluster != _expected_sectors_per_cluster(sector_count * SECTOR_SIZE):
        raise ValueError("FreeDOS cluster size does not match the reviewed size table.")
    if sectors_per_track != 63 or heads != 255 or media_label != label:
        raise ValueError("FreeDOS CHS geometry or media label was altered.")

    return {
        "schema": 1,
        "disk_size_bytes": disk_size,
        "logical_sector_size": SECTOR_SIZE,
        "partition_start_sector": start_sector,
        "partition_sector_count": sector_count,
        "sectors_per_cluster": sectors_per_cluster,
        "sectors_per_track": 63,
        "heads": 255,
        "label": media_label,
    }


def _expected_sectors_per_cluster(partition_bytes):
    if partition_bytes < 32 * 1024 * 1024:
        raise ValueError("FreeDOS FAT32 partition is below the reviewed 32 MiB boundary.")
    if partition_bytes < 64 * 1024 * 1024:
        return 1
    if partition_bytes < 128 * 1024 * 1024:
        return 2
    if partition_bytes < 256 * 1024 * 1024:
        return 4
    if partition_bytes < 8 * 1024 * 1024 * 1024:
        return 8
    if partition_bytes < 16 * 1024 * 1024 * 1024:
        return 16
    if partition_bytes < 32 * 1024 * 1024 * 1024:
        return 32
    if partition_bytes < 2 * 1024 * 1024 * 1024 * 1024:
        return 64
    raise ValueError("FreeDOS FAT32 partition reaches the unsupported 2 TiB boundary.")


def _phrase_from_fields(plan):
    return f"WRITE FREEDOS 1.4 TO {plan['device_path']} FOR X86 BIOS LEGACY"


def _validate_request(binary, device, identity, label):
    if not os.path.isabs(str(binary or "")):
        raise ValueError("The packaged FreeDOS formatter is unavailable.")
    _canonical_device_path(device)
    if not str(identity or "").strip():
        raise ValueError("Refresh the USB list before creating FreeDOS media.")
    _normalize_label(label)


def _canonical_device_path(value):
    path = str(value or "").strip()
    if not os.path.isabs(path) or not path.startswith("/dev/") or os.path.normpath(path) != path:
        raise ValueError("Choose one canonical whole removable drive before creating FreeDOS media.")
    return path


def _normalize_label(value):
    if not isinstance(value, str) or value.strip() != value:
        raise ValueError("FreeDOS label must be canonical text without surrounding whitespace.")
    if not 1 <= len(value) <= 11:
        raise ValueError("FreeDOS label must contain 1 to 11 characters.")
    if any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for character in value):
        raise ValueError("FreeDOS label must use uppercase ASCII letters, digits, '-' or '_'.")
    return value


def _timestamp(value, label):
    text = _text(value, f"FreeDOS report is missing its {label}.")
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"FreeDOS report has an invalid {label}.") from exc


def _mapping(value, message):
    if not isinstance(value, dict):
        raise ValueError(message)
    return value


def _text(value, message):
    text = str(value or "").strip()
    if not text:
        raise ValueError(message)
    return text


def _integer(value, label):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"FreeDOS {label} must be an exact integer.")
    return value


def _positive_integer(value, label):
    number = _integer(value, label)
    if number <= 0:
        raise ValueError(f"FreeDOS {label} must be positive.")
    return number


def _nonnegative_integer(value, label):
    number = _integer(value, label)
    if number < 0:
        raise ValueError(f"FreeDOS {label} must not be negative.")
    return number


def _boolean(value, label):
    if not isinstance(value, bool):
        raise ValueError(f"FreeDOS {label} must be a boolean.")
    return value


def _human_duration(seconds):
    seconds = max(0, int(seconds))
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


def _human_bytes(value):
    amount = float(value)
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    index = 0
    while amount >= 1024 and index < len(units) - 1:
        amount /= 1024
        index += 1
    return f"{amount:.1f} {units[index]}" if index else f"{int(amount)} {units[index]}"
