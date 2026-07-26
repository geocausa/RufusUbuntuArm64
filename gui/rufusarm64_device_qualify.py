"""Pure helpers for the GTK device-qualification and drive-backup workflows."""

import json
import os
import re

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_BACKUP_FORMATS = {"raw", "vhd", "vhdx"}
_BACKUP_PHASES = {"capture", "hash_source", "convert", "hash_output"}


def build_dry_run_command(binary, device, identity, profile):
    _validate(binary, device, identity, profile)
    return [
        binary,
        "--device",
        device,
        "--expected-identity",
        identity,
        "--profile",
        profile,
        "--dry-run",
        "--json",
    ]


def build_run_command(pkexec, binary, device, identity, profile):
    if not pkexec:
        raise ValueError("Administrator authentication helper is unavailable.")
    _validate(binary, device, identity, profile)
    return [
        pkexec,
        binary,
        "--device",
        device,
        "--expected-identity",
        identity,
        "--profile",
        profile,
        "--yes",
        "--json",
    ]


def normalize_plan(payload):
    value = _mapping(payload, "Device qualification returned an invalid plan.")
    device = _mapping(value.get("device"), "Device qualification plan is missing device details.")
    plan = _mapping(value.get("plan"), "Device qualification plan is missing its test plan.")
    regions = plan.get("regions")
    if not isinstance(regions, list) or not regions:
        raise ValueError("Device qualification plan contains no test regions.")
    identity = str(value.get("identity") or "").strip()
    if not identity:
        raise ValueError("Device qualification plan is missing the device identity.")
    return {"device": device, "identity": identity, "plan": plan}


def normalize_report(payload):
    value = _mapping(payload, "Device qualification returned an invalid report.")
    if int(value.get("schema") or 0) != 1:
        raise ValueError("Device qualification report uses an unsupported schema.")
    status = str(value.get("status") or "").strip()
    if status not in {"passed", "failed", "cancelled"}:
        raise ValueError("Device qualification report has an invalid status.")
    passes = value.get("passes")
    if not isinstance(passes, list):
        raise ValueError("Device qualification report is missing pass results.")
    normalized = dict(value)
    normalized["status"] = status
    normalized["passes"] = passes
    return normalized


def plan_summary(plan):
    normalized = normalize_plan(plan)
    device = normalized["device"]
    details = normalized["plan"]
    name = str(device.get("model") or device.get("path") or "selected USB drive")
    profile = str(details.get("profile") or "quick").capitalize()
    regions = len(details["regions"])
    planned = int(details.get("planned_bytes") or 0)
    return f"{profile} qualification will overwrite {regions} test region(s) on {name} ({_human_bytes(planned)} per pass)."


def report_summary(report):
    value = normalize_report(report)
    status = value["status"]
    completed = _human_bytes(int(value.get("completed_bytes") or 0))
    if status == "passed":
        return f"USB qualification passed after {completed} of verified I/O."
    failure = value.get("failure") or {}
    message = str(failure.get("message") or "No detailed failure reason was returned.")
    if value.get("aliasing_detected"):
        message = "False-capacity or aliased storage was detected. " + message
    if status == "cancelled":
        return f"USB qualification was cancelled after {completed}."
    return f"USB qualification failed after {completed}. {message}"


def decode_json_output(output, label):
    try:
        return json.loads(output)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} returned malformed JSON.") from exc


def _validate(binary, device, identity, profile):
    if not binary:
        raise ValueError("Device qualification utility is unavailable.")
    if not str(device or "").startswith("/dev/"):
        raise ValueError("Choose a whole USB drive before qualification.")
    if not str(identity or "").strip():
        raise ValueError("Refresh the USB list before qualification.")
    if profile not in {"quick", "full"}:
        raise ValueError("Qualification profile must be quick or full.")


# Drive-image backup helpers live in this already-packaged pure module so the
# installed launcher and the source-facing compatibility facade use one contract.
def backup_build_dry_run_command(binary, device, identity, output, format_name="raw"):
    format_name = _backup_validate(binary, device, identity, output, format_name)
    return [
        binary,
        "--device",
        device,
        "--output",
        output,
        "--format",
        format_name,
        "--expected-identity",
        identity,
        "--dry-run",
        "--json",
    ]


def backup_build_run_command(pkexec, binary, device, identity, output, format_name="raw"):
    if not pkexec:
        raise ValueError("Administrator authentication helper is unavailable.")
    format_name = _backup_validate(binary, device, identity, output, format_name)
    return [
        pkexec,
        binary,
        "--device",
        device,
        "--output",
        output,
        "--format",
        format_name,
        "--expected-identity",
        identity,
        "--yes",
        "--json",
        "--progress-json",
    ]


def backup_confirmation_phrase(device, output):
    if not str(device or "").startswith("/dev/"):
        raise ValueError("Choose a whole removable drive before saving an image.")
    if not os.path.isabs(str(output or "")):
        raise ValueError("Choose an absolute destination path for the new image.")
    return f"SAVE {device} TO {output}"


def backup_normalize_plan(payload):
    value = _mapping(payload, "Drive-image backup returned an invalid plan.")
    device = _mapping(value.get("device"), "Backup plan is missing source-device details.")
    destination = _mapping(value.get("destination"), "Backup plan is missing destination details.")
    identity = str(value.get("identity") or "").strip()
    if not identity:
        raise ValueError("Backup plan is missing the source identity.")
    path = str(device.get("path") or "").strip()
    output = str(destination.get("path") or "").strip()
    directory = str(destination.get("directory") or "").strip()
    format_name = str(destination.get("format") or "").strip().lower()
    if format_name not in _BACKUP_FORMATS:
        raise ValueError("Backup plan contains an unsupported output format.")
    if not path.startswith("/dev/"):
        raise ValueError("Backup plan contains an invalid source path.")
    if not os.path.isabs(output) or not os.path.isabs(directory):
        raise ValueError("Backup plan contains an invalid destination path.")
    if os.path.dirname(output) != directory:
        raise ValueError("Backup plan contains inconsistent destination details.")
    required = _nonnegative_integer(destination.get("required_bytes"), "required byte count")
    available = _nonnegative_integer(destination.get("available_bytes"), "available byte count")
    source_bytes = _nonnegative_integer(destination.get("source_bytes"), "source byte count")
    minimum = _nonnegative_integer(destination.get("container_minimum_bytes", 0), "container minimum byte count")
    size = _nonnegative_integer(device.get("size"), "source capacity")
    if required <= 0 or size <= 0 or source_bytes != size:
        raise ValueError("Backup plan reports an invalid source capacity.")
    if format_name == "raw":
        if required != size or minimum != 0:
            raise ValueError("Raw backup plan contains invalid destination sizing.")
    elif minimum <= 0 or minimum > required:
        raise ValueError("Container backup plan contains invalid allocation bounds.")
    if available < required:
        raise ValueError("Backup plan reports insufficient destination space.")
    normalized_device = dict(device)
    normalized_device["path"] = path
    normalized_device["size"] = size
    normalized_destination = dict(destination)
    normalized_destination.update(
        {
            "path": output,
            "directory": directory,
            "format": format_name,
            "source_bytes": source_bytes,
            "required_bytes": required,
            "container_minimum_bytes": minimum,
            "available_bytes": available,
        }
    )
    return {"device": normalized_device, "identity": identity, "destination": normalized_destination}


def backup_normalize_progress(payload):
    value = _mapping(payload, "Backup progress record is invalid.")
    if int(value.get("schema") or 0) != 2 or value.get("type") != "progress":
        raise ValueError("Backup progress record uses an unsupported schema or type.")
    phase = str(value.get("phase") or "").strip()
    if phase not in _BACKUP_PHASES:
        raise ValueError("Backup progress record contains an unsupported phase.")
    done = _nonnegative_integer(value.get("done"), "completed byte count")
    total = _nonnegative_integer(value.get("total"), "total byte count")
    elapsed_ms = _nonnegative_integer(value.get("elapsed_ms"), "elapsed time")
    rate = _nonnegative_integer(value.get("bytes_per_second"), "transfer rate")
    if total <= 0 or done > total:
        raise ValueError("Backup progress record contains invalid byte accounting.")
    eta = value.get("eta_seconds")
    if eta is not None:
        eta = _nonnegative_integer(eta, "ETA")
    normalized = dict(value)
    normalized.update(
        {
            "schema": 2,
            "type": "progress",
            "phase": phase,
            "done": done,
            "total": total,
            "elapsed_ms": elapsed_ms,
            "bytes_per_second": rate,
            "eta_seconds": eta,
        }
    )
    return normalized


def backup_normalize_report(payload):
    value = _mapping(payload, "Drive-image backup returned an invalid report.")
    if int(value.get("schema") or 0) != 2:
        raise ValueError("Drive-image backup report uses an unsupported schema.")
    status = str(value.get("status") or "").strip()
    if status not in {"passed", "failed", "cancelled"}:
        raise ValueError("Drive-image backup report has an invalid status.")
    format_name = str(value.get("format") or "").strip().lower()
    if format_name not in _BACKUP_FORMATS:
        raise ValueError("Drive-image backup report contains an unsupported format.")
    planned = _nonnegative_integer(value.get("planned_bytes"), "planned byte count")
    completed = _nonnegative_integer(value.get("completed_bytes"), "completed byte count")
    output_bytes = _nonnegative_integer(value.get("output_bytes", 0), "output byte count")
    if planned <= 0 or completed > planned:
        raise ValueError("Drive-image backup report contains invalid byte accounting.")
    legacy_hash = str(value.get("sha256") or "").strip().lower()
    source_hash = str(value.get("source_sha256") or "").strip().lower()
    output_hash = str(value.get("output_sha256") or "").strip().lower()
    comparison = str(value.get("content_comparison") or "").strip()
    consistency = str(value.get("consistency") or "").strip()
    failure = value.get("failure")
    if status == "passed":
        if completed != planned or failure is not None:
            raise ValueError("Successful backup report is incomplete or includes a failure record.")
        if not all(_SHA256_RE.fullmatch(item) for item in (legacy_hash, source_hash, output_hash)):
            raise ValueError("Successful backup report is missing complete SHA-256 evidence.")
        if legacy_hash != source_hash or output_bytes <= 0 or comparison != "passed":
            raise ValueError("Successful backup report contains inconsistent verification evidence.")
        if format_name == "raw":
            if output_bytes != planned or output_hash != source_hash or consistency != "not_applicable":
                raise ValueError("Successful raw backup report contains inconsistent evidence.")
        elif format_name == "vhd":
            if consistency != "unsupported":
                raise ValueError("Successful VHD backup report contains invalid consistency evidence.")
        elif consistency != "passed":
            raise ValueError("Successful VHDX backup report is missing consistency evidence.")
    else:
        if any((legacy_hash, source_hash, output_hash, output_bytes, comparison, consistency)):
            raise ValueError("Failed or cancelled backup report must not claim completed verification evidence.")
        if not isinstance(failure, dict):
            raise ValueError("Failed or cancelled backup report is missing its failure record.")
        kind = str(failure.get("kind") or "").strip()
        message = str(failure.get("message") or "").strip()
        if not kind or not message:
            raise ValueError("Backup failure record is incomplete.")
        byte_offset = failure.get("byte_offset")
        if byte_offset is not None:
            byte_offset = _nonnegative_integer(byte_offset, "failure byte offset")
            if byte_offset > completed:
                raise ValueError("Backup failure offset exceeds the completed byte count.")
        failure = dict(failure)
        failure.update({"kind": kind, "message": message})
        if byte_offset is not None:
            failure["byte_offset"] = byte_offset
    normalized = dict(value)
    normalized.update(
        {
            "schema": 2,
            "status": status,
            "format": format_name,
            "planned_bytes": planned,
            "completed_bytes": completed,
            "sha256": legacy_hash,
            "source_sha256": source_hash,
            "output_sha256": output_hash,
            "output_bytes": output_bytes,
            "content_comparison": comparison,
            "consistency": consistency,
            "failure": failure,
        }
    )
    return normalized


def backup_decode_progress_line(line):
    try:
        payload = json.loads(str(line or "").strip())
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or payload.get("type") != "progress":
        return None
    return backup_normalize_progress(payload)


def backup_plan_summary(plan):
    value = backup_normalize_plan(plan)
    device = value["device"]
    destination = value["destination"]
    name = " ".join(
        part for part in (str(device.get("vendor") or "").strip(), str(device.get("model") or "").strip()) if part
    ) or str(device.get("path") or "selected drive")
    minimum = ""
    if destination["container_minimum_bytes"]:
        minimum = f" Minimum container estimate: {_human_bytes(destination['container_minimum_bytes'])}; admission remains conservative."
    return (
        f"Source: {name} ({device['path']}), {_human_bytes(device['size'])}.\n"
        f"Destination filesystem: {destination['directory']}; {destination['format'].upper()} image: {destination['path']}.\n"
        f"Conservative required: {_human_bytes(destination['required_bytes'])}; available: "
        f"{_human_bytes(destination['available_bytes'])}.{minimum} The source will be opened read-only."
    )


def backup_progress_summary(progress):
    value = backup_normalize_progress(progress)
    percent = value["done"] * 100.0 / value["total"]
    rate = _human_bytes(value["bytes_per_second"]) + "/s" if value["bytes_per_second"] else "measuring speed"
    eta = _human_duration(value["eta_seconds"]) if value["eta_seconds"] is not None else "estimating time"
    phase = value["phase"].replace("_", " ").capitalize()
    return (
        f"{phase}: {percent:.1f}% — {_human_bytes(value['done'])} of {_human_bytes(value['total'])}; "
        f"{rate}; {eta} remaining"
    )


def backup_report_summary(report, output):
    value = backup_normalize_report(report)
    completed = _human_bytes(value["completed_bytes"])
    if value["status"] == "passed":
        return (
            f"{value['format'].upper()} drive image saved to {output} ({_human_bytes(value['output_bytes'])}); "
            f"source SHA-256 {value['source_sha256']}; output SHA-256 {value['output_sha256']}."
        )
    failure = value.get("failure") or {}
    message = str(failure.get("message") or "No detailed failure reason was returned.")
    if value["status"] == "cancelled":
        return f"Drive-image backup was cancelled after {completed}."
    return f"Drive-image backup failed after {completed}. {message}"


def _backup_validate(binary, device, identity, output, format_name):
    if not binary:
        raise ValueError("Drive-image backup utility is unavailable.")
    if not str(device or "").startswith("/dev/"):
        raise ValueError("Choose a whole removable drive before saving an image.")
    if not str(identity or "").strip():
        raise ValueError("Refresh the USB list before saving an image.")
    output = str(output or "")
    if not os.path.isabs(output):
        raise ValueError("Choose an absolute destination path for the new image.")
    if os.path.lexists(output):
        raise ValueError("Choose a new destination path; existing files and symbolic links are never replaced.")
    format_name = str(format_name or "").strip().lower()
    if format_name not in _BACKUP_FORMATS:
        raise ValueError("Drive-image format must be raw, vhd, or vhdx.")
    return format_name


def _mapping(value, message):
    if not isinstance(value, dict):
        raise ValueError(message)
    return value


def _nonnegative_integer(value, label):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"Backup {label} is invalid.")
    if value < 0:
        raise ValueError(f"Backup {label} is invalid.")
    return value


def _human_bytes(value):
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    number = float(max(0, int(value)))
    for unit in units:
        if number < 1024 or unit == units[-1]:
            return f"{number:.1f} {unit}" if unit != "B" else f"{int(number)} B"
        number /= 1024
    return f"{int(value)} B"


def _human_duration(seconds):
    value = max(0, int(seconds))
    if value < 60:
        return f"{value}s"
    minutes, remaining = divmod(value, 60)
    if minutes < 60:
        return f"{minutes}m {remaining:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m"
