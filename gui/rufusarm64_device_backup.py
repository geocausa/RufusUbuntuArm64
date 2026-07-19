"""Pure helpers for the GTK drive-image backup workflow."""

import json
import os
import re

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def build_dry_run_command(binary, device, identity, output):
    _validate(binary, device, identity, output)
    return [
        binary,
        "--device",
        device,
        "--output",
        output,
        "--expected-identity",
        identity,
        "--dry-run",
        "--json",
    ]


def build_run_command(pkexec, binary, device, identity, output):
    if not pkexec:
        raise ValueError("Administrator authentication helper is unavailable.")
    _validate(binary, device, identity, output)
    return [
        pkexec,
        binary,
        "--device",
        device,
        "--output",
        output,
        "--expected-identity",
        identity,
        "--yes",
        "--json",
        "--progress-json",
    ]


def normalize_plan(payload):
    value = _mapping(payload, "Drive-image backup returned an invalid plan.")
    device = _mapping(value.get("device"), "Backup plan is missing source-device details.")
    destination = _mapping(value.get("destination"), "Backup plan is missing destination details.")
    identity = str(value.get("identity") or "").strip()
    if not identity:
        raise ValueError("Backup plan is missing the source identity.")
    path = str(device.get("path") or "").strip()
    output = str(destination.get("path") or "").strip()
    if not path.startswith("/dev/"):
        raise ValueError("Backup plan contains an invalid source path.")
    if not os.path.isabs(output):
        raise ValueError("Backup plan contains an invalid destination path.")
    required = _nonnegative_integer(destination.get("required_bytes"), "required byte count")
    available = _nonnegative_integer(destination.get("available_bytes"), "available byte count")
    if required <= 0:
        raise ValueError("Backup plan reports an empty source device.")
    if available < required:
        raise ValueError("Backup plan reports insufficient destination space.")
    normalized_destination = dict(destination)
    normalized_destination["path"] = output
    normalized_destination["required_bytes"] = required
    normalized_destination["available_bytes"] = available
    return {"device": dict(device), "identity": identity, "destination": normalized_destination}


def normalize_progress(payload):
    value = _mapping(payload, "Backup progress record is invalid.")
    if int(value.get("schema") or 0) != 1 or value.get("type") != "progress":
        raise ValueError("Backup progress record uses an unsupported schema or type.")
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
            "schema": 1,
            "type": "progress",
            "done": done,
            "total": total,
            "elapsed_ms": elapsed_ms,
            "bytes_per_second": rate,
            "eta_seconds": eta,
        }
    )
    return normalized


def normalize_report(payload):
    value = _mapping(payload, "Drive-image backup returned an invalid report.")
    if int(value.get("schema") or 0) != 1:
        raise ValueError("Drive-image backup report uses an unsupported schema.")
    status = str(value.get("status") or "").strip()
    if status not in {"passed", "failed", "cancelled"}:
        raise ValueError("Drive-image backup report has an invalid status.")
    planned = _nonnegative_integer(value.get("planned_bytes"), "planned byte count")
    completed = _nonnegative_integer(value.get("completed_bytes"), "completed byte count")
    if planned <= 0 or completed > planned:
        raise ValueError("Drive-image backup report contains invalid byte accounting.")
    sha256 = str(value.get("sha256") or "").strip().lower()
    if status == "passed":
        if completed != planned or not _SHA256_RE.fullmatch(sha256):
            raise ValueError("Successful backup report is incomplete or missing its SHA-256 digest.")
    elif sha256:
        raise ValueError("Failed or cancelled backup report must not claim a SHA-256 digest.")
    failure = value.get("failure")
    if failure is not None and not isinstance(failure, dict):
        raise ValueError("Drive-image backup report contains an invalid failure record.")
    normalized = dict(value)
    normalized.update(
        {
            "schema": 1,
            "status": status,
            "planned_bytes": planned,
            "completed_bytes": completed,
            "sha256": sha256,
            "failure": failure,
        }
    )
    return normalized


def decode_progress_line(line):
    try:
        payload = json.loads(str(line or "").strip())
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or payload.get("type") != "progress":
        return None
    return normalize_progress(payload)


def plan_summary(plan):
    value = normalize_plan(plan)
    device = value["device"]
    destination = value["destination"]
    name = " ".join(
        part for part in (str(device.get("vendor") or "").strip(), str(device.get("model") or "").strip()) if part
    ) or str(device.get("path") or "selected drive")
    return (
        f"Save {_human_bytes(destination['required_bytes'])} from {name} to {destination['path']}. "
        f"The destination filesystem has {_human_bytes(destination['available_bytes'])} available."
    )


def progress_summary(progress):
    value = normalize_progress(progress)
    percent = value["done"] * 100.0 / value["total"]
    rate = _human_bytes(value["bytes_per_second"]) + "/s" if value["bytes_per_second"] else "measuring speed"
    eta = _human_duration(value["eta_seconds"]) if value["eta_seconds"] is not None else "estimating time"
    return (
        f"{percent:.1f}% — {_human_bytes(value['done'])} of {_human_bytes(value['total'])}; "
        f"{rate}; {eta} remaining"
    )


def report_summary(report, output):
    value = normalize_report(report)
    completed = _human_bytes(value["completed_bytes"])
    if value["status"] == "passed":
        return f"Drive image saved to {output} ({completed}); SHA-256 {value['sha256']}."
    failure = value.get("failure") or {}
    message = str(failure.get("message") or "No detailed failure reason was returned.")
    if value["status"] == "cancelled":
        return f"Drive-image backup was cancelled after {completed}."
    return f"Drive-image backup failed after {completed}. {message}"


def _validate(binary, device, identity, output):
    if not binary:
        raise ValueError("Drive-image backup utility is unavailable.")
    if not str(device or "").startswith("/dev/"):
        raise ValueError("Choose a whole removable drive before saving an image.")
    if not str(identity or "").strip():
        raise ValueError("Refresh the USB list before saving an image.")
    if not os.path.isabs(str(output or "")):
        raise ValueError("Choose an absolute destination path for the new image.")


def _mapping(value, message):
    if not isinstance(value, dict):
        raise ValueError(message)
    return value


def _nonnegative_integer(value, label):
    if isinstance(value, bool):
        raise ValueError(f"Backup {label} is invalid.")
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Backup {label} is invalid.") from exc
    if result < 0:
        raise ValueError(f"Backup {label} is invalid.")
    return result


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
