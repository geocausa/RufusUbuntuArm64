"""Pure contracts for snapshot-bound filesystem ISO capture."""

import json
import os
import re

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PROFILE = "iso9660-joliet-udf"
_PHASES = {
    "source_view",
    "inventory_source",
    "master",
    "revalidate_source",
    "validate_mount",
    "validate_content",
    "publish",
}
_REQUIRED_LIMITATIONS = {
    "The ISO is a filesystem remaster, not a physical-disk image.",
    "Partition tables, hidden sectors, boot records and unallocated space are not captured.",
    "Bootability is not claimed or inferred from successful filesystem capture.",
    "Only the reviewed regular-file and directory subset is supported.",
}


def build_dry_run_command(binary, device, identity, output):
    _validate_base(binary, device, identity, output)
    return [
        binary,
        "--device",
        device,
        "--output",
        output,
        "--format",
        "iso",
        "--expected-identity",
        identity,
        "--dry-run",
        "--json",
    ]


def build_run_command(pkexec, binary, device, identity, output, plan):
    if not pkexec:
        raise ValueError("Administrator authentication helper is unavailable.")
    _validate_base(binary, device, identity, output)
    value = normalize_plan(plan)
    if value["device"]["path"] != device or value["identity"] != identity:
        raise ValueError("ISO plan no longer refers to the selected drive identity.")
    if value["destination"]["path"] != output:
        raise ValueError("ISO plan no longer refers to the selected destination.")
    return [
        pkexec,
        binary,
        "--device",
        device,
        "--output",
        output,
        "--format",
        "iso",
        "--expected-identity",
        identity,
        "--expected-source-node",
        value["source_node"],
        "--expected-source-mount",
        value["filesystem_capture"]["source_mount"],
        "--volume-id",
        value["filesystem_capture"]["volume_id"],
        "--yes",
        "--json",
        "--progress-json",
    ]


def confirmation_phrase(plan):
    value = normalize_plan(plan)
    filesystem = value["filesystem_capture"]
    return (
        f"SAVE FILESYSTEM {value['source_node']} AT {filesystem['source_mount']} "
        f"ON {value['device']['path']} TO {value['destination']['path']}"
    )


def normalize_plan(payload):
    value = _mapping(payload, "Filesystem ISO capture returned an invalid plan.")
    device = _mapping(value.get("device"), "ISO plan is missing source-device details.")
    destination = _mapping(value.get("destination"), "ISO plan is missing destination details.")
    filesystem = _mapping(value.get("filesystem_capture"), "ISO plan is missing filesystem evidence.")
    identity = str(value.get("identity") or "").strip()
    source_node = str(value.get("source_node") or "").strip()
    device_path = str(device.get("path") or "").strip()
    output = str(destination.get("path") or "").strip()
    directory = str(destination.get("directory") or "").strip()
    if not identity:
        raise ValueError("ISO plan is missing the whole-device identity.")
    if not device_path.startswith("/dev/") or not source_node.startswith("/dev/"):
        raise ValueError("ISO plan contains an invalid source-device binding.")
    device_size = _nonnegative_integer(device.get("size"), "device capacity")
    if device_size <= 0:
        raise ValueError("ISO plan contains an invalid whole-device capacity.")
    if str(destination.get("format") or "").strip().lower() != "iso":
        raise ValueError("ISO plan contains an invalid destination format.")
    if not os.path.isabs(output) or os.path.dirname(output) != directory or not output.lower().endswith(".iso"):
        raise ValueError("ISO plan contains inconsistent destination details.")
    if int(filesystem.get("schema") or 0) != 1:
        raise ValueError("ISO filesystem plan uses an unsupported schema.")
    if str(filesystem.get("format") or "").strip().lower() != "iso":
        raise ValueError("ISO filesystem plan contains an invalid format.")
    if str(filesystem.get("profile") or "").strip() != _PROFILE:
        raise ValueError("ISO filesystem plan contains an unsupported mastering profile.")
    if str(filesystem.get("filesystem") or "").strip().lower() != "udf":
        raise ValueError("ISO filesystem plan does not require UDF validation.")
    source_device = str(filesystem.get("source_device") or "").strip()
    source_mount = str(filesystem.get("source_mount") or "").strip()
    provider = str(filesystem.get("provider") or "").strip()
    volume_id = str(filesystem.get("volume_id") or "").strip()
    if source_device != device_path or not os.path.isabs(source_mount) or source_mount == "/":
        raise ValueError("ISO filesystem plan contains inconsistent source details.")
    if not os.path.isabs(provider) or os.path.basename(provider) != "genisoimage":
        raise ValueError("ISO filesystem plan contains an invalid mastering provider.")
    if not re.fullmatch(r"[A-Z0-9_]{1,32}", volume_id):
        raise ValueError("ISO filesystem plan contains an invalid volume identifier.")
    if str(filesystem.get("destination") or "").strip() != output:
        raise ValueError("ISO filesystem plan contains a different destination path.")
    files = _nonnegative_integer(filesystem.get("files"), "file count")
    directories = _nonnegative_integer(filesystem.get("directories"), "directory count")
    source_bytes = _nonnegative_integer(filesystem.get("source_bytes"), "source byte count")
    required = _nonnegative_integer(filesystem.get("required_bytes"), "required byte count")
    available = _nonnegative_integer(filesystem.get("available_bytes"), "available byte count")
    if required <= 0 or available < required:
        raise ValueError("ISO filesystem plan contains invalid destination sizing.")
    if _nonnegative_integer(destination.get("source_bytes"), "destination source byte count") != source_bytes:
        raise ValueError("ISO plan reports inconsistent source byte counts.")
    if _nonnegative_integer(destination.get("required_bytes"), "destination required byte count") != required:
        raise ValueError("ISO plan reports inconsistent required byte counts.")
    if _nonnegative_integer(destination.get("available_bytes"), "destination available byte count") != available:
        raise ValueError("ISO plan reports inconsistent available byte counts.")
    if _nonnegative_integer(destination.get("container_minimum_bytes", 0), "container minimum byte count") != 0:
        raise ValueError("ISO plan must not claim a virtual-container minimum.")
    binding = _digest(filesystem.get("source_binding_sha256"), "source binding")
    content = _digest(filesystem.get("source_content_sha256"), "source content")
    limitations = filesystem.get("limitations")
    if (
        not isinstance(limitations, list)
        or not all(isinstance(item, str) for item in limitations)
        or set(limitations) != _REQUIRED_LIMITATIONS
        or len(limitations) != len(_REQUIRED_LIMITATIONS)
    ):
        raise ValueError("ISO filesystem plan is missing required limitations.")
    normalized_device = dict(device)
    normalized_device.update({"path": device_path, "size": device_size})
    normalized_destination = dict(destination)
    normalized_destination.update(
        {
            "path": output,
            "directory": directory,
            "format": "iso",
            "source_bytes": source_bytes,
            "required_bytes": required,
            "container_minimum_bytes": 0,
            "available_bytes": available,
        }
    )
    normalized_filesystem = dict(filesystem)
    normalized_filesystem.update(
        {
            "schema": 1,
            "format": "iso",
            "profile": _PROFILE,
            "filesystem": "udf",
            "source_device": source_device,
            "source_mount": source_mount,
            "destination": output,
            "provider": provider,
            "volume_id": volume_id,
            "files": files,
            "directories": directories,
            "source_bytes": source_bytes,
            "required_bytes": required,
            "available_bytes": available,
            "source_binding_sha256": binding,
            "source_content_sha256": content,
            "limitations": list(limitations),
        }
    )
    return {
        "device": normalized_device,
        "identity": identity,
        "destination": normalized_destination,
        "filesystem_capture": normalized_filesystem,
        "source_node": source_node,
    }


def normalize_progress(payload):
    value = _mapping(payload, "ISO progress record is invalid.")
    if int(value.get("schema") or 0) != 2 or value.get("type") != "progress":
        raise ValueError("ISO progress record uses an unsupported schema or type.")
    phase = str(value.get("phase") or "").strip()
    if phase not in _PHASES:
        raise ValueError("ISO progress record contains an unsupported phase.")
    done = _nonnegative_integer(value.get("done"), "completed byte count")
    total = _nonnegative_integer(value.get("total"), "total byte count")
    elapsed_ms = _nonnegative_integer(value.get("elapsed_ms"), "elapsed time")
    rate = _nonnegative_integer(value.get("bytes_per_second"), "transfer rate")
    if done > total or (total == 0 and done != 0):
        raise ValueError("ISO progress record contains invalid byte accounting.")
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


def decode_progress_line(line):
    try:
        payload = json.loads(str(line or "").strip())
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or payload.get("type") != "progress":
        return None
    return normalize_progress(payload)


def normalize_report(payload):
    value = _mapping(payload, "Filesystem ISO capture returned an invalid report.")
    if int(value.get("schema") or 0) != 1:
        raise ValueError("Filesystem ISO report uses an unsupported schema.")
    status = str(value.get("status") or "").strip()
    if status not in {"passed", "failed", "cancelled"}:
        raise ValueError("Filesystem ISO report has an invalid status.")
    profile = str(value.get("profile") or "").strip()
    filesystem = str(value.get("filesystem") or "").strip().lower()
    if profile != _PROFILE or filesystem != "udf":
        raise ValueError("Filesystem ISO report contains an unsupported profile or filesystem.")
    source_device = str(value.get("source_device") or "").strip()
    source_mount = str(value.get("source_mount") or "").strip()
    destination = str(value.get("destination") or "").strip()
    if not source_device.startswith("/dev/") or not os.path.isabs(source_mount) or source_mount == "/":
        raise ValueError("Filesystem ISO report contains invalid source details.")
    if not os.path.isabs(destination) or not destination.lower().endswith(".iso"):
        raise ValueError("Filesystem ISO report contains an invalid destination.")
    files = _nonnegative_integer(value.get("files"), "file count")
    directories = _nonnegative_integer(value.get("directories"), "directory count")
    source_bytes = _nonnegative_integer(value.get("source_bytes"), "source byte count")
    required = _nonnegative_integer(value.get("required_bytes"), "required byte count")
    output_bytes = _nonnegative_integer(value.get("output_bytes"), "output byte count")
    if status == "passed" and required <= 0:
        raise ValueError("Successful filesystem ISO report contains an invalid destination bound.")
    binding = str(value.get("source_binding_sha256") or "").strip().lower()
    content = str(value.get("source_content_sha256") or "").strip().lower()
    output_hash = str(value.get("output_sha256") or "").strip().lower()
    comparison = str(value.get("content_comparison") or "").strip()
    source_stable = value.get("source_stable") is True
    udf_validated = value.get("udf_validated") is True
    published = value.get("published") is True
    failure_kind = str(value.get("failure_kind") or "").strip()
    failure = str(value.get("failure") or "").strip()
    if status == "passed":
        if not all(_SHA256_RE.fullmatch(item) for item in (binding, content, output_hash)):
            raise ValueError("Successful filesystem ISO report is missing SHA-256 evidence.")
        if output_bytes <= 0 or output_bytes > required or comparison != "passed":
            raise ValueError("Successful filesystem ISO report contains invalid output evidence.")
        if not source_stable or not udf_validated or not published or failure_kind or failure:
            raise ValueError("Successful filesystem ISO report is incomplete or includes failure evidence.")
    else:
        if published:
            raise ValueError("Failed or cancelled filesystem ISO report must not claim publication.")
        if not failure_kind or not failure:
            raise ValueError("Failed or cancelled filesystem ISO report is missing failure details.")
        for digest in (binding, content, output_hash):
            if digest and not _SHA256_RE.fullmatch(digest):
                raise ValueError("Filesystem ISO failure report contains a malformed digest.")
    normalized = dict(value)
    normalized.update(
        {
            "schema": 1,
            "status": status,
            "format": "iso",
            "profile": profile,
            "filesystem": filesystem,
            "source_device": source_device,
            "source_mount": source_mount,
            "destination": destination,
            "files": files,
            "directories": directories,
            "source_bytes": source_bytes,
            "required_bytes": required,
            "planned_bytes": source_bytes,
            "completed_bytes": source_bytes if status == "passed" else 0,
            "output_bytes": output_bytes,
            "source_binding_sha256": binding,
            "source_content_sha256": content,
            "output_sha256": output_hash,
            "content_comparison": comparison,
            "source_stable": source_stable,
            "udf_validated": udf_validated,
            "published": published,
            "failure_kind": failure_kind,
            "failure": failure,
        }
    )
    return normalized


def plan_summary(plan):
    value = normalize_plan(plan)
    filesystem = value["filesystem_capture"]
    name = " ".join(
        part
        for part in (
            str(value["device"].get("vendor") or "").strip(),
            str(value["device"].get("model") or "").strip(),
        )
        if part
    ) or value["device"]["path"]
    return (
        f"Source: {name} ({value['device']['path']}), mounted filesystem {value['source_node']} at "
        f"{filesystem['source_mount']} — {filesystem['files']} files, {filesystem['directories']} directories, "
        f"{_human_bytes(filesystem['source_bytes'])}.\n"
        f"ISO9660/Joliet/UDF destination: {filesystem['destination']}. Conservative required: "
        f"{_human_bytes(filesystem['required_bytes'])}; available: {_human_bytes(filesystem['available_bytes'])}.\n"
        "This is a filesystem remaster, not a physical-disk image, and bootability is not claimed."
    )


def progress_summary(progress):
    value = normalize_progress(progress)
    phase = value["phase"].replace("_", " ").capitalize()
    if value["total"] == 0:
        return f"{phase}: working…"
    percent = value["done"] * 100.0 / value["total"]
    rate = _human_bytes(value["bytes_per_second"]) + "/s" if value["bytes_per_second"] else "measuring speed"
    eta = _human_duration(value["eta_seconds"]) if value["eta_seconds"] is not None else "estimating time"
    return (
        f"{phase}: {percent:.1f}% — {_human_bytes(value['done'])} of {_human_bytes(value['total'])}; "
        f"{rate}; {eta} remaining"
    )


def report_summary(report, output):
    value = normalize_report(report)
    if value["status"] == "passed":
        return (
            f"Verified UDF filesystem ISO saved to {output} ({_human_bytes(value['output_bytes'])}); "
            f"source content SHA-256 {value['source_content_sha256']}; output SHA-256 {value['output_sha256']}. "
            "No physical-disk or bootability claim is made."
        )
    if value["status"] == "cancelled":
        return "Filesystem ISO capture was cancelled safely; no final image was published."
    return f"Filesystem ISO capture failed; no final image was published. {value['failure']}"


def _validate_base(binary, device, identity, output):
    if not binary:
        raise ValueError("Drive-image backup utility is unavailable.")
    if not str(device or "").startswith("/dev/"):
        raise ValueError("Choose a whole removable drive before saving an ISO.")
    if not str(identity or "").strip():
        raise ValueError("Refresh the USB list before saving an ISO.")
    output = str(output or "")
    if not os.path.isabs(output) or not output.lower().endswith(".iso"):
        raise ValueError("Choose an absolute .iso destination path.")
    if os.path.lexists(output):
        raise ValueError("Choose a new destination path; existing files and symbolic links are never replaced.")


def _mapping(value, message):
    if not isinstance(value, dict):
        raise ValueError(message)
    return value


def _nonnegative_integer(value, label):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"ISO {label} is invalid.")
    return value


def _digest(value, label):
    digest = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(digest):
        raise ValueError(f"ISO {label} SHA-256 is invalid.")
    return digest


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
