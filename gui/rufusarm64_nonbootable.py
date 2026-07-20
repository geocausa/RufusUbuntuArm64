"""Pure contracts for the GTK non-bootable formatting workflow."""

import os


FILESYSTEM_DISPLAYS = {
    "fat32": "FAT32",
    "exfat": "exFAT",
    "ntfs": "NTFS",
    "ext4": "ext4",
}
SCHEMES = {"gpt", "mbr"}
STATUSES = {"passed", "failed", "cancelled"}
FAILURE_PHASES = {"preflight", "erase", "partition", "format", "verify", "complete"}


def build_dry_run_command(binary, device, identity, scheme, filesystem, label):
    _validate_request(binary, device, identity, scheme, filesystem, label)
    return [
        binary,
        "--device",
        device,
        "--expected-identity",
        identity,
        "--scheme",
        scheme,
        "--filesystem",
        filesystem,
        "--label",
        label,
        "--dry-run",
        "--json",
    ]


def build_run_command(pkexec, binary, device, identity, scheme, filesystem, label, cancel_file):
    if not os.path.isabs(str(pkexec or "")):
        raise ValueError("Ubuntu administrator authentication is unavailable.")
    _validate_request(binary, device, identity, scheme, filesystem, label)
    cancel_file = str(cancel_file or "")
    if not os.path.isabs(cancel_file):
        raise ValueError("A private cancellation channel is required.")
    return [
        pkexec,
        binary,
        "--device",
        device,
        "--expected-identity",
        identity,
        "--scheme",
        scheme,
        "--filesystem",
        filesystem,
        "--label",
        label,
        "--cancel-file",
        cancel_file,
        "--yes",
        "--json",
    ]


def confirmation_phrase(plan):
    value = normalize_plan(plan)
    details = value["plan"]
    phrase = (
        f"FORMAT {details['device_path']} AS {details['filesystem_display']} "
        f"USING {details['scheme'].upper()}"
    )
    if details["label"]:
        return phrase + " LABEL " + details["label"]
    return phrase + " WITHOUT A LABEL"


def normalize_plan(payload):
    value = _mapping(payload, "Non-bootable formatting returned an invalid plan.")
    device = _mapping(value.get("device"), "Formatting plan is missing device details.")
    identity = _text(value.get("identity"), "Formatting plan is missing the device identity.")
    plan = _normalize_plan_fields(value.get("plan"))
    table = _normalize_table(value.get("partition_table"), plan)

    device_path = _text(device.get("path"), "Formatting plan contains an invalid device path.")
    device_size = _positive_integer(device.get("size"), "device capacity")
    if device_path != plan["device_path"] or device_size != plan["device_size_bytes"]:
        raise ValueError("Formatting plan device details do not match its guarded plan.")
    if identity != plan["expected_identity"]:
        raise ValueError("Formatting plan identity does not match its guarded plan.")

    expected = _phrase_from_fields(plan)
    returned = _text(value.get("confirmation"), "Formatting plan is missing its confirmation phrase.")
    if returned != expected:
        raise ValueError("Formatting plan returned an inconsistent confirmation phrase.")

    normalized_device = dict(device)
    normalized_device.update({"path": device_path, "size": device_size})
    return {
        "device": normalized_device,
        "identity": identity,
        "plan": plan,
        "partition_table": table,
        "confirmation": returned,
    }


def normalize_report(payload, reviewed_plan=None):
    value = _mapping(payload, "Non-bootable formatting returned an invalid report.")
    if _integer(value.get("schema"), "report schema") != 1 or value.get("mode") != "non-bootable":
        raise ValueError("Formatting report uses an unsupported schema or mode.")
    status = _text(value.get("status"), "Formatting report is missing its status.")
    if status not in STATUSES:
        raise ValueError("Formatting report contains an invalid status.")
    if value.get("bootable") is not False:
        raise ValueError("Formatting report must not claim bootable media.")

    plan = _normalize_plan_fields(value.get("plan"))
    table = _normalize_table(value.get("partition_table"), plan)
    if reviewed_plan is not None:
        reviewed = normalize_plan(reviewed_plan)
        if plan != reviewed["plan"] or table != reviewed["partition_table"]:
            raise ValueError("Formatting report does not match the reviewed plan.")

    media_changed = _boolean(value.get("media_changed"), "media-changed state")
    reusable = _boolean(value.get("reusable"), "reusable state")
    filesystem = value.get("filesystem")
    failure = value.get("failure")

    normalized_filesystem = None
    normalized_failure = None
    if status == "passed":
        if not media_changed or not reusable or failure is not None:
            raise ValueError("Successful formatting report has inconsistent completion state.")
        state = _mapping(filesystem, "Successful formatting report is missing filesystem verification.")
        normalized_filesystem = {
            "path": _text(state.get("path"), "Filesystem report is missing its partition path."),
            "type": _text(state.get("type"), "Filesystem report is missing its type."),
            "label": str(state.get("label") or ""),
            "uuid": str(state.get("uuid") or ""),
            "size_bytes": _positive_integer(state.get("size_bytes"), "filesystem size"),
            "read_only": _boolean(state.get("read_only"), "filesystem read-only state"),
            "parent_path": _text(state.get("parent_path"), "Filesystem report is missing its parent path."),
        }
        if (
            normalized_filesystem["type"] != plan["filesystem"]
            or normalized_filesystem["label"] != plan["label"]
            or normalized_filesystem["size_bytes"] != plan["partition_size_bytes"]
            or normalized_filesystem["parent_path"] != plan["device_path"]
            or normalized_filesystem["read_only"]
        ):
            raise ValueError("Verified filesystem does not match the reviewed plan.")
    else:
        if reusable or filesystem is not None:
            raise ValueError("Incomplete formatting report must not claim reusable verified media.")
        record = _mapping(failure, "Incomplete formatting report is missing failure details.")
        phase = _text(record.get("phase"), "Formatting failure is missing its phase.")
        message = _text(record.get("message"), "Formatting failure is missing its message.")
        failure_changed = _boolean(record.get("media_changed"), "failure media-changed state")
        if phase not in FAILURE_PHASES or failure_changed != media_changed:
            raise ValueError("Formatting failure details contradict the report state.")
        normalized_failure = {"phase": phase, "message": message, "media_changed": failure_changed}

    normalized = dict(value)
    normalized.update(
        {
            "schema": 1,
            "mode": "non-bootable",
            "status": status,
            "plan": plan,
            "partition_table": table,
            "filesystem": normalized_filesystem,
            "failure": normalized_failure,
            "media_changed": media_changed,
            "reusable": reusable,
            "bootable": False,
        }
    )
    return normalized


def plan_summary(payload):
    value = normalize_plan(payload)
    device = value["device"]
    plan = value["plan"]
    name = " ".join(
        part for part in (str(device.get("vendor") or "").strip(), str(device.get("model") or "").strip()) if part
    ) or plan["device_path"]
    label = f'label "{plan["label"]}"' if plan["label"] else "no volume label"
    tools = ", ".join(plan["required_tools"])
    warnings = "\n".join(f"• {item}" for item in plan["warnings"])
    return (
        f"Target: {name} ({plan['device_path']}), {_human_bytes(plan['device_size_bytes'])}.\n"
        f"Layout: {plan['scheme'].upper()}, one {plan['filesystem_display']} data partition, {label}.\n"
        f"Partition: starts at {_human_bytes(plan['partition_start_bytes'])}; "
        f"usable size {_human_bytes(plan['partition_size_bytes'])}.\n"
        f"Required tools: {tools}. The result is data-only and is not claimed bootable.\n{warnings}"
    )


def report_summary(payload):
    value = normalize_report(payload)
    if value["status"] == "passed":
        state = value["filesystem"]
        uuid = f", UUID {state['uuid']}" if state["uuid"] else ""
        return (
            f"Data-only media is ready: {value['plan']['filesystem_display']} on {state['path']}, "
            f"{_human_bytes(state['size_bytes'])}{uuid}. It is not bootable."
        )
    failure = value["failure"]
    if value["status"] == "cancelled" and not value["media_changed"]:
        return "Formatting was cancelled before erasure; the selected drive was not changed."
    state = "The drive was changed and must be reformatted before use." if value["media_changed"] else "The drive was not changed."
    verb = "cancelled" if value["status"] == "cancelled" else "failed"
    return f"Formatting {verb} during {failure['phase']}. {state} {failure['message']}"


def _normalize_plan_fields(payload):
    plan = _mapping(payload, "Formatting plan is missing its guarded plan.")
    if _integer(plan.get("schema"), "plan schema") != 1 or plan.get("mode") != "non-bootable":
        raise ValueError("Formatting plan uses an unsupported schema or mode.")
    if plan.get("bootable") is not False or plan.get("destructive") is not True:
        raise ValueError("Formatting plan contains an invalid safety envelope.")
    device_path = _text(plan.get("device_path"), "Formatting plan is missing its device path.")
    if not device_path.startswith("/dev/"):
        raise ValueError("Formatting plan contains an invalid device path.")
    identity = _text(plan.get("expected_identity"), "Formatting plan is missing its expected identity.")
    scheme = _text(plan.get("scheme"), "Formatting plan is missing its partition scheme.").lower()
    filesystem = _text(plan.get("filesystem"), "Formatting plan is missing its filesystem.").lower()
    if scheme not in SCHEMES or filesystem not in FILESYSTEM_DISPLAYS:
        raise ValueError("Formatting plan contains an unsupported layout or filesystem.")
    display = _text(plan.get("filesystem_display"), "Formatting plan is missing its filesystem display name.")
    if display != FILESYSTEM_DISPLAYS[filesystem]:
        raise ValueError("Formatting plan contains an inconsistent filesystem contract.")
    sector_size = _positive_integer(plan.get("logical_sector_size"), "logical sector size")
    if sector_size not in {512, 4096}:
        raise ValueError("Formatting plan contains an unsupported logical sector size.")
    device_size = _positive_integer(plan.get("device_size_bytes"), "device capacity")
    start = _positive_integer(plan.get("partition_start_bytes"), "partition start")
    size = _positive_integer(plan.get("partition_size_bytes"), "partition size")
    if start % sector_size or size % sector_size or start + size > device_size:
        raise ValueError("Formatting plan contains invalid partition geometry.")
    if _integer(plan.get("partition_number"), "partition number") != 1:
        raise ValueError("Formatting plan must contain exactly one data partition.")
    partition_type = _text(plan.get("partition_type"), "Formatting plan is missing its partition type.")
    tools = plan.get("required_tools")
    warnings = plan.get("warnings")
    if not isinstance(tools, list) or len(tools) != 4 or not all(isinstance(item, str) and item for item in tools):
        raise ValueError("Formatting plan contains an invalid required-tool contract.")
    if not isinstance(warnings, list) or not warnings or not all(isinstance(item, str) and item for item in warnings):
        raise ValueError("Formatting plan is missing its safety warnings.")
    return {
        "schema": 1,
        "mode": "non-bootable",
        "bootable": False,
        "destructive": True,
        "device_path": device_path,
        "expected_identity": identity,
        "device_size_bytes": device_size,
        "logical_sector_size": sector_size,
        "scheme": scheme,
        "filesystem": filesystem,
        "filesystem_display": display,
        "label": str(plan.get("label") or ""),
        "partition_number": 1,
        "partition_start_bytes": start,
        "partition_size_bytes": size,
        "partition_type": partition_type,
        "required_tools": list(tools),
        "warnings": list(warnings),
    }


def _normalize_table(payload, plan):
    table = _mapping(payload, "Formatting plan is missing its partition table.")
    normalized = {
        "schema": _integer(table.get("schema"), "partition-table schema"),
        "scheme": _text(table.get("scheme"), "Partition table is missing its scheme.").lower(),
        "device_path": _text(table.get("device_path"), "Partition table is missing its device path."),
        "sector_size": _positive_integer(table.get("sector_size"), "partition-table sector size"),
        "partition_number": _integer(table.get("partition_number"), "partition-table partition number"),
        "start_sector": _positive_integer(table.get("start_sector"), "partition start sector"),
        "size_sectors": _positive_integer(table.get("size_sectors"), "partition size in sectors"),
        "partition_type": _text(table.get("partition_type"), "Partition table is missing its type."),
        "filesystem": _text(table.get("filesystem"), "Partition table is missing its filesystem.").lower(),
        "filesystem_display": _text(table.get("filesystem_display"), "Partition table is missing its display name."),
        "label": str(table.get("label") or ""),
    }
    if (
        normalized["schema"] != 1
        or normalized["scheme"] != plan["scheme"]
        or normalized["device_path"] != plan["device_path"]
        or normalized["sector_size"] != plan["logical_sector_size"]
        or normalized["partition_number"] != 1
        or normalized["start_sector"] * normalized["sector_size"] != plan["partition_start_bytes"]
        or normalized["size_sectors"] * normalized["sector_size"] != plan["partition_size_bytes"]
        or normalized["partition_type"] != plan["partition_type"]
        or normalized["filesystem"] != plan["filesystem"]
        or normalized["filesystem_display"] != plan["filesystem_display"]
        or normalized["label"] != plan["label"]
    ):
        raise ValueError("Partition table does not match the reviewed formatting plan.")
    return normalized


def _phrase_from_fields(plan):
    phrase = f"FORMAT {plan['device_path']} AS {plan['filesystem_display']} USING {plan['scheme'].upper()}"
    return phrase + (f" LABEL {plan['label']}" if plan["label"] else " WITHOUT A LABEL")


def _validate_request(binary, device, identity, scheme, filesystem, label):
    if not os.path.isabs(str(binary or "")):
        raise ValueError("The packaged non-bootable formatter is unavailable.")
    if not str(device or "").startswith("/dev/"):
        raise ValueError("Choose a whole removable drive before formatting.")
    if not str(identity or "").strip():
        raise ValueError("Refresh the USB list before formatting.")
    if str(scheme or "").lower() not in SCHEMES:
        raise ValueError("Partition scheme must be GPT or MBR.")
    if str(filesystem or "").lower() not in FILESYSTEM_DISPLAYS:
        raise ValueError("Filesystem must be FAT32, exFAT, NTFS, or ext4.")
    if not isinstance(label, str):
        raise ValueError("Volume label must be text.")


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
        raise ValueError(f"Formatting {label} must be an exact integer.")
    return value


def _positive_integer(value, label):
    number = _integer(value, label)
    if number <= 0:
        raise ValueError(f"Formatting {label} must be positive.")
    return number


def _boolean(value, label):
    if not isinstance(value, bool):
        raise ValueError(f"Formatting {label} must be a boolean.")
    return value


def _human_bytes(value):
    amount = float(value)
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    index = 0
    while amount >= 1024 and index < len(units) - 1:
        amount /= 1024
        index += 1
    return f"{amount:.1f} {units[index]}" if index else f"{int(amount)} {units[index]}"
