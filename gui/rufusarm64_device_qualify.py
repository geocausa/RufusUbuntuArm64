"""Pure helpers for the GTK device-qualification workflow."""

import json


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


def _mapping(value, message):
    if not isinstance(value, dict):
        raise ValueError(message)
    return value


def _human_bytes(value):
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    number = float(max(0, value))
    for unit in units:
        if number < 1024 or unit == units[-1]:
            return f"{number:.1f} {unit}" if unit != "B" else f"{int(number)} B"
        number /= 1024
    return f"{int(value)} B"
