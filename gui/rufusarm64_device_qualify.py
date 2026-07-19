"""Pure helpers for the RufusArm64 USB qualification interface."""


def normalize_qualification_profile(value):
    profile = str(value or "quick").strip().lower()
    if profile not in {"quick", "full"}:
        raise ValueError("USB test profile must be Quick or Full.")
    return profile


def build_qualification_command(pkexec_path, helper_path, device, identity, profile="quick"):
    pkexec_path = str(pkexec_path or "").strip()
    helper_path = str(helper_path or "").strip()
    device = str(device or "").strip()
    identity = str(identity or "").strip()
    profile = normalize_qualification_profile(profile)
    if not pkexec_path:
        raise ValueError("Administrator authentication is unavailable.")
    if not helper_path:
        raise ValueError("The RufusArm64 USB qualification utility is not installed correctly.")
    if not device.startswith("/dev/"):
        raise ValueError("Choose a whole USB drive before starting the test.")
    if not identity:
        raise ValueError("Refresh the USB list before starting the test; the selected identity token is missing.")
    return [
        pkexec_path,
        helper_path,
        "--device",
        device,
        "--expected-identity",
        identity,
        "--profile",
        profile,
        "--yes",
        "--json-progress",
    ]


def normalize_qualification_report(payload):
    if not isinstance(payload, dict):
        raise ValueError("USB qualification returned invalid data.")
    if payload.get("schema") != 1:
        raise ValueError("USB qualification returned an unsupported report schema.")
    profile = normalize_qualification_profile(payload.get("profile"))
    status = str(payload.get("status") or "").strip().lower()
    if status not in {"passed", "failed", "cancelled"}:
        raise ValueError("USB qualification returned an invalid result status.")

    normalized = dict(payload)
    normalized["profile"] = profile
    normalized["status"] = status
    for name in (
        "capacity",
        "region_size",
        "region_count",
        "sentinel_count",
        "pattern_count",
        "planned_bytes",
        "completed_bytes",
    ):
        value = payload.get(name, 0)
        if isinstance(value, bool):
            raise ValueError(f"USB qualification returned an invalid {name.replace('_', ' ')}.")
        try:
            value = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"USB qualification returned an invalid {name.replace('_', ' ')}.") from exc
        if value < 0:
            raise ValueError(f"USB qualification returned a negative {name.replace('_', ' ')}.")
        normalized[name] = value

    normalized["aliasing_detected"] = bool(payload.get("aliasing_detected", False))
    passes = payload.get("passes")
    if not isinstance(passes, list) or any(not isinstance(item, dict) for item in passes):
        raise ValueError("USB qualification returned an invalid pass list.")
    normalized["passes"] = [dict(item) for item in passes]

    failure = payload.get("failure")
    if failure is not None and not isinstance(failure, dict):
        raise ValueError("USB qualification returned invalid failure details.")
    normalized["failure"] = dict(failure) if failure is not None else None
    if status == "passed" and normalized["failure"] is not None:
        raise ValueError("A passed USB qualification report cannot contain a failure.")
    if status == "failed" and normalized["failure"] is None:
        raise ValueError("A failed USB qualification report is missing failure details.")
    if normalized["completed_bytes"] > normalized["planned_bytes"] and normalized["planned_bytes"] > 0:
        raise ValueError("USB qualification reported more completed data than planned.")
    return normalized


def normalize_qualification_event(payload):
    if not isinstance(payload, dict):
        raise ValueError("USB qualification returned an invalid event.")
    event = str(payload.get("event") or "").strip().lower()
    if event == "result":
        return {"event": "result", "report": normalize_qualification_report(payload.get("report"))}
    if event != "progress":
        raise ValueError("USB qualification returned an unknown event type.")
    normalized = {"event": "progress"}
    normalized["stage"] = str(payload.get("stage") or "working").strip().lower()
    normalized["pattern"] = str(payload.get("pattern") or "").strip()
    for name in ("pass", "done", "total", "offset"):
        value = payload.get(name, 0)
        if isinstance(value, bool):
            raise ValueError(f"USB qualification returned an invalid progress {name}.")
        try:
            value = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"USB qualification returned an invalid progress {name}.") from exc
        if value < 0:
            raise ValueError(f"USB qualification returned a negative progress {name}.")
        normalized[name] = value
    if normalized["total"] and normalized["done"] > normalized["total"]:
        raise ValueError("USB qualification progress exceeded its total.")
    return normalized


def qualification_progress_fraction(done, total):
    try:
        done = max(0, int(done or 0))
        total = max(0, int(total or 0))
    except (TypeError, ValueError):
        return 0.0
    if total <= 0:
        return 0.0
    return min(1.0, done / total)


def qualification_progress_text(stage, pass_number, pattern, done, total, human_bytes):
    stage_name = str(stage or "working").replace("_", " ").title()
    try:
        pass_number = max(0, int(pass_number or 0))
    except (TypeError, ValueError):
        pass_number = 0
    pattern = str(pattern or "").strip()
    detail = []
    if pass_number:
        detail.append(f"pass {pass_number}")
    if pattern:
        detail.append(pattern)
    heading = stage_name + (f" ({', '.join(detail)})" if detail else "")
    fraction = qualification_progress_fraction(done, total)
    try:
        total_value = max(0, int(total or 0))
        done_value = min(max(0, int(done or 0)), total_value) if total_value else max(0, int(done or 0))
    except (TypeError, ValueError):
        done_value = 0
        total_value = 0
    if total_value <= 0:
        return heading
    return f"{heading}: {fraction * 100:.1f}% — {human_bytes(done_value)} of {human_bytes(total_value)}"


def qualification_result_summary(payload, human_bytes):
    report = normalize_qualification_report(payload)
    profile_name = report["profile"].title()
    completed = human_bytes(report["completed_bytes"])
    if report["status"] == "passed":
        return (
            f"{profile_name} USB qualification passed. {completed} of test I/O completed across "
            f"{report['region_count']} region(s) and {report['pattern_count']} pattern(s). "
            "No address aliasing or read-back mismatch was detected. Existing data on tested regions was overwritten."
        )
    if report["status"] == "cancelled":
        return (
            f"{profile_name} USB qualification was cancelled after {completed}. The result is incomplete, and data in "
            "regions already tested was overwritten."
        )

    failure = report["failure"] or {}
    kind = str(failure.get("kind") or "verification failure").replace("_", " ")
    message = str(failure.get("message") or "The device did not reproduce the written test data.")
    offset = failure.get("byte_offset")
    location = ""
    try:
        location = f" at byte {int(offset)}" if offset is not None else ""
    except (TypeError, ValueError):
        pass
    alias = " Address aliasing or false-capacity behavior was detected." if report["aliasing_detected"] else ""
    return f"USB qualification failed ({kind}{location}). {message}{alias}"
