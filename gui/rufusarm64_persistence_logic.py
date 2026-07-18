"""Pure helpers for the RufusArm64 persistent-live-media wizard."""

import os
import re
import stat

SIZE_PATTERN = re.compile(r"^[0-9]+$")
LABEL_PATTERN = re.compile(r"^[A-Z0-9 _-]{1,11}$")


def inspect_source_identity(path):
    """Return a resolved regular-file path and its cross-privilege identity."""
    path = str(path or "").strip()
    if not path:
        raise ValueError("Choose a Linux ISO image first.")
    resolved = os.path.realpath(os.path.abspath(path))
    try:
        info = os.stat(resolved, follow_symlinks=False)
    except OSError as exc:
        raise ValueError(f"Could not inspect the selected image: {exc}") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_size <= 0:
        raise ValueError("The selected image must be a non-empty regular file.")
    fields = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    if any(int(value) <= 0 for value in fields[:3]) or any(int(value) < 0 for value in fields[3:]):
        raise ValueError("The selected image does not expose a complete kernel identity.")
    return resolved, ":".join(str(int(value)) for value in fields)


def normalize_boot_label(value):
    label = str(value or "RUFUS-LIVE").strip().upper() or "RUFUS-LIVE"
    if not LABEL_PATTERN.fullmatch(label):
        raise ValueError("The boot volume label must be 1–11 uppercase letters, numbers, spaces, underscores, or hyphens.")
    return label


def normalize_persistence_gib(value):
    try:
        amount = int(value or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError("Persistence size must be a whole number of GiB.") from exc
    if amount < 0 or amount > 1024:
        raise ValueError("Persistence size must be between 0 and 1024 GiB; zero uses the suitable remaining space.")
    return amount


def build_analyze_command(pkexec, helper, image, source_identity, target_size, persistence_gib, cancel_path):
    values = [str(value or "").strip() for value in (pkexec, helper, image, source_identity, cancel_path)]
    if not all(values):
        raise ValueError("Persistence analysis requires authentication, an identity-bound image, and a cancellation channel.")
    try:
        target_size = int(target_size or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError("The selected USB drive reports an invalid capacity.") from exc
    persistence_gib = normalize_persistence_gib(persistence_gib)
    if target_size <= 0:
        raise ValueError("The selected USB drive reports an invalid capacity.")
    return [
        values[0], values[1], "persistence", "analyze",
        "--image", values[2],
        "--expected-source-identity", values[3],
        "--target-size", str(target_size),
        "--size", f"{persistence_gib}G" if persistence_gib else "0",
        "--cancel-file", values[4],
        "--json",
    ]


def build_create_command(
    pkexec,
    persistence_helper,
    image,
    source_identity,
    device,
    target_identity,
    persistence_gib,
    volume_label,
    cancel_path,
    runtime_uefi_validation=False,
):
    values = [
        str(value or "").strip()
        for value in (pkexec, persistence_helper, image, source_identity, device, target_identity, cancel_path)
    ]
    if not all(values):
        raise ValueError("Persistent USB creation requires identity-bound image and target selections.")
    if not values[4].startswith("/dev/"):
        raise ValueError("The selected target is not a whole device under /dev.")
    persistence_gib = normalize_persistence_gib(persistence_gib)
    label = normalize_boot_label(volume_label)
    if not isinstance(runtime_uefi_validation, bool):
        raise ValueError("Runtime UEFI media validation must be an explicit boolean selection.")
    command = [
        values[0], values[1],
        "--image", values[2],
        "--expected-source-identity", values[3],
        "--device", values[4],
        "--expected-identity", values[5],
        "--persistence-size", f"{persistence_gib}G" if persistence_gib else "0",
        "--volume-label", label,
        "--cancel-file", values[6],
        "--json-progress",
        "--yes",
    ]
    if runtime_uefi_validation:
        command.append("--runtime-uefi-validation")
    return command


def _normalize_patch_path(value):
    path = str(value or "").strip().replace("\\", "/")
    if not path or path.startswith("/"):
        raise ValueError("The persistence analyzer returned an invalid boot-file edit path.")
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("The persistence analyzer returned an invalid boot-file edit path.")
    return "/".join(parts)


def normalize_plan(payload):
    if not isinstance(payload, dict):
        raise ValueError("The persistence analyzer returned an invalid response.")
    detection = payload.get("detection")
    plan = payload.get("plan")
    if not isinstance(detection, dict) or not isinstance(plan, dict):
        raise ValueError("The persistence analyzer response is incomplete.")
    name = str(detection.get("display_name") or detection.get("DisplayName") or "Linux live media").strip()
    family = str(detection.get("family") or detection.get("Family") or "").strip()
    filesystem = str(plan.get("filesystem") or plan.get("Filesystem") or "ext4").strip()
    label = str(plan.get("filesystem_label") or plan.get("FilesystemLabel") or "").strip()
    parameter = str(plan.get("boot_parameter") or plan.get("BootParameter") or "").strip()
    try:
        size = int(plan.get("size_bytes") or plan.get("SizeBytes") or 0)
        target_size = int(payload.get("target_size") or payload.get("TargetSize") or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError("The persistence analyzer returned invalid partition sizes.") from exc
    patch_paths = plan.get("patch_paths") or plan.get("PatchPaths") or []
    if not name or not family or filesystem != "ext4" or not label or not parameter or size < 1024**3:
        raise ValueError("The persistence analyzer did not return a complete supported contract.")
    if target_size <= 0 or size >= target_size:
        raise ValueError("The persistence analyzer returned an impossible target layout.")
    if not isinstance(patch_paths, list):
        raise ValueError("The persistence analyzer returned invalid boot-file edits.")
    normalized_paths = [_normalize_patch_path(path) for path in patch_paths]
    if len(normalized_paths) != len(set(normalized_paths)):
        raise ValueError("The persistence analyzer returned duplicate boot-file edits.")
    return {
        "name": name,
        "family": family,
        "filesystem": filesystem,
        "label": label,
        "parameter": parameter,
        "size": size,
        "target_size": target_size,
        "patch_paths": normalized_paths,
    }


def plan_summary(plan, human_bytes):
    lines = [
        f"Compatible media: {plan['name']}",
        f"Persistent storage: {human_bytes(plan['size'])} ext4 labelled \"{plan['label']}\"",
        f"Boot option to enable: {plan['parameter']}",
    ]
    if plan["patch_paths"]:
        lines.append("Boot files to update: " + ", ".join(plan["patch_paths"]))
    lines.append("The live operating system remains on the FAT32 boot partition; changes are stored separately and survive reboots.")
    return "\n".join(lines)
