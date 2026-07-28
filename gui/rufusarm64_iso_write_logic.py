"""Pure command and response contracts for Linux ISO Image mode."""

import os

ISO_IMAGE_MODE = "linux-iso"
DD_IMAGE_MODE = "raw"


def build_iso_analysis_command(pkexec, helper, image, source_identity, target_size, cancel_path):
    values = [str(value or "").strip() for value in (pkexec, helper, image, source_identity, cancel_path)]
    if not all(values):
        raise ValueError("ISO Image mode analysis requires authentication, a helper, an identity-bound image, and a cancellation channel.")
    try:
        target_size = int(target_size or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError("The selected USB capacity must be a whole byte count.") from exc
    if target_size <= 0:
        raise ValueError("The selected USB drive does not report a usable capacity.")
    return [
        values[0], values[1], "analyze",
        "--image", values[2],
        "--expected-source-identity", values[3],
        "--target-size", str(target_size),
        "--cancel-file", values[4],
        "--json",
    ]


def build_iso_create_command(pkexec, helper, image, source_identity, device, target_identity, cancel_path, volume_label="RUFUS-LIVE"):
    values = [str(value or "").strip() for value in (
        pkexec, helper, image, source_identity, device, target_identity, cancel_path,
    )]
    if not all(values):
        raise ValueError("ISO Image mode creation requires authentication and exact source/target identities.")
    label = str(volume_label or "RUFUS-LIVE").strip().upper() or "RUFUS-LIVE"
    if len(label) > 11 or any(ord(char) < 0x20 or ord(char) > 0x7E or char in '"*+,./:;<=>?[\\]|' for char in label):
        raise ValueError("The ISO Image mode FAT32 label must be at most 11 printable ASCII characters without FAT-forbidden punctuation.")
    return [
        values[0], values[1], "create",
        "--image", values[2],
        "--expected-source-identity", values[3],
        "--device", values[4],
        "--expected-identity", values[5],
        "--volume-label", label,
        "--cancel-file", values[6],
        "--yes",
        "--json-progress",
    ]


def normalize_iso_analysis(payload):
    if not isinstance(payload, dict):
        raise ValueError("ISO Image mode analysis returned invalid data.")
    layout = payload.get("layout")
    if not isinstance(layout, dict):
        raise ValueError("ISO Image mode analysis is missing its target layout.")
    partition = layout.get("partition")
    if not isinstance(partition, dict):
        raise ValueError("ISO Image mode analysis is missing its FAT32 partition.")
    try:
        image_size = int(payload.get("image_size") or 0)
        target_size = int(payload.get("target_size") or 0)
        entries = int(payload.get("manifest_entries") or 0)
        files = int(payload.get("manifest_files") or 0)
        directories = int(payload.get("manifest_directories") or 0)
        manifest_bytes = int(payload.get("manifest_bytes") or 0)
        required_bytes = int(payload.get("fat32_required_bytes") or 0)
        sector_size = int(layout.get("sector_size") or 0)
        layout_target = int(layout.get("target_size") or 0)
        layout_required = int(layout.get("required_bytes") or 0)
        number = int(partition.get("number") or 0)
        start = int(partition.get("start_bytes") or 0)
        size = int(partition.get("size_bytes") or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError("ISO Image mode analysis returned invalid numeric data.") from exc
    architecture = str(payload.get("architecture") or "").strip().lower()
    boot_path = str(payload.get("uefi_boot_path") or "").strip().replace("\\", "/")
    if (
        image_size <= 0 or target_size <= 0 or layout_target != target_size or
        entries <= 0 or files <= 0 or directories < 0 or manifest_bytes <= 0 or required_bytes < manifest_bytes or
        sector_size not in {512, 1024, 2048, 4096} or layout_required != required_bytes or
        number != 1 or start <= 0 or size <= required_bytes or start + size > target_size or
        architecture not in {"arm64", "amd64", "386"} or
        not boot_path.lower().startswith("efi/boot/boot") or not boot_path.lower().endswith(".efi")
    ):
        raise ValueError("ISO Image mode analysis returned an inconsistent or unsafe layout.")
    normalized = dict(payload)
    normalized["layout"] = dict(layout)
    normalized["layout"]["partition"] = dict(partition)
    normalized["image_size"] = image_size
    normalized["target_size"] = target_size
    normalized["manifest_entries"] = entries
    normalized["manifest_files"] = files
    normalized["manifest_directories"] = directories
    normalized["manifest_bytes"] = manifest_bytes
    normalized["fat32_required_bytes"] = required_bytes
    normalized["architecture"] = architecture
    normalized["uefi_boot_path"] = boot_path
    return normalized


def iso_analysis_summary(payload, human_bytes):
    result = normalize_iso_analysis(payload)
    partition = result["layout"]["partition"]
    return (
        f"ISO Image mode will create one writable GPT/UEFI/FAT32 partition of {human_bytes(partition['size_bytes'])}.\n"
        f"The complete ISO tree contains {result['manifest_files']} files ({human_bytes(result['manifest_bytes'])}); "
        f"every file was hashed during analysis and will be copied and verified again.\n"
        f"Fallback UEFI loader: {result['uefi_boot_path']}."
    )


def helper_is_usable(path):
    return bool(path) and os.path.isfile(path) and os.access(path, os.X_OK)
