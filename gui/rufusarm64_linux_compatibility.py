"""Headless, descriptor-bound Linux ISO compatibility analysis."""

import os
import re
import stat
import struct

ISO_SECTOR_SIZE = 2048
FIRST_ISO_DESCRIPTOR = 16
LAST_ISO_DESCRIPTOR = 64
MAX_BOOT_CATALOGUE_BYTES = 2048
MAX_BOOT_IMAGE_PROBE_BYTES = 64 * 1024
MAX_BOOT_ENTRIES = 32
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def normalize_el_torito_uefi_plan(inspection, source_size):
    """Validate the strict Go El Torito plan before exposing ISO Image mode."""
    if not isinstance(inspection, dict):
        return None
    plan = inspection.get("el_torito_uefi")
    if not isinstance(plan, dict):
        return None
    try:
        normalized = {
            "schema": int(plan.get("schema") or 0),
            "source_size": int(plan.get("source_size") or 0),
            "catalog_lba": int(plan.get("catalog_lba") or 0),
            "entry_index": int(plan.get("entry_index") or 0),
            "platform_id": int(plan.get("platform_id") or 0),
            "media_type": int(plan.get("media_type") or 0),
            "image_lba": int(plan.get("image_lba") or 0),
            "image_offset": int(plan.get("image_offset") or 0),
            "image_length": int(plan.get("image_length") or 0),
            "catalog_sha256": str(plan.get("catalog_sha256") or "").strip().lower(),
            "image_sha256": str(plan.get("image_sha256") or "").strip().lower(),
            "plan_sha256": str(plan.get("plan_sha256") or "").strip().lower(),
        }
    except (TypeError, ValueError):
        return None
    if (
        normalized["schema"] != 1
        or normalized["source_size"] != int(source_size or 0)
        or normalized["catalog_lba"] <= 0
        or normalized["entry_index"] <= 0
        or normalized["platform_id"] != 0xEF
        or normalized["media_type"] != 0
        or normalized["image_lba"] <= 0
        or normalized["image_offset"] < 0
        or normalized["image_length"] <= 0
        or normalized["image_offset"] + normalized["image_length"] > normalized["source_size"]
        or not all(SHA256_PATTERN.fullmatch(normalized[key]) for key in ("catalog_sha256", "image_sha256", "plan_sha256"))
    ):
        return None
    return normalized

def _read_at(handle, offset, size):
    if offset < 0 or size < 0:
        return b""
    handle.seek(offset)
    return handle.read(size)


def _has_disk_layout(handle):
    sector = _read_at(handle, 0, 512)
    if len(sector) != 512 or sector[510:512] != b"\x55\xaa":
        return False
    for index in range(4):
        entry = sector[446 + index * 16 : 462 + index * 16]
        if len(entry) == 16 and entry[4] != 0 and struct.unpack_from("<I", entry, 12)[0] != 0:
            return True
    return False


def _iso_boot_catalogue(handle):
    has_iso = False
    catalogue_lba = 0
    for sector in range(FIRST_ISO_DESCRIPTOR, LAST_ISO_DESCRIPTOR + 1):
        descriptor = _read_at(handle, sector * ISO_SECTOR_SIZE, ISO_SECTOR_SIZE)
        if len(descriptor) < 75:
            break
        if descriptor[1:6] != b"CD001" or descriptor[6] != 1:
            continue
        descriptor_type = descriptor[0]
        if descriptor_type == 0 and descriptor[7:39].rstrip(b" \x00") == b"EL TORITO SPECIFICATION":
            catalogue_lba = struct.unpack_from("<I", descriptor, 71)[0]
        elif descriptor_type == 1:
            has_iso = True
        elif descriptor_type == 255:
            break
    return has_iso, catalogue_lba


def _valid_catalogue_validation(entry):
    if len(entry) != 32 or entry[0] != 1 or entry[30:32] != b"\x55\xaa":
        return False
    return sum(struct.unpack("<16H", entry)) & 0xFFFF == 0


def _platform_name(value):
    if value == 0x00:
        return "BIOS"
    if value == 0xEF:
        return "UEFI"
    return ""


def _catalogue_boot_entries(handle, catalogue_lba):
    if catalogue_lba <= 0:
        return []
    catalogue = _read_at(handle, catalogue_lba * ISO_SECTOR_SIZE, MAX_BOOT_CATALOGUE_BYTES)
    if len(catalogue) < 64 or not _valid_catalogue_validation(catalogue[:32]):
        return []

    entries = []

    def add_entry(platform, entry):
        if len(entries) >= MAX_BOOT_ENTRIES or len(entry) != 32 or entry[0] != 0x88:
            return
        name = _platform_name(platform)
        image_lba = struct.unpack_from("<I", entry, 8)[0]
        if name and image_lba > 0:
            entries.append((name, image_lba))

    default_platform = catalogue[1]
    add_entry(default_platform, catalogue[32:64])
    offset = 64
    while offset + 32 <= len(catalogue) and len(entries) < MAX_BOOT_ENTRIES:
        header = catalogue[offset : offset + 32]
        header_id = header[0]
        if header_id not in (0x90, 0x91):
            offset += 32
            continue
        platform = header[1]
        count = min(header[2], MAX_BOOT_ENTRIES - len(entries))
        offset += 32
        for _ in range(count):
            if offset + 32 > len(catalogue):
                return entries
            add_entry(platform, catalogue[offset : offset + 32])
            offset += 32
        if header_id == 0x91:
            break
    return entries


def _bootloader_fingerprints(handle, entries, file_size):
    found = set()
    for _, image_lba in entries[:MAX_BOOT_ENTRIES]:
        offset = image_lba * ISO_SECTOR_SIZE
        if offset < 0 or offset >= file_size:
            continue
        size = min(MAX_BOOT_IMAGE_PROBE_BYTES, file_size - offset)
        sample = _read_at(handle, offset, size).upper()
        if b"ISOLINUX" in sample:
            found.add("ISOLINUX")
        elif b"SYSLINUX" in sample:
            found.add("SYSLINUX")
        if b"GRUB" in sample:
            found.add("GRUB")
    return sorted(found)


def _snapshot_from_metadata(resolved, metadata):
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0:
        return ()
    return (
        str(resolved),
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(metadata.st_ctime_ns),
    )


def _source_snapshot(path):
    """Resolve and hold one non-empty regular-file identity without following the resolved final component."""
    try:
        resolved = os.path.realpath(os.path.abspath(os.fspath(path)))
    except (OSError, TypeError, ValueError):
        return ()
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(resolved, flags)
    except OSError:
        return ()
    try:
        return _snapshot_from_metadata(resolved, os.fstat(descriptor))
    except OSError:
        return ()
    finally:
        os.close(descriptor)


def linux_compatibility_profile(path, inspection, expected_snapshot=None):
    """Return bounded compatibility facts only for the stable source snapshot inspected by the helper."""
    if not isinstance(inspection, dict):
        return {}
    if not inspection.get("recognized") or inspection.get("mode") != "raw":
        return {}
    if inspection.get("needs_preparation"):
        return {}
    container = str(inspection.get("container_format") or "plain").lower()
    if container not in {"", "plain"}:
        return {}

    expected = tuple(expected_snapshot or _source_snapshot(path))
    if len(expected) != 6 or _source_snapshot(path) != expected:
        return {}
    resolved = expected[0]
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(resolved, flags)
    except OSError:
        return {}
    try:
        metadata = os.fstat(descriptor)
        if _snapshot_from_metadata(resolved, metadata) != expected:
            return {}
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            disk_layout = _has_disk_layout(handle)
            has_iso, catalogue_lba = _iso_boot_catalogue(handle)
            entries = _catalogue_boot_entries(handle, catalogue_lba) if has_iso else []
            bootloaders = _bootloader_fingerprints(handle, entries, metadata.st_size)
        if _snapshot_from_metadata(resolved, os.fstat(descriptor)) != expected:
            return {}
    except (OSError, struct.error):
        return {}
    finally:
        os.close(descriptor)

    strict_uefi = normalize_el_torito_uefi_plan(inspection, metadata.st_size)
    boot_method_set = {platform for platform, _ in entries if platform != "UEFI"}
    if strict_uefi is not None:
        boot_method_set.add("UEFI")
    boot_methods = sorted(boot_method_set, key=lambda item: (item != "BIOS", item))
    el_torito_refusal = str(inspection.get("el_torito_uefi_refusal") or "").strip()
    if not disk_layout and not has_iso:
        return {}

    if has_iso and disk_layout:
        write_path = "hybrid-direct-write"
        parts = [
            "Compatibility: hybrid ISO/raw disk layout detected; RufusArm64 preserves its partition and boot structures byte-for-byte."
        ]
    elif has_iso:
        write_path = "optical-direct-write"
        parts = [
            "Compatibility: optical-only ISO detected; RufusArm64 preserves it byte-for-byte, so USB boot may depend on firmware USB-CD emulation."
        ]
    else:
        write_path = "raw-direct-write"
        parts = [
            "Compatibility: raw disk layout detected; RufusArm64 preserves its embedded partition and boot structures byte-for-byte."
        ]

    if has_iso:
        if boot_methods:
            parts.append("Validated El Torito firmware entries: " + " and ".join(boot_methods) + ".")
        else:
            parts.append("No valid El Torito BIOS or UEFI boot entry was found.")
        if strict_uefi is not None:
            parts.append(
                "Strict UEFI extraction plan: "
                + strict_uefi["image_sha256"]
                + f" ({strict_uefi['image_length']} bytes)."
            )
        elif el_torito_refusal:
            parts.append("El Torito UEFI extraction unavailable: " + el_torito_refusal + ".")
        if bootloaders:
            parts.append("Bootloader fingerprint: " + ", ".join(bootloaders) + ".")
    parts.append("Software inspection does not prove that the intended computer will boot this USB.")

    return {
        "write_path": write_path,
        "hybrid": bool(has_iso and disk_layout),
        "optical": bool(has_iso),
        "boot_methods": boot_methods,
        "bootloaders": bootloaders,
        "el_torito_uefi": strict_uefi,
        "el_torito_uefi_refusal": el_torito_refusal,
        "summary": " ".join(parts),
    }


def enrich_linux_inspection(path, inspection, expected_snapshot=None):
    """Attach an idempotent Linux compatibility profile to a helper result."""
    if not isinstance(inspection, dict) or inspection.get("compatibility_profile"):
        return inspection
    profile = linux_compatibility_profile(path, inspection, expected_snapshot)
    if not profile:
        return inspection
    enriched = dict(inspection)
    enriched["compatibility_profile"] = profile
    base = str(enriched.get("description") or "").strip()
    enriched["description"] = (base + "\n" if base else "") + profile["summary"]
    return enriched


def install_linux_compatibility(window_class):
    """Bind native inspection and bounded compatibility reporting to one stable source snapshot."""
    if getattr(window_class, "_linux_compatibility_installed", False):
        return
    original_run_image_inspection = window_class._run_image_inspection
    original_finish_image_inspection = window_class._finish_image_inspection

    def integrated_run_image_inspection(window, path, generation):
        snapshots = getattr(window, "_linux_inspection_snapshots", None)
        if not isinstance(snapshots, dict):
            snapshots = {}
            window._linux_inspection_snapshots = snapshots
        snapshots[generation] = _source_snapshot(path)
        return original_run_image_inspection(window, path, generation)

    def integrated_finish_image_inspection(window, path, generation, inspection):
        snapshots = getattr(window, "_linux_inspection_snapshots", {})
        expected = snapshots.pop(generation, ()) if isinstance(snapshots, dict) else ()
        current_path = window.image_chooser.get_filename() or ""
        if window.closed or generation != window.inspection_generation or current_path != path:
            return original_finish_image_inspection(window, path, generation, inspection)
        if not expected or _source_snapshot(path) != expected:
            result = original_finish_image_inspection(
                window,
                path,
                generation,
                {
                    "recognized": False,
                    "description": "The selected image changed while it was being inspected. Choose the image again.",
                },
            )
            window.append_log("Image inspection was discarded because the selected source snapshot changed.")
            return result
        result = original_finish_image_inspection(window, path, generation, inspection)
        enriched = enrich_linux_inspection(path, window.inspection, expected)
        if enriched is not window.inspection:
            window.inspection = enriched
            window.update_layout(enriched)
            window.set_busy(window.busy)
            profile = enriched.get("compatibility_profile") or {}
            window.append_log("Linux image compatibility:\n" + str(profile.get("summary") or ""))
        return result

    window_class._run_image_inspection = integrated_run_image_inspection
    window_class._finish_image_inspection = integrated_finish_image_inspection
    window_class._linux_compatibility_installed = True
