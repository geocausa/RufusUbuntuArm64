"""Packaged RufusArm64 entry point with all reviewed main-window integrations."""

import os
import struct
import sys

from gi.repository import Gtk

from rufusarm64_device_qualify_dialog import install_drive_backup
from rufusarm64_freedos_dialog import install_freedos
from rufusarm64_nonbootable_dialog import NonBootableFormatDialog, install_nonbootable


POST_OPERATION_RESTORE = 9101
POST_OPERATION_ANOTHER = 9102
ISO_SECTOR_SIZE = 2048
FIRST_ISO_DESCRIPTOR = 16
LAST_ISO_DESCRIPTOR = 64
MAX_BOOT_CATALOGUE_BYTES = 2048
MAX_BOOT_IMAGE_PROBE_BYTES = 64 * 1024
MAX_BOOT_ENTRIES = 32


def _selected_target(window):
    index = window.target_combo.get_active()
    selected = window.devices[index] if 0 <= index < len(window.devices) else None
    return (
        str((selected or {}).get("path") or ""),
        str((selected or {}).get("identity") or ""),
    )


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


def linux_compatibility_profile(path, inspection):
    """Return a bounded read-only compatibility explanation for one plain raw image."""
    if not isinstance(inspection, dict):
        return {}
    if not inspection.get("recognized") or inspection.get("mode") != "raw":
        return {}
    if inspection.get("needs_preparation"):
        return {}
    container = str(inspection.get("container_format") or "plain").lower()
    if container not in {"", "plain"}:
        return {}

    resolved = os.path.realpath(str(path or ""))
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(resolved, flags)
    except OSError:
        return {}
    try:
        stat = os.fstat(descriptor)
        if not stat.st_size or not os.path.isfile(resolved):
            return {}
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            disk_layout = _has_disk_layout(handle)
            has_iso, catalogue_lba = _iso_boot_catalogue(handle)
            entries = _catalogue_boot_entries(handle, catalogue_lba) if has_iso else []
            bootloaders = _bootloader_fingerprints(handle, entries, stat.st_size)
    except (OSError, struct.error):
        return {}
    finally:
        os.close(descriptor)

    boot_methods = sorted({platform for platform, _ in entries}, key=lambda item: (item != "BIOS", item))
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
        if bootloaders:
            parts.append("Bootloader fingerprint: " + ", ".join(bootloaders) + ".")
    parts.append("Software inspection does not prove that the intended computer will boot this USB.")

    return {
        "write_path": write_path,
        "hybrid": bool(has_iso and disk_layout),
        "optical": bool(has_iso),
        "boot_methods": boot_methods,
        "bootloaders": bootloaders,
        "summary": " ".join(parts),
    }


def enrich_linux_inspection(path, inspection):
    """Attach an idempotent Linux compatibility profile to a helper result."""
    if not isinstance(inspection, dict) or inspection.get("compatibility_profile"):
        return inspection
    profile = linux_compatibility_profile(path, inspection)
    if not profile:
        return inspection
    enriched = dict(inspection)
    enriched["compatibility_profile"] = profile
    base = str(enriched.get("description") or "").strip()
    enriched["description"] = (base + "\n" if base else "") + profile["summary"]
    return enriched


def install_linux_compatibility(window_class):
    """Install bounded image-specific Linux compatibility reporting."""
    if getattr(window_class, "_linux_compatibility_installed", False):
        return
    original_finish_image_inspection = window_class._finish_image_inspection

    def integrated_finish_image_inspection(window, path, generation, inspection):
        result = original_finish_image_inspection(window, path, generation, inspection)
        current_path = window.image_chooser.get_filename() or ""
        if window.closed or generation != window.inspection_generation or current_path != path:
            return result
        enriched = enrich_linux_inspection(path, window.inspection)
        if enriched is not window.inspection:
            window.inspection = enriched
            window.update_layout(enriched)
            window.set_busy(window.busy)
            profile = enriched.get("compatibility_profile") or {}
            window.append_log("Linux image compatibility:\n" + str(profile.get("summary") or ""))
        return result

    window_class._finish_image_inspection = integrated_finish_image_inspection
    window_class._linux_compatibility_installed = True


def install_post_operation_reuse(window_class):
    """Install explicit, non-destructive next-step actions around the main writer."""
    if getattr(window_class, "_post_operation_reuse_installed", False):
        return

    original_init = window_class.__init__
    original_start = window_class.start
    original_finish = window_class.finish
    original_set_busy = window_class.set_busy

    def integrated_init(window, app):
        original_init(window, app)
        window._post_operation_pending = ("", "")
        window._post_operation_target = ("", "")

        window.nonbootable_button.set_label("Restore / format…")
        window.nonbootable_button.set_tooltip_text(
            "Erase the selected removable drive, remove any boot layout, and create one verified data-only filesystem"
        )

        bar = Gtk.InfoBar()
        bar.set_message_type(Gtk.MessageType.INFO)
        bar.set_show_close_button(True)
        bar.set_no_show_all(True)
        bar.connect("response", window.post_operation_response)
        bar.add_button("Restore drive for storage…", POST_OPERATION_RESTORE)
        bar.add_button("Create another USB", POST_OPERATION_ANOTHER)

        label = Gtk.Label()
        label.set_xalign(0)
        label.set_line_wrap(True)
        bar.get_content_area().add(label)
        window.post_operation_bar = bar
        window.post_operation_label = label

        parent = window.progress.get_parent()
        parent.pack_start(bar, False, False, 0)
        children = parent.get_children()
        parent.reorder_child(bar, children.index(window.progress_detail) + 1)

    def integrated_start(window, *args):
        window.hide_post_operation_actions()
        window._post_operation_pending = _selected_target(window)
        result = original_start(window, *args)
        if window.active_job != "writer":
            window._post_operation_pending = ("", "")
        return result

    def integrated_finish(window, return_code):
        target = window._post_operation_pending
        mode = str(getattr(window, "active_mode", "") or "")
        was_cancelled = bool(getattr(window, "cancel_requested", False))
        result = original_finish(window, return_code)
        window._post_operation_pending = ("", "")
        if all(target):
            window._post_operation_target = target
            if return_code == 0:
                window.show_post_operation_actions(
                    "USB creation is complete. Keep this bootable medium unchanged, create another copy from the selected image, "
                    "or erase its boot layout later and restore the whole drive as ordinary storage.",
                    Gtk.MessageType.INFO,
                )
            else:
                state = "was cancelled" if was_cancelled else "failed"
                window.show_post_operation_actions(
                    f"USB creation {state}. The selected drive may contain incomplete media. Recreate it or use Restore drive for "
                    "storage before ordinary file use.",
                    Gtk.MessageType.WARNING,
                )
            window.append_log(
                f"Post-operation actions are bound to {target[0]} ({target[1]}) after mode {mode or 'unknown'}."
            )
        return result

    def integrated_set_busy(window, busy):
        original_set_busy(window, busy)
        bar = getattr(window, "post_operation_bar", None)
        if bar is not None:
            bar.set_sensitive(not busy)

    def show_post_operation_actions(window, text, message_type):
        window.post_operation_label.set_text(text)
        window.post_operation_bar.set_message_type(message_type)
        window.post_operation_bar.set_no_show_all(False)
        window.post_operation_bar.show_all()

    def hide_post_operation_actions(window):
        bar = getattr(window, "post_operation_bar", None)
        if bar is None:
            return
        bar.hide()
        bar.set_no_show_all(True)

    def post_operation_response(window, _bar, response_id):
        if response_id == POST_OPERATION_ANOTHER:
            window.hide_post_operation_actions()
            window.progress.set_fraction(0.0)
            window.progress.set_text("Ready for another USB")
            window.progress_detail.set_text(
                "The image remains selected. Connect or choose another removable drive, check it carefully, then select Create USB."
            )
            window.refresh_devices()
            window.target_combo.grab_focus()
            return
        if response_id != POST_OPERATION_RESTORE:
            window.hide_post_operation_actions()
            return

        device, identity = window._post_operation_target
        window.hide_post_operation_actions()
        if not device or not identity:
            window.progress_detail.set_text("The completed operation target is no longer available. Select the drive and refresh first.")
            return
        dialog = NonBootableFormatDialog(window, device, identity)
        dialog.run()
        if dialog.running:
            return
        dialog.closed = True
        dialog.plan_generation += 1
        dialog.run_generation += 1
        dialog._remove_cancel_path()
        dialog.destroy()
        window.save_settings()
        window.refresh_devices()

    window_class.__init__ = integrated_init
    window_class.start = integrated_start
    window_class.finish = integrated_finish
    window_class.set_busy = integrated_set_busy
    window_class.show_post_operation_actions = show_post_operation_actions
    window_class.hide_post_operation_actions = hide_post_operation_actions
    window_class.post_operation_response = post_operation_response
    window_class._post_operation_reuse_installed = True


def run_rufusarm64(argv=None):
    """Run the main GTK application after installing the reviewed extensions."""
    from rufusarm64 import RufusApp, RufusWindow

    install_drive_backup(RufusWindow)
    install_nonbootable(RufusWindow)
    install_freedos(RufusWindow)
    install_linux_compatibility(RufusWindow)
    install_post_operation_reuse(RufusWindow)
    return RufusApp().run(list(sys.argv[1:] if argv is None else argv))
