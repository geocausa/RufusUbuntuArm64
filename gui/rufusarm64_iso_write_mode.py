"""Rufus-style ISO Image mode versus DD Image mode selection for Linux ISOHybrid media."""

import os

from gi.repository import Gtk

import rufusarm64
from rufusarm64_logic import inspect_source_identity, normalize_volume_label


ISO_HELPER = "/usr/lib/rufusarm64/rufusarm64-persistence-helper"
_pending_iso_window = None


def hybrid_mode_available(info):
    """Return whether inspection exposes a bounded UEFI ISOHybrid choice."""
    if not isinstance(info, dict) or info.get("mode") != "raw":
        return False
    profile = info.get("compatibility_profile")
    if not isinstance(profile, dict):
        return False
    methods = profile.get("boot_methods") or []
    return (
        profile.get("write_path") == "hybrid-direct-write"
        and profile.get("hybrid") is True
        and isinstance(methods, list)
        and "UEFI" in methods
    )


def build_iso_write_command(pkexec, helper, image, path, identity, cancel_path, volume_label="RUFUS-LIVE"):
    """Build the narrow identity-bound privileged ISO Image mode command."""
    values = [str(value or "").strip() for value in (pkexec, helper, image, path, identity, cancel_path)]
    if not all(values):
        raise ValueError("ISO Image mode requires authentication, an image, a USB identity, and a cancellation channel.")
    resolved_image, source_identity = inspect_source_identity(values[2])
    return [
        values[0],
        values[1],
        "--operation",
        "iso",
        "--image",
        resolved_image,
        "--expected-source-identity",
        source_identity,
        "--device",
        values[3],
        "--expected-identity",
        values[4],
        "--volume-label",
        normalize_volume_label(volume_label, "fat32"),
        "--cancel-file",
        values[5],
        "--json-progress",
        "--yes",
    ]


class ISOHybridWriteModeDialog(Gtk.Dialog):
    """Explicit choice matching Rufus's ISOHybrid write-mode boundary."""

    def __init__(self, parent):
        super().__init__(title="ISOHybrid image detected", transient_for=parent, modal=True)
        self.add_button("Cancel", Gtk.ResponseType.CANCEL)
        self.add_button("Continue", Gtk.ResponseType.OK)
        self.set_default_response(Gtk.ResponseType.OK)
        self.set_default_size(620, 360)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        box.set_border_width(18)
        self.get_content_area().pack_start(box, True, True, 0)

        title = Gtk.Label()
        title.set_markup("<span size='large' weight='bold'>Choose how to write this image</span>")
        title.set_xalign(0)
        box.pack_start(title, False, False, 0)

        intro = Gtk.Label(
            label=(
                "This image can be used as an optical ISO or as a complete disk image. "
                "ISO Image mode is selected by default, as in Rufus on Windows."
            )
        )
        intro.set_xalign(0)
        intro.set_line_wrap(True)
        box.pack_start(intro, False, False, 0)

        self.iso_mode = Gtk.RadioButton.new_with_label_from_widget(
            None, "Write in ISO Image mode (Recommended)"
        )
        self.iso_mode.set_active(True)
        self.iso_mode.set_tooltip_text(
            "Create a conventional writable FAT32 USB and extract and verify every supported file."
        )
        box.pack_start(self.iso_mode, False, False, 0)

        iso_detail = Gtk.Label(
            label=(
                "Creates one conventional writable FAT32 partition, extracts the ISO files, and verifies every copied file by SHA-256. "
                "The current safe scope requires compatible filenames, files below FAT32's 4 GiB limit, sufficient capacity, and the correct UEFI fallback loader. "
                "All checks finish before the USB is erased."
            )
        )
        iso_detail.set_xalign(0)
        iso_detail.set_line_wrap(True)
        iso_detail.set_margin_start(28)
        iso_detail.get_style_context().add_class("dim-label")
        box.pack_start(iso_detail, False, False, 0)

        self.dd_mode = Gtk.RadioButton.new_with_label_from_widget(
            self.iso_mode, "Write in DD Image mode"
        )
        self.dd_mode.set_tooltip_text(
            "Copy the image byte-for-byte, preserving its embedded partitions and boot structures."
        )
        box.pack_start(self.dd_mode, False, False, 0)

        dd_detail = Gtk.Label(
            label=(
                "Copies the whole image exactly, preserving its embedded partition table, filesystems, boot records, and fixed image capacity. "
                "Use this when ISO Image mode is refused or when an exact clone is preferred."
            )
        )
        dd_detail.set_xalign(0)
        dd_detail.set_line_wrap(True)
        dd_detail.set_margin_start(28)
        dd_detail.get_style_context().add_class("dim-label")
        box.pack_start(dd_detail, False, False, 0)

        self.show_all()

    def selected_mode(self):
        return "iso" if self.iso_mode.get_active() else "dd"


def install_iso_write_mode():
    """Install the choice dialog without changing the reviewed DD writer."""
    window_class = rufusarm64.RufusWindow
    if getattr(window_class, "_iso_write_mode_installed", False):
        return

    original_update_layout = window_class.update_layout
    original_start = window_class.start
    original_build_writer_command = rufusarm64.build_writer_command

    def integrated_update_layout(window, info):
        result = original_update_layout(window, info)
        if hybrid_mode_available(info):
            window.mode_value.set_text(
                "ISOHybrid image: ISO Image mode (recommended/default) and DD Image mode are available. "
                "Choose when Create USB is pressed."
            )
            window.layout_note.set_text(
                "ISO Image mode creates a conventional writable FAT32 USB after full compatibility checks. "
                "DD Image mode preserves the image byte-for-byte."
            )
        return result

    def integrated_build_writer_command(*args, **kwargs):
        global _pending_iso_window
        window = _pending_iso_window
        if window is None:
            return original_build_writer_command(*args, **kwargs)
        if not os.path.isfile(ISO_HELPER) or not os.access(ISO_HELPER, os.X_OK):
            raise ValueError("The package-owned ISO Image mode helper is not installed or executable.")
        # The base builder's positional contract keeps image, target, identity,
        # cancellation path, and volume label at stable positions.
        if len(args) < 8:
            raise ValueError("ISO Image mode received an incomplete writer request.")
        return build_iso_write_command(
            args[0],
            ISO_HELPER,
            args[2],
            args[3],
            args[4],
            args[6],
            "RUFUS-LIVE",
        )

    def integrated_start(window, *args):
        global _pending_iso_window
        if window.persistence_enabled.get_active() or not hybrid_mode_available(window.inspection):
            return original_start(window, *args)

        dialog = ISOHybridWriteModeDialog(window)
        response = dialog.run()
        choice = dialog.selected_mode()
        dialog.destroy()
        if response != Gtk.ResponseType.OK:
            return None

        original_inspection = window.inspection
        original_verify = window.verify.get_active()
        temporary = dict(original_inspection)
        if choice == "iso":
            temporary.update(
                {
                    "mode": "linux-iso",
                    "description": (
                        "ISO Image mode (recommended): create a conventional writable FAT32 USB, "
                        "extract the ISO files, and SHA-256 verify every copied file"
                    ),
                    "windows_options": False,
                }
            )
            window.verify.set_active(True)
            _pending_iso_window = window
        else:
            temporary.update(
                {
                    "mode": "raw",
                    "description": (
                        "DD Image mode: preserve the ISOHybrid partition and boot layout byte-for-byte"
                    ),
                    "windows_options": False,
                }
            )

        window.inspection = temporary
        try:
            result = original_start(window, *args)
            if choice == "iso" and window.active_job == "writer":
                window.active_mode = "linux-iso"
                window.active_verify_requested = True
            return result
        finally:
            _pending_iso_window = None
            window.inspection = original_inspection
            window.verify.set_active(original_verify)
            window.update_layout(window.inspection)

    rufusarm64.build_writer_command = integrated_build_writer_command
    window_class.update_layout = integrated_update_layout
    window_class.start = integrated_start
    window_class._iso_write_mode_installed = True
