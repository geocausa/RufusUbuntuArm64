"""Rufus-style ISO Image mode versus DD Image mode selection for Linux ISOHybrid media."""

import os

from gi.repository import Gtk

import rufusarm64
from rufusarm64_logic import inspect_source_identity, normalize_volume_label


ISO_HELPER = "/usr/lib/rufusarm64/rufusarm64-persistence-helper"
DEFAULT_ISO_PARTITION_SCHEME = "mbr"
DEFAULT_ISO_FILESYSTEM = "auto"
DEFAULT_ISO_CLUSTER_SIZE = "4096"
DEFAULT_ISO_VOLUME_LABEL = "RUFUS-LIVE"
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


def normalize_iso_partition_scheme(value):
    value = str(value or DEFAULT_ISO_PARTITION_SCHEME).strip().lower()
    if value not in {"mbr", "gpt"}:
        raise ValueError("ISO Image mode partition scheme must be MBR or GPT.")
    return value


def normalize_iso_filesystem(value):
    value = str(value or DEFAULT_ISO_FILESYSTEM).strip().lower()
    if value in {"automatic", ""}:
        value = "auto"
    if value not in {"auto", "fat32", "ntfs"}:
        raise ValueError("ISO Image mode filesystem must be Automatic, FAT32, or NTFS.")
    return value


def normalize_iso_cluster_size(value):
    value = str(value or DEFAULT_ISO_CLUSTER_SIZE).strip().lower()
    if value in {"", "auto", "0"}:
        return DEFAULT_ISO_CLUSTER_SIZE
    if value not in {"4096", "8192", "16384", "32768"}:
        raise ValueError("ISO Image mode cluster size must be 4 KiB, 8 KiB, 16 KiB, or 32 KiB.")
    return value


def normalize_iso_volume_label(value, filesystem):
    filesystem = normalize_iso_filesystem(filesystem)
    label_filesystem = "ntfs" if filesystem == "ntfs" else "fat32"
    return normalize_volume_label(value or DEFAULT_ISO_VOLUME_LABEL, label_filesystem)


def iso_source_state(previous_source, selected_source, current_label):
    selected = os.path.realpath(str(selected_source or "").strip()) if selected_source else ""
    label = str(current_label or DEFAULT_ISO_VOLUME_LABEL)
    if selected and selected != str(previous_source or ""):
        label = DEFAULT_ISO_VOLUME_LABEL
    return selected or str(previous_source or ""), label


def iso_layout_summary(partition_scheme, filesystem, cluster_size, volume_label):
    scheme = normalize_iso_partition_scheme(partition_scheme).upper()
    filesystem = normalize_iso_filesystem(filesystem)
    cluster = int(normalize_iso_cluster_size(cluster_size)) // 1024
    label = normalize_iso_volume_label(volume_label, filesystem)
    filesystem_text = filesystem.upper()
    if filesystem == "auto":
        filesystem_text = "Automatic (FAT32 preferred)"
    return f"{scheme} / UEFI / {filesystem_text} / {cluster} KiB clusters / label {label}"


def build_iso_write_command(
    pkexec,
    helper,
    image,
    path,
    identity,
    cancel_path,
    volume_label=DEFAULT_ISO_VOLUME_LABEL,
    partition_scheme=DEFAULT_ISO_PARTITION_SCHEME,
    filesystem=DEFAULT_ISO_FILESYSTEM,
    cluster_size=DEFAULT_ISO_CLUSTER_SIZE,
):
    """Build the narrow identity-bound privileged ISO Image mode command."""
    values = [str(value or "").strip() for value in (pkexec, helper, image, path, identity, cancel_path)]
    if not all(values):
        raise ValueError("ISO Image mode requires authentication, an image, a USB identity, and a cancellation channel.")
    resolved_image, source_identity = inspect_source_identity(values[2])
    scheme = normalize_iso_partition_scheme(partition_scheme)
    selected_filesystem = normalize_iso_filesystem(filesystem)
    cluster = normalize_iso_cluster_size(cluster_size)
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
        normalize_iso_volume_label(volume_label, selected_filesystem),
        "--partition-scheme",
        scheme,
        "--filesystem",
        selected_filesystem,
        "--cluster-size",
        cluster,
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
            "Create a conventional writable USB using reviewed MBR/GPT and Automatic/FAT32/NTFS settings."
        )
        box.pack_start(self.iso_mode, False, False, 0)

        iso_detail = Gtk.Label(
            label=(
                "Creates a conventional writable data partition, extracts the ISO files, and verifies every copied file by SHA-256. "
                "Automatic prefers FAT32 and uses NTFS with the verified UEFI:NTFS boot partition only when FAT32 is incompatible. "
                "Partition scheme, filesystem, cluster size, and label come from the visible ISO-mode controls. All checks finish before the USB is erased."
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
                "The visible ISO extraction layout controls are ignored in DD mode."
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
    """Install the choice and reviewed ISO layout controls without changing DD semantics."""
    window_class = rufusarm64.RufusWindow
    if getattr(window_class, "_iso_write_mode_installed", False):
        return

    original_init = window_class.__init__
    original_update_layout = window_class.update_layout
    original_start = window_class.start
    original_save_settings = window_class.save_settings
    original_partition_changed = window_class.partition_changed
    original_filesystem_changed = window_class.filesystem_changed
    original_build_writer_command = rufusarm64.build_writer_command

    def update_iso_note(window):
        try:
            summary = iso_layout_summary(
                window.partition_combo.get_active_id(),
                window.filesystem_combo.get_active_id(),
                window.cluster_combo.get_active_id(),
                window.volume_label.get_text(),
            )
        except ValueError as exc:
            window.layout_note.set_text(str(exc))
            return
        window.layout_note.set_text(
            "ISO Image mode: " + summary + ". MBR is broadly compatible with removable-media UEFI; GPT is the modern alternative. "
            "Automatic prefers FAT32 and selects NTFS/UEFI:NTFS only when the complete media tree requires it. "
            "DD Image mode ignores these controls and preserves the source image exactly."
        )

    def label_changed(widget, window):
        if getattr(window, "_iso_settings_suspended", False):
            return
        if hybrid_mode_available(window.inspection) or _pending_iso_window is window:
            window.iso_volume_label = widget.get_text()
            update_iso_note(window)
        elif window.inspection.get("mode") == "windows":
            window._windows_volume_label = widget.get_text()

    def cluster_changed(_widget, window):
        if hybrid_mode_available(window.inspection) or _pending_iso_window is window:
            try:
                window.iso_cluster_size = normalize_iso_cluster_size(window.cluster_combo.get_active_id())
            except ValueError:
                return
            update_iso_note(window)

    def integrated_init(window, *args, **kwargs):
        original_init(window, *args, **kwargs)
        window.iso_partition_scheme = normalize_iso_partition_scheme(
            window.settings.get("iso_partition_scheme", DEFAULT_ISO_PARTITION_SCHEME)
        )
        window.iso_filesystem = normalize_iso_filesystem(
            window.settings.get("iso_filesystem", DEFAULT_ISO_FILESYSTEM)
        )
        window.iso_cluster_size = normalize_iso_cluster_size(
            window.settings.get("iso_cluster_size", DEFAULT_ISO_CLUSTER_SIZE)
        )
        try:
            window.iso_volume_label = normalize_iso_volume_label(
                window.settings.get("iso_volume_label", DEFAULT_ISO_VOLUME_LABEL), window.iso_filesystem
            )
        except ValueError:
            window.iso_volume_label = DEFAULT_ISO_VOLUME_LABEL
        window._windows_volume_label = str(window.settings.get("volume_label", "RUFUSARM64"))
        window._iso_source_path = ""
        window._iso_settings_suspended = False
        window.volume_label.connect("changed", label_changed, window)
        window.cluster_combo.connect("changed", cluster_changed, window)

    def apply_iso_controls(window):
        source, label = iso_source_state(
            window._iso_source_path,
            window.image_chooser.get_filename() or "",
            window.iso_volume_label,
        )
        window._iso_source_path = source
        window.iso_volume_label = label
        window._iso_settings_suspended = True
        try:
            window.partition_combo.set_active_id(window.iso_partition_scheme)
            window.target_system_combo.set_active_id("uefi")
            window.filesystem_combo.set_active_id(window.iso_filesystem)
            window.cluster_combo.set_active_id(window.iso_cluster_size)
            window.volume_label.set_max_length(32 if window.iso_filesystem == "ntfs" else 11)
            window.volume_label.set_text(
                normalize_iso_volume_label(window.iso_volume_label, window.iso_filesystem)
            )
        except ValueError:
            window.iso_volume_label = DEFAULT_ISO_VOLUME_LABEL
            window.volume_label.set_text(DEFAULT_ISO_VOLUME_LABEL)
        finally:
            window._iso_settings_suspended = False
        editable = not window.busy
        window.partition_combo.set_sensitive(editable)
        window.target_system_combo.set_sensitive(False)
        window.filesystem_combo.set_sensitive(editable)
        window.cluster_combo.set_sensitive(editable)
        window.volume_label.set_sensitive(editable)
        for widget in (
            window.driver_chooser,
            window.dbx_chooser,
            window.dbx_update_button,
            window.quick_format,
            window.bad_block_check,
        ):
            widget.set_sensitive(False)
        update_iso_note(window)

    def integrated_update_layout(window, info):
        result = original_update_layout(window, info)
        if info.get("mode") == "windows":
            window._iso_settings_suspended = True
            try:
                window.volume_label.set_text(window._windows_volume_label)
            finally:
                window._iso_settings_suspended = False
        elif hybrid_mode_available(info):
            window.mode_value.set_text(
                "ISOHybrid image: ISO Image mode (recommended/default) and DD Image mode are available. "
                "ISO mode supports reviewed MBR/GPT and Automatic/FAT32/NTFS choices."
            )
            apply_iso_controls(window)
        return result

    def integrated_partition_changed(window, *args):
        result = original_partition_changed(window, *args)
        if hybrid_mode_available(window.inspection) or _pending_iso_window is window:
            try:
                window.iso_partition_scheme = normalize_iso_partition_scheme(
                    window.partition_combo.get_active_id()
                )
            except ValueError:
                return result
            update_iso_note(window)
        return result

    def integrated_filesystem_changed(window, *args):
        result = original_filesystem_changed(window, *args)
        if not (hybrid_mode_available(window.inspection) or _pending_iso_window is window):
            return result
        try:
            selected = normalize_iso_filesystem(window.filesystem_combo.get_active_id())
        except ValueError:
            return result
        window.iso_filesystem = selected
        window._iso_settings_suspended = True
        try:
            window.volume_label.set_max_length(32 if selected == "ntfs" else 11)
            window.iso_volume_label = normalize_iso_volume_label(window.volume_label.get_text(), selected)
            window.volume_label.set_text(window.iso_volume_label)
        except ValueError:
            window.iso_volume_label = DEFAULT_ISO_VOLUME_LABEL
            window.volume_label.set_text(DEFAULT_ISO_VOLUME_LABEL)
        finally:
            window._iso_settings_suspended = False
        update_iso_note(window)
        return result

    def integrated_save_settings(window):
        iso_active = hybrid_mode_available(window.inspection) or _pending_iso_window is window
        if not iso_active:
            if window.inspection.get("mode") == "windows":
                window._windows_volume_label = window.volume_label.get_text()
            return original_save_settings(window)

        window.iso_partition_scheme = normalize_iso_partition_scheme(window.partition_combo.get_active_id())
        window.iso_filesystem = normalize_iso_filesystem(window.filesystem_combo.get_active_id())
        window.iso_cluster_size = normalize_iso_cluster_size(window.cluster_combo.get_active_id())
        window.iso_volume_label = normalize_iso_volume_label(window.volume_label.get_text(), window.iso_filesystem)
        window.settings["iso_partition_scheme"] = window.iso_partition_scheme
        window.settings["iso_filesystem"] = window.iso_filesystem
        window.settings["iso_cluster_size"] = window.iso_cluster_size
        window.settings["iso_volume_label"] = window.iso_volume_label

        state = (
            window.partition_combo.get_active_id(),
            window.target_system_combo.get_active_id(),
            window.filesystem_combo.get_active_id(),
            window.cluster_combo.get_active_id(),
            window.volume_label.get_text(),
        )
        window._iso_settings_suspended = True
        try:
            window.partition_combo.set_active_id(window.windows_partition_scheme)
            window.target_system_combo.set_active_id(window.windows_target_system)
            window.filesystem_combo.set_active_id(window.windows_filesystem)
            window.cluster_combo.set_active_id(window.windows_cluster_size)
            window.volume_label.set_text(window._windows_volume_label)
            original_save_settings(window)
        finally:
            window.partition_combo.set_active_id(state[0])
            window.target_system_combo.set_active_id(state[1])
            window.filesystem_combo.set_active_id(state[2])
            window.cluster_combo.set_active_id(state[3])
            window.volume_label.set_text(state[4])
            window._iso_settings_suspended = False

    def integrated_build_writer_command(*args, **kwargs):
        window = _pending_iso_window
        if window is None:
            return original_build_writer_command(*args, **kwargs)
        if not os.path.isfile(ISO_HELPER) or not os.access(ISO_HELPER, os.X_OK):
            raise ValueError("The package-owned ISO Image mode helper is not installed or executable.")
        if len(args) < 8:
            raise ValueError("ISO Image mode received an incomplete writer request.")
        return build_iso_write_command(
            args[0],
            ISO_HELPER,
            args[2],
            args[3],
            args[4],
            args[6],
            window.volume_label.get_text(),
            window.partition_combo.get_active_id(),
            window.filesystem_combo.get_active_id(),
            window.cluster_combo.get_active_id(),
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
        original_append_log = window.append_log
        temporary = dict(original_inspection)
        layout_summary = ""
        if choice == "iso":
            try:
                window.iso_partition_scheme = normalize_iso_partition_scheme(window.partition_combo.get_active_id())
                window.iso_filesystem = normalize_iso_filesystem(window.filesystem_combo.get_active_id())
                window.iso_cluster_size = normalize_iso_cluster_size(window.cluster_combo.get_active_id())
                window.iso_volume_label = normalize_iso_volume_label(window.volume_label.get_text(), window.iso_filesystem)
                layout_summary = iso_layout_summary(
                    window.iso_partition_scheme,
                    window.iso_filesystem,
                    window.iso_cluster_size,
                    window.iso_volume_label,
                )
            except ValueError as exc:
                window.message(str(exc), Gtk.MessageType.ERROR)
                return None
            temporary.update(
                {
                    "mode": "linux-iso",
                    "description": (
                        "ISO Image mode (recommended): " + layout_summary + "; extract the ISO files and SHA-256 verify every copied file"
                    ),
                    "windows_options": False,
                }
            )
            window.verify.set_active(True)
            _pending_iso_window = window

            def append_iso_log(text):
                if str(text) == "Layout: From image / From image / From image":
                    text = "Layout: " + layout_summary
                return original_append_log(text)

            window.append_log = append_iso_log
        else:
            temporary.update(
                {
                    "mode": "raw",
                    "description": (
                        "DD Image mode: preserve the ISOHybrid partition and boot layout byte-for-byte; visible ISO layout choices are ignored"
                    ),
                    "windows_options": False,
                }
            )

        window.inspection = temporary
        try:
            result = original_start(window, *args)
            if choice == "iso" and window.active_job == "writer":
                window.active_mode = "linux-iso"
                window.active_filesystem = window.iso_filesystem
                window.active_verify_requested = True
            return result
        finally:
            _pending_iso_window = None
            window.append_log = original_append_log
            window.inspection = original_inspection
            window.verify.set_active(original_verify)
            window.update_layout(window.inspection)

    rufusarm64.build_writer_command = integrated_build_writer_command
    window_class.__init__ = integrated_init
    window_class.update_layout = integrated_update_layout
    window_class.partition_changed = integrated_partition_changed
    window_class.filesystem_changed = integrated_filesystem_changed
    window_class.save_settings = integrated_save_settings
    window_class.start = integrated_start
    window_class._iso_write_mode_installed = True
