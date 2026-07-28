"""GTK integration for Linux ISO Image mode with DD as the safe fallback."""

import json
import os
import signal
import subprocess
import tempfile
import threading

from gi.repository import GLib, Gtk

from rufusarm64_iso_write_logic import (
    DD_IMAGE_MODE,
    ISO_IMAGE_MODE,
    build_iso_analysis_command,
    build_iso_create_command,
    helper_is_usable,
    iso_analysis_summary,
    normalize_iso_analysis,
)
from rufusarm64_logic import human_bytes, inspect_source_identity


ISO_HELPER = "/usr/lib/rufusarm64/rufusarm64-iso-helper"
PKEXEC = "/usr/bin/pkexec"
ISO_HINT = (
    "ISO Image mode will be checked against the selected USB when Create USB is pressed. "
    "When supported it is the default; byte-for-byte DD Image mode remains available."
)


def _eligible(window):
    inspection = getattr(window, "inspection", {}) or {}
    profile = inspection.get("compatibility_profile") or {}
    return (
        inspection.get("recognized")
        and inspection.get("mode") == "raw"
        and not inspection.get("needs_preparation")
        and bool(profile.get("hybrid"))
        and bool(profile.get("optical"))
        and not window.persistence_enabled.get_active()
    )


def _selected_device(window):
    index = window.target_combo.get_active()
    if not (0 <= index < len(window.devices)):
        return None
    device = window.devices[index]
    required = (
        str(device.get("path") or ""),
        str(device.get("identity") or ""),
        int(device.get("size") or 0),
    )
    return device if all(required) else None


def _request_cancel(path, process):
    if path:
        try:
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            os.close(descriptor)
        except FileExistsError:
            pass
        except OSError:
            pass
    if process is not None and process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            pass


def _analyze(window, image, device):
    if not helper_is_usable(ISO_HELPER):
        return None, "The package-owned ISO Image mode helper is not installed or executable."
    if not helper_is_usable(PKEXEC):
        return None, "Ubuntu administrator authentication (pkexec) is not installed."
    try:
        resolved_image, source_identity = inspect_source_identity(image)
    except ValueError as exc:
        return None, str(exc)

    runtime_dir = f"/run/user/{os.getuid()}"
    cancel_path = ""
    try:
        descriptor, cancel_path = tempfile.mkstemp(
            prefix="rufusarm64-iso-analysis-", suffix=".cancel", dir=runtime_dir
        )
        os.close(descriptor)
        os.unlink(cancel_path)
        command = build_iso_analysis_command(
            PKEXEC,
            ISO_HELPER,
            resolved_image,
            source_identity,
            int(device.get("size") or 0),
            cancel_path,
        )
    except (OSError, ValueError) as exc:
        return None, str(exc)

    dialog = Gtk.Dialog(title="Checking ISO Image mode", transient_for=window, modal=True)
    cancel_button = dialog.add_button("Cancel", Gtk.ResponseType.CANCEL)
    dialog.set_default_response(Gtk.ResponseType.CANCEL)
    dialog.set_deletable(False)
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
    box.set_border_width(18)
    spinner = Gtk.Spinner()
    spinner.start()
    label = Gtk.Label(
        label=(
            "RufusArm64 is mounting the ISO privately and read-only, hashing every file, "
            "checking the fallback UEFI loader, FAT32 names and capacity. The USB is not being modified."
        )
    )
    label.set_xalign(0)
    label.set_line_wrap(True)
    box.pack_start(spinner, False, False, 0)
    box.pack_start(label, False, False, 0)
    dialog.get_content_area().pack_start(box, True, True, 0)
    dialog.show_all()

    state = {"done": False, "process": None, "returncode": 1, "stdout": "", "stderr": "", "cancelled": False}

    def worker():
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            state["process"] = process
            stdout, stderr = process.communicate(timeout=300)
            state["returncode"] = process.returncode
            state["stdout"] = stdout
            state["stderr"] = stderr
        except subprocess.TimeoutExpired:
            _request_cancel(cancel_path, state.get("process"))
            state["stderr"] = "ISO Image mode analysis exceeded the five-minute safety limit."
        except Exception as exc:
            state["stderr"] = str(exc)
        finally:
            state["done"] = True
            GLib.idle_add(dialog.response, Gtk.ResponseType.OK)

    threading.Thread(target=worker, daemon=True).start()
    while not state["done"]:
        response = dialog.run()
        if response == Gtk.ResponseType.CANCEL and not state["done"]:
            state["cancelled"] = True
            cancel_button.set_sensitive(False)
            spinner.start()
            label.set_text("Cancellation requested. Waiting for the private read-only mount to be cleaned up…")
            _request_cancel(cancel_path, state.get("process"))
            continue
    dialog.destroy()
    try:
        os.unlink(cancel_path)
    except FileNotFoundError:
        pass
    except OSError:
        pass

    if state["cancelled"]:
        return None, "ISO Image mode analysis was cancelled; nothing was modified."
    if state["returncode"] != 0:
        error = state["stderr"].strip() or state["stdout"].strip() or "ISO Image mode analysis failed."
        return None, error
    try:
        payload = normalize_iso_analysis(json.loads(state["stdout"]))
    except (ValueError, json.JSONDecodeError) as exc:
        return None, str(exc)

    current = _selected_device(window)
    if (
        current is None
        or window.image_chooser.get_filename() != image
        or str(current.get("path") or "") != str(device.get("path") or "")
        or str(current.get("identity") or "") != str(device.get("identity") or "")
        or int(current.get("size") or 0) != int(device.get("size") or 0)
    ):
        return None, "The selected ISO or USB changed during analysis. Choose them again."
    try:
        current_image, current_identity = inspect_source_identity(image)
    except ValueError as exc:
        return None, str(exc)
    if current_image != resolved_image or current_identity != source_identity:
        return None, "The selected ISO changed during analysis. Choose it again."
    return (payload, resolved_image, source_identity), ""


def _choose_supported(window, analysis):
    dialog = Gtk.Dialog(title="ISOHybrid image detected", transient_for=window, modal=True)
    dialog.add_button("Cancel", Gtk.ResponseType.CANCEL)
    dialog.add_button("Continue", Gtk.ResponseType.OK)
    dialog.set_default_response(Gtk.ResponseType.OK)
    dialog.set_default_size(620, 360)
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
    box.set_border_width(18)
    dialog.get_content_area().pack_start(box, True, True, 0)

    title = Gtk.Label()
    title.set_markup("<span size='large' weight='bold'>Choose how to write this image</span>")
    title.set_xalign(0)
    box.pack_start(title, False, False, 0)

    iso = Gtk.RadioButton.new_with_label_from_widget(None, "Write in ISO Image mode (Recommended)")
    iso.set_active(True)
    iso.set_tooltip_text("Create a fresh writable FAT32 USB and copy and verify the ISO filesystem tree.")
    box.pack_start(iso, False, False, 0)
    iso_detail = Gtk.Label(label=iso_analysis_summary(analysis, human_bytes))
    iso_detail.set_xalign(0)
    iso_detail.set_line_wrap(True)
    iso_detail.set_margin_start(28)
    iso_detail.get_style_context().add_class("dim-label")
    box.pack_start(iso_detail, False, False, 0)

    dd = Gtk.RadioButton.new_with_label_from_widget(iso, "Write in DD Image mode")
    dd.set_tooltip_text("Preserve every byte, embedded partition and boot structure exactly as stored in the image.")
    box.pack_start(dd, False, False, 0)
    dd_detail = Gtk.Label(
        label=(
            "Use DD mode for an exact clone or when the image relies on its embedded hybrid layout. "
            "The resulting USB may expose unusual or read-only partitions."
        )
    )
    dd_detail.set_xalign(0)
    dd_detail.set_line_wrap(True)
    dd_detail.set_margin_start(28)
    dd_detail.get_style_context().add_class("dim-label")
    box.pack_start(dd_detail, False, False, 0)

    dialog.show_all()
    response = dialog.run()
    selected = ISO_IMAGE_MODE if iso.get_active() else DD_IMAGE_MODE
    dialog.destroy()
    return selected if response == Gtk.ResponseType.OK else ""


def _choose_dd_fallback(window, error):
    dialog = Gtk.MessageDialog(
        transient_for=window,
        modal=True,
        message_type=Gtk.MessageType.INFO,
        buttons=Gtk.ButtonsType.CANCEL,
        text="ISO Image mode is unavailable for this image and USB",
    )
    dialog.format_secondary_text(
        f"{error}\n\nRufusArm64 can still preserve the image exactly using DD Image mode."
    )
    dialog.add_button("Use DD Image mode", Gtk.ResponseType.OK)
    dialog.set_default_response(Gtk.ResponseType.CANCEL)
    response = dialog.run()
    dialog.destroy()
    return DD_IMAGE_MODE if response == Gtk.ResponseType.OK else ""


def install_iso_image_mode(window_class):
    """Install the ISO-vs-DD decision without weakening the existing writer."""
    if getattr(window_class, "_iso_image_mode_installed", False):
        return
    original_update_layout = window_class.update_layout
    original_start = window_class.start
    method_globals = original_start.__globals__
    original_builder = method_globals.get("build_writer_command")
    if not callable(original_builder):
        raise RuntimeError("RufusArm64 writer command boundary is unavailable")

    def integrated_update_layout(window, info):
        shown = info
        profile = (info or {}).get("compatibility_profile") if isinstance(info, dict) else None
        if isinstance(profile, dict) and profile.get("hybrid") and profile.get("optical"):
            shown = dict(info)
            description = str(shown.get("description") or "").strip()
            if ISO_HINT not in description:
                shown["description"] = (description + "\n" if description else "") + ISO_HINT
        return original_update_layout(window, shown)

    def integrated_start(window, *args):
        if not _eligible(window):
            return original_start(window, *args)
        image = window.image_chooser.get_filename() or ""
        device = _selected_device(window)
        if not image or device is None:
            return original_start(window, *args)

        analyzed, error = _analyze(window, image, device)
        if analyzed is None:
            selected_mode = _choose_dd_fallback(window, error)
            if not selected_mode:
                window.append_log(error)
                return None
            window.append_log("ISO Image mode unavailable; the user explicitly selected DD Image mode.\n" + error)
            return original_start(window, *args)

        analysis, resolved_image, source_identity = analyzed
        selected_mode = _choose_supported(window, analysis)
        if not selected_mode:
            return None
        if selected_mode == DD_IMAGE_MODE:
            window.append_log("Write method: DD Image mode selected explicitly.")
            return original_start(window, *args)

        device_path = str(device.get("path") or "")
        target_identity = str(device.get("identity") or "")

        def iso_builder(
            _pkexec,
            _helper,
            builder_image,
            builder_path,
            builder_identity,
            _verify,
            cancel_path,
            *_args,
            **_kwargs,
        ):
            if builder_image != image or builder_path != device_path or builder_identity != target_identity:
                raise ValueError("The ISO or USB selection changed after ISO Image mode analysis.")
            return build_iso_create_command(
                PKEXEC,
                ISO_HELPER,
                resolved_image,
                source_identity,
                device_path,
                target_identity,
                cancel_path,
                "RUFUS-LIVE",
            )

        previous_inspection = window.inspection
        previous_verify = window.verify.get_active()
        iso_inspection = dict(previous_inspection)
        iso_inspection["mode"] = ISO_IMAGE_MODE
        iso_inspection["description"] = (
            "Linux ISO Image mode (recommended): fresh GPT/UEFI/FAT32 layout with complete copied-file verification.\n"
            + iso_analysis_summary(analysis, human_bytes)
        )
        window.inspection = iso_inspection
        window.verify.set_active(True)
        method_globals["build_writer_command"] = iso_builder
        try:
            result = original_start(window, *args)
            if window.active_job == "writer":
                window.active_mode = ISO_IMAGE_MODE
                window.append_log("Write method: ISO Image mode selected (default).")
            return result
        finally:
            method_globals["build_writer_command"] = original_builder
            window.inspection = previous_inspection
            window.verify.set_active(previous_verify)
            window.update_layout(previous_inspection)
            window.set_busy(window.busy)

    window_class.update_layout = integrated_update_layout
    window_class.start = integrated_start
    window_class._iso_image_mode_installed = True
