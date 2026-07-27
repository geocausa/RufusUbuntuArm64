"""Focused GTK extension for explicit raw, dynamic VHD, and dynamic VHDX backup."""

import json
import os
import signal
import stat
import subprocess
import threading

from gi.repository import GLib, Gtk

from rufusarm64_i18n import gettext as _
import rufusarm64_device_qualify_dialog as backup_dialog
from rufusarm64_device_qualify import (
    backup_build_dry_run_command,
    backup_build_run_command,
    backup_confirmation_phrase,
    backup_decode_progress_line,
    backup_normalize_plan,
    backup_normalize_report,
    backup_progress_summary,
)

_FORMAT_LABELS = {
    "raw": "Raw image (.img)",
    "vhd": "Dynamic VHD (.vhd)",
    "vhdx": "Dynamic VHDX (.vhdx)",
}
_FORMAT_EXTENSIONS = {"raw": ".img", "vhd": ".vhd", "vhdx": ".vhdx"}
_FORMAT_CHOOSER_TITLES = {
    "raw": "Choose a new Raw image (.img) file",
    "vhd": "Choose a new Dynamic VHD (.vhd) file",
    "vhdx": "Choose a new Dynamic VHDX (.vhdx) file",
    "iso": "Choose a new Filesystem ISO/UDF (.iso) file",
}
_SOURCE_PHASES = {"capture", "hash_source", "convert"}


def _format_presentation_label(format_name):
    """Translate only the reviewed display label; canonical format IDs remain unchanged."""
    source = _FORMAT_LABELS.get(str(format_name or ""), "")
    return _(source) if source else source


def _format_chooser_title(format_name):
    """Return one exact translated Save-dialog title without formatting an operation value."""
    source = _FORMAT_CHOOSER_TITLES.get(str(format_name or ""), "")
    return _(source) if source else source


def _backup_detail_box(dialog):
    content_children = dialog.get_content_area().get_children()
    if not content_children:
        raise RuntimeError("Backup dialog content is unavailable.")
    outer = content_children[0]
    scroll = next((child for child in outer.get_children() if isinstance(child, Gtk.ScrolledWindow)), None)
    if scroll is None:
        raise RuntimeError("Backup dialog details area is unavailable.")
    child = scroll.get_child()
    if isinstance(child, Gtk.Viewport):
        child = child.get_child()
    if not isinstance(child, Gtk.Box):
        raise RuntimeError("Backup dialog details layout is unavailable.")
    return child


def _selected_format(dialog):
    value = str(dialog.format_selector.get_active_id() or "raw").strip().lower()
    return value if value in _FORMAT_LABELS else "raw"


def _phase_status(phase):
    return {
        "capture": "Reading the source and writing the temporary raw image. Do not disconnect the drive.",
        "hash_source": "Authenticating the complete held source before conversion.",
        "convert": "Creating the dynamic virtual-disk container from held descriptors.",
        "hash_output": "Hashing and synchronizing the completed container before publication.",
    }.get(phase, "Saving and verifying the drive image.")


def install_drive_backup_formats():
    """Patch only the backup dialog after its reviewed base implementation loads."""
    dialog_class = backup_dialog.DriveImageBackupDialog
    if getattr(dialog_class, "_backup_formats_installed", False):
        return

    original_init = dialog_class.__init__
    original_set_running = dialog_class.set_running

    def integrated_init(dialog, parent, device, identity, binary, pkexec):
        original_init(dialog, parent, device, identity, binary, pkexec)
        dialog.backup_format = "raw"
        dialog.last_progress_phase = ""

        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        row.pack_start(Gtk.Label(label=_("Image format")), False, False, 0)
        dialog.format_selector = Gtk.ComboBoxText()
        for format_name in _FORMAT_LABELS:
            dialog.format_selector.append(format_name, _format_presentation_label(format_name))
        dialog.format_selector.set_active_id("raw")
        dialog.format_selector.set_tooltip_text(
            _("Raw is byte-for-byte. VHD and VHDX are dynamic sparse containers verified against the held source.")
        )
        dialog.format_selector.connect("changed", dialog.format_changed)
        row.pack_start(dialog.format_selector, True, True, 0)
        details = _backup_detail_box(dialog)
        details.pack_start(row, False, False, 0)
        details.reorder_child(row, 1)
        row.show_all()

    def format_changed(dialog, *_):
        if dialog.running:
            return
        dialog.backup_format = _selected_format(dialog)
        extension = _FORMAT_EXTENSIONS[dialog.backup_format]
        dialog.plan_generation += 1
        dialog.plan = None
        dialog.output_path = ""
        dialog.destination.set_text("")
        dialog.destination.set_placeholder_text(f"Choose a new {extension} path")
        dialog.confirmation.set_text("")
        dialog.confirm_label.set_text("The exact confirmation phrase appears after planning.")
        dialog.plan_label.set_text("Choose a new destination path to calculate the read-only plan.")
        dialog.status.set_text(f"Choose a new {_FORMAT_LABELS[dialog.backup_format]} destination file.")
        dialog.confirmation_changed()

    def choose_destination(dialog, *_):
        if dialog.running:
            return
        format_name = _selected_format(dialog)
        extension = _FORMAT_EXTENSIONS[format_name]
        chooser = Gtk.FileChooserDialog(
            title=_format_chooser_title(format_name),
            transient_for=dialog,
            action=Gtk.FileChooserAction.SAVE,
        )
        chooser.add_buttons(_("Cancel"), Gtk.ResponseType.CANCEL, _("Choose"), Gtk.ResponseType.OK)
        chooser.set_do_overwrite_confirmation(True)
        chooser.set_current_name(f"rufusarm64-{os.path.basename(dialog.device)}{extension}")
        saved_directory = str(dialog.parent_window.settings.get("backup_directory") or "")
        if saved_directory and os.path.isdir(saved_directory):
            chooser.set_current_folder(saved_directory)
        image_filter = Gtk.FileFilter()
        image_filter.set_name(_format_presentation_label(format_name))
        image_filter.add_pattern(f"*{extension}")
        chooser.add_filter(image_filter)
        response = chooser.run()
        filename = chooser.get_filename() if response == Gtk.ResponseType.OK else ""
        chooser.destroy()
        if not filename:
            return
        filename = os.path.abspath(filename)
        if not filename.lower().endswith(extension):
            filename += extension
        if os.path.lexists(filename):
            dialog.plan = None
            dialog.output_path = ""
            dialog.destination.set_text("")
            dialog.plan_label.set_text("Destination refused: existing files and symbolic links are never replaced.")
            dialog.status.set_text("Choose a new destination path.")
            dialog.confirmation.set_text("")
            return
        dialog.backup_format = format_name
        dialog.output_path = filename
        dialog.destination.set_text(filename)
        dialog.parent_window.settings["backup_directory"] = os.path.dirname(filename)
        dialog.plan = None
        dialog.confirmation.set_text("")
        dialog.refresh_plan()

    def refresh_plan(dialog):
        if dialog.running or not dialog.output_path:
            return
        dialog.plan_generation += 1
        generation = dialog.plan_generation
        format_name = _selected_format(dialog)
        dialog.plan = None
        dialog.run_button.set_sensitive(False)
        dialog.status.set_text("Calculating a read-only source and destination plan…")
        dialog.plan_label.set_text("Checking source identity, container allocation bounds, collision, and disk separation…")
        try:
            command = backup_build_dry_run_command(
                dialog.binary,
                dialog.device,
                dialog.identity,
                dialog.output_path,
                format_name,
            )
        except ValueError as exc:
            dialog.status.set_text(str(exc))
            return
        threading.Thread(
            target=dialog._format_plan_worker,
            args=(command, generation, format_name, dialog.output_path),
            daemon=True,
        ).start()

    def format_plan_worker(dialog, command, generation, format_name, output_path):
        try:
            completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=30)
            if completed.returncode != 0:
                raise RuntimeError((completed.stderr or completed.stdout or "Backup planning failed.").strip())
            payload = backup_normalize_plan(json.loads(completed.stdout))
            if payload["device"]["path"] != dialog.device:
                raise ValueError("Backup plan no longer refers to the selected device.")
            if payload["identity"] != dialog.identity:
                raise ValueError("Backup plan no longer refers to the selected device identity.")
            if payload["destination"]["path"] != output_path:
                raise ValueError("Backup plan returned a different destination path.")
            if payload["destination"]["format"] != format_name:
                raise ValueError("Backup plan returned a different output format.")
            GLib.idle_add(dialog._plan_ready, generation, payload, "")
        except Exception as exc:
            GLib.idle_add(dialog._plan_ready, generation, None, str(exc))

    def set_running(dialog, running):
        original_set_running(dialog, running)
        dialog.format_selector.set_sensitive(not dialog.running)

    def start_run(dialog, *_):
        if dialog.running or not dialog.plan or not dialog.output_path:
            return
        try:
            expected = backup_confirmation_phrase(dialog.device, dialog.output_path)
            if dialog.confirmation.get_text().strip() != expected:
                raise ValueError("Type the exact SAVE phrase before authentication.")
            format_name = _selected_format(dialog)
            if dialog.plan["destination"]["format"] != format_name:
                raise ValueError("The selected image format changed after planning.")
            command = backup_build_run_command(
                dialog.pkexec,
                dialog.binary,
                dialog.device,
                dialog.identity,
                dialog.output_path,
                format_name,
            )
        except ValueError as exc:
            dialog.status.set_text(str(exc))
            return
        dialog.run_generation += 1
        generation = dialog.run_generation
        dialog.last_progress_done = 0
        dialog.last_progress_phase = ""
        dialog.progress.set_fraction(0.0)
        dialog.progress.set_text("Waiting for administrator authentication…")
        dialog.result.get_buffer().set_text("Backup in progress…")
        dialog.set_running(True)
        dialog.status.set_text("Authenticate to begin the read-only capture.")
        threading.Thread(target=dialog._format_run_worker, args=(command, generation), daemon=True).start()

    def format_run_worker(dialog, command, generation):
        diagnostics = []
        diagnostics_size = 0
        payload = None
        returncode = 1
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                start_new_session=True,
            )
            dialog.process = process
            source_bytes = int(dialog.plan["destination"]["source_bytes"])
            planned_format = str(dialog.plan["destination"]["format"])
            last_by_phase = {}
            for line in process.stderr:
                progress = backup_decode_progress_line(line)
                if progress is not None:
                    phase = progress["phase"]
                    if phase in _SOURCE_PHASES and progress["total"] != source_bytes:
                        raise ValueError("Backup progress violated the reviewed source capacity.")
                    if progress["done"] < last_by_phase.get(phase, 0):
                        raise ValueError("Backup progress moved backwards within a phase.")
                    last_by_phase[phase] = progress["done"]
                    GLib.idle_add(dialog._format_progress_ready, generation, progress)
                    continue
                text = line.strip()
                if text and len(diagnostics) < 64 and diagnostics_size + len(text) <= 32768:
                    diagnostics.append(text)
                    diagnostics_size += len(text)
            stdout = process.stdout.read()
            returncode = process.wait()
            dialog.process = None
            if stdout.strip():
                payload = backup_normalize_report(json.loads(stdout))
            if payload is None:
                raise RuntimeError("Drive-image backup did not return its final report.")
            if payload["planned_bytes"] != source_bytes or payload["format"] != planned_format:
                raise ValueError("Backup report does not match the reviewed plan.")
            if (returncode == 0) != (payload["status"] == "passed"):
                raise ValueError("Backup report status does not match the helper exit status.")
            if payload["status"] == "passed":
                info = os.lstat(dialog.output_path)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_size != payload["output_bytes"]
                    or info.st_uid != os.getuid()
                ):
                    raise ValueError("The completed destination file does not match the verified report or desktop user.")
            GLib.idle_add(dialog._run_ready, generation, payload, "\n".join(diagnostics), returncode)
        except Exception as exc:
            process = dialog.process
            dialog.process = None
            if process is not None:
                dialog._terminate_and_reap(process)
            detail = str(exc)
            if diagnostics:
                detail += "\n\nDiagnostics:\n" + "\n".join(diagnostics)
            GLib.idle_add(dialog._run_ready, generation, None, detail, returncode)

    def format_progress_ready(dialog, generation, progress):
        if dialog.closed or generation != dialog.run_generation or not dialog.running:
            return False
        phase = progress["phase"]
        done = progress["done"]
        if phase != dialog.last_progress_phase:
            dialog.last_progress_phase = phase
            dialog.last_progress_done = 0
        if done < dialog.last_progress_done:
            return False
        dialog.last_progress_done = done
        fraction = min(1.0, done / progress["total"])
        dialog.progress.set_fraction(fraction)
        dialog.progress.set_text(backup_progress_summary(progress))
        dialog.status.set_text(_phase_status(phase))
        return False

    dialog_class.__init__ = integrated_init
    dialog_class.format_changed = format_changed
    dialog_class.choose_destination = choose_destination
    dialog_class.refresh_plan = refresh_plan
    dialog_class._format_plan_worker = format_plan_worker
    dialog_class.set_running = set_running
    dialog_class.start_run = start_run
    dialog_class._format_run_worker = format_run_worker
    dialog_class._format_progress_ready = format_progress_ready
    dialog_class._backup_formats_installed = True
