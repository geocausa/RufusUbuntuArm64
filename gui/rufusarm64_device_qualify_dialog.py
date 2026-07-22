"""GTK dialogs for explicit USB qualification and verified drive-image backup."""

import json
import os
import signal
import stat
import subprocess
import sys
import threading

from gi.repository import GLib, Gtk

from rufusarm64_device_qualify import (
    backup_build_dry_run_command,
    backup_build_run_command,
    backup_confirmation_phrase,
    backup_decode_progress_line,
    backup_normalize_plan,
    backup_normalize_report,
    backup_plan_summary,
    backup_progress_summary,
    backup_report_summary,
    build_dry_run_command,
    build_run_command,
    normalize_plan,
    normalize_report,
    plan_summary,
    report_summary,
)

DEVICE_BACKUP = "/usr/bin/rufusarm64-device-backup"


class DeviceQualificationDialog(Gtk.Dialog):
    def __init__(self, parent, device, identity, binary, pkexec):
        super().__init__(title="Check USB drive", transient_for=parent, modal=True)
        self.device = device
        self.identity = identity
        self.binary = binary
        self.pkexec = pkexec
        self.running = False
        self.process = None
        self.plan = None
        self.set_default_size(700, 560)
        self.set_resizable(True)
        self.add_button("Close", Gtk.ResponseType.CLOSE)
        self.close_button = self.get_widget_for_response(Gtk.ResponseType.CLOSE)
        self.connect("delete-event", self.on_delete_event)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_border_width(18)
        self.get_content_area().pack_start(box, True, True, 0)

        detail_scroll = Gtk.ScrolledWindow()
        detail_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        detail_scroll.set_hexpand(True)
        detail_scroll.set_vexpand(True)
        detail_scroll.set_min_content_height(120)
        detail_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        detail_scroll.add(detail_box)
        box.pack_start(detail_scroll, True, True, 0)

        intro = Gtk.Label(
            label=(
                "This is a separate destructive USB qualification test. It overwrites every tested region and does not "
                "preserve files or partitions. The normal Create USB workflow is not changed."
            )
        )
        intro.set_xalign(0)
        intro.set_line_wrap(True)
        detail_box.pack_start(intro, False, False, 0)

        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        row.pack_start(Gtk.Label(label="Test profile"), False, False, 0)
        self.profile = Gtk.ComboBoxText()
        self.profile.append("quick", "Quick capacity and alias check")
        self.profile.append("full", "Full-device multi-region verification")
        self.profile.set_active_id("quick")
        self.profile.connect("changed", self.plan_changed)
        row.pack_start(self.profile, True, True, 0)
        detail_box.pack_start(row, False, False, 0)

        self.plan_label = Gtk.Label(label="Calculating a read-only plan…")
        self.plan_label.set_xalign(0)
        self.plan_label.set_line_wrap(True)
        self.plan_label.set_selectable(True)
        detail_box.pack_start(self.plan_label, False, False, 0)

        warning = Gtk.InfoBar()
        warning.set_message_type(Gtk.MessageType.WARNING)
        warning_label = Gtk.Label(
            label=(
                "Running the test will erase data in every selected test region. A full test is intended for an empty USB drive."
            )
        )
        warning_label.set_xalign(0)
        warning_label.set_line_wrap(True)
        warning.get_content_area().add(warning_label)
        detail_box.pack_start(warning, False, False, 0)

        confirm_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        confirm_row.pack_start(Gtk.Label(label=f"Type ERASE {device} to enable the test"), False, False, 0)
        self.confirmation = Gtk.Entry()
        self.confirmation.connect("changed", self.confirmation_changed)
        confirm_row.pack_start(self.confirmation, True, True, 0)
        box.pack_start(confirm_row, False, False, 0)

        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.run_button = Gtk.Button(label="Run USB check")
        self.run_button.get_style_context().add_class("destructive-action")
        self.run_button.set_sensitive(False)
        self.run_button.connect("clicked", self.start_run)
        actions.pack_start(self.run_button, False, False, 0)
        self.cancel_button = Gtk.Button(label="Cancel test")
        self.cancel_button.set_sensitive(False)
        self.cancel_button.connect("clicked", self.cancel_run)
        actions.pack_start(self.cancel_button, False, False, 0)
        self.spinner = Gtk.Spinner()
        actions.pack_start(self.spinner, False, False, 0)
        self.status = Gtk.Label(label="Preparing…")
        self.status.set_xalign(0)
        self.status.set_line_wrap(True)
        actions.pack_start(self.status, True, True, 0)
        box.pack_start(actions, False, False, 0)

        result_scroll = Gtk.ScrolledWindow()
        result_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        result_scroll.set_min_content_height(140)
        result_scroll.set_max_content_height(220)
        result_scroll.set_propagate_natural_height(True)
        self.result = Gtk.TextView(editable=False, cursor_visible=False, monospace=True, wrap_mode=Gtk.WrapMode.WORD_CHAR)
        self.result.get_buffer().set_text("No qualification report is available yet.")
        result_scroll.add(self.result)
        box.pack_start(result_scroll, False, False, 0)

        self.show_all()
        self.refresh_plan()

    def on_delete_event(self, *_):
        if self.running:
            self.status.set_text("The USB check is still running. Cancel it before closing this dialog.")
            return True
        return False

    def plan_changed(self, *_):
        if not self.running:
            self.plan = None
            self.confirmation.set_text("")
            self.refresh_plan()

    def confirmation_changed(self, *_):
        expected = f"ERASE {self.device}"
        self.run_button.set_sensitive(bool(self.plan) and not self.running and self.confirmation.get_text().strip() == expected)

    def set_running(self, running):
        self.running = bool(running)
        self.profile.set_sensitive(not self.running)
        self.confirmation.set_sensitive(not self.running)
        self.run_button.set_sensitive(False if self.running else bool(self.plan) and self.confirmation.get_text().strip() == f"ERASE {self.device}")
        self.cancel_button.set_sensitive(self.running)
        self.close_button.set_sensitive(not self.running)
        if self.running:
            self.spinner.start()
        else:
            self.spinner.stop()

    def refresh_plan(self):
        self.status.set_text("Calculating a read-only plan…")
        profile = self.profile.get_active_id() or "quick"
        try:
            command = build_dry_run_command(self.binary, self.device, self.identity, profile)
        except ValueError as exc:
            self.status.set_text(str(exc))
            return
        threading.Thread(target=self._plan_worker, args=(command,), daemon=True).start()

    def _plan_worker(self, command):
        try:
            completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=30)
            if completed.returncode != 0:
                raise RuntimeError((completed.stderr or completed.stdout or "Plan failed").strip())
            payload = normalize_plan(json.loads(completed.stdout))
            GLib.idle_add(self._plan_ready, payload, "")
        except Exception as exc:
            GLib.idle_add(self._plan_ready, None, str(exc))

    def _plan_ready(self, payload, error):
        if error:
            self.plan = None
            self.plan_label.set_text("Qualification plan unavailable.")
            self.status.set_text(error)
        else:
            self.plan = payload
            self.plan_label.set_text(plan_summary(payload))
            self.status.set_text("Review the plan, type the exact erase phrase, then run the check.")
        self.confirmation_changed()
        return False

    def start_run(self, *_):
        if self.running or not self.plan:
            return
        try:
            command = build_run_command(
                self.pkexec,
                self.binary,
                self.device,
                self.identity,
                self.profile.get_active_id() or "quick",
            )
        except ValueError as exc:
            self.status.set_text(str(exc))
            return
        self.set_running(True)
        self.status.set_text("Waiting for administrator authentication…")
        threading.Thread(target=self._run_worker, args=(command,), daemon=True).start()

    def _run_worker(self, command):
        try:
            self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = self.process.communicate()
            returncode = self.process.returncode
            self.process = None
            payload = None
            if stdout.strip():
                payload = normalize_report(json.loads(stdout))
            if payload is None:
                raise RuntimeError((stderr or "Qualification did not return a report.").strip())
            GLib.idle_add(self._run_ready, payload, stderr.strip(), returncode)
        except Exception as exc:
            self.process = None
            GLib.idle_add(self._run_ready, None, str(exc), 1)

    def _run_ready(self, payload, error, returncode):
        self.set_running(False)
        self.confirmation.set_text("")
        if payload is None:
            self.status.set_text("USB qualification could not complete.")
            self.result.get_buffer().set_text(error)
            return False
        summary = report_summary(payload)
        self.status.set_text(summary)
        rendered = json.dumps(payload, indent=2, sort_keys=True)
        if error:
            rendered += "\n\nDiagnostics:\n" + error
        self.result.get_buffer().set_text(rendered)
        if returncode != 0 and payload.get("status") == "passed":
            self.status.set_text("The report says passed, but the helper returned an error status. Treat this result as failed.")
        return False

    def cancel_run(self, *_):
        process = self.process
        if not process or process.poll() is not None:
            return
        self.status.set_text("Cancelling after the current I/O operation…")
        try:
            process.terminate()
        except OSError as exc:
            self.status.set_text(f"Could not request cancellation: {exc}")


class DriveImageBackupDialog(Gtk.Dialog):
    """Save a verified image of the selected removable drive without writing to it."""

    def __init__(self, parent, device, identity, binary, pkexec):
        super().__init__(title="Save drive image", transient_for=parent, modal=True)
        self.parent_window = parent
        self.device = device
        self.identity = identity
        self.binary = binary
        self.pkexec = pkexec
        self.output_path = ""
        self.plan = None
        self.process = None
        self.running = False
        self.closed = False
        self.completed = False
        self.plan_generation = 0
        self.run_generation = 0
        self.last_progress_done = 0
        self.set_default_size(760, 560)
        self.set_resizable(True)
        self.add_button("Close", Gtk.ResponseType.CLOSE)
        self.close_button = self.get_widget_for_response(Gtk.ResponseType.CLOSE)
        self.connect("delete-event", self.on_delete_event)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_border_width(18)
        self.get_content_area().pack_start(box, True, True, 0)

        detail_scroll = Gtk.ScrolledWindow()
        detail_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        detail_scroll.set_hexpand(True)
        detail_scroll.set_vexpand(True)
        detail_scroll.set_min_content_height(120)
        detail_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        detail_scroll.add(detail_box)
        box.pack_start(detail_scroll, True, True, 0)

        intro = Gtk.Label(
            label=(
                "Save a byte-for-byte image of the selected removable drive. The source is opened read-only, but its mounted "
                "filesystems may be unmounted briefly to obtain a coherent image. Create USB and Check USB are separate workflows."
            )
        )
        intro.set_xalign(0)
        intro.set_line_wrap(True)
        detail_box.pack_start(intro, False, False, 0)

        destination_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        destination_row.pack_start(Gtk.Label(label="New image file"), False, False, 0)
        self.destination = Gtk.Entry(editable=False)
        self.destination.set_hexpand(True)
        self.destination.set_placeholder_text("Choose a new .img path")
        destination_row.pack_start(self.destination, True, True, 0)
        self.choose_button = Gtk.Button(label="Choose…")
        self.choose_button.connect("clicked", self.choose_destination)
        destination_row.pack_start(self.choose_button, False, False, 0)
        detail_box.pack_start(destination_row, False, False, 0)

        self.plan_label = Gtk.Label(label="Choose a new destination path to calculate the read-only plan.")
        self.plan_label.set_xalign(0)
        self.plan_label.set_line_wrap(True)
        self.plan_label.set_selectable(True)
        detail_box.pack_start(self.plan_label, False, False, 0)

        note = Gtk.InfoBar()
        note.set_message_type(Gtk.MessageType.INFO)
        note_label = Gtk.Label(
            label=(
                "The final image path is created only after every planned byte has been copied, synchronized, SHA-256 hashed, "
                "and revalidated. Existing files and symbolic links are never replaced."
            )
        )
        note_label.set_xalign(0)
        note_label.set_line_wrap(True)
        note.get_content_area().add(note_label)
        detail_box.pack_start(note, False, False, 0)

        self.confirm_label = Gtk.Label(label="The exact confirmation phrase appears after planning.")
        self.confirm_label.set_xalign(0)
        self.confirm_label.set_line_wrap(True)
        self.confirm_label.set_selectable(True)
        box.pack_start(self.confirm_label, False, False, 0)
        self.confirmation = Gtk.Entry()
        self.confirmation.set_placeholder_text("Type the exact SAVE phrase")
        self.confirmation.connect("changed", self.confirmation_changed)
        box.pack_start(self.confirmation, False, False, 0)

        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.run_button = Gtk.Button(label="Save drive image")
        self.run_button.get_style_context().add_class("suggested-action")
        self.run_button.set_sensitive(False)
        self.run_button.connect("clicked", self.start_run)
        actions.pack_start(self.run_button, False, False, 0)
        self.cancel_button = Gtk.Button(label="Cancel backup")
        self.cancel_button.set_sensitive(False)
        self.cancel_button.connect("clicked", self.cancel_run)
        actions.pack_start(self.cancel_button, False, False, 0)
        self.status = Gtk.Label(label="Choose a destination file.")
        self.status.set_xalign(0)
        self.status.set_line_wrap(True)
        actions.pack_start(self.status, True, True, 0)
        box.pack_start(actions, False, False, 0)

        self.progress = Gtk.ProgressBar(show_text=True)
        self.progress.set_text("Not started")
        box.pack_start(self.progress, False, False, 0)

        result_scroll = Gtk.ScrolledWindow()
        result_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        result_scroll.set_min_content_height(140)
        result_scroll.set_max_content_height(220)
        result_scroll.set_propagate_natural_height(True)
        self.result = Gtk.TextView(editable=False, cursor_visible=False, monospace=True, wrap_mode=Gtk.WrapMode.WORD_CHAR)
        self.result.get_buffer().set_text("No backup report is available yet.")
        result_scroll.add(self.result)
        box.pack_start(result_scroll, False, False, 0)
        self.show_all()

    def choose_destination(self, *_):
        if self.running:
            return
        dialog = Gtk.FileChooserDialog(
            title="Choose a new drive-image file",
            transient_for=self,
            action=Gtk.FileChooserAction.SAVE,
        )
        dialog.add_buttons("Cancel", Gtk.ResponseType.CANCEL, "Choose", Gtk.ResponseType.OK)
        dialog.set_do_overwrite_confirmation(True)
        dialog.set_current_name(f"rufusarm64-{os.path.basename(self.device)}.img")
        saved_directory = str(self.parent_window.settings.get("backup_directory") or "")
        if saved_directory and os.path.isdir(saved_directory):
            dialog.set_current_folder(saved_directory)
        image_filter = Gtk.FileFilter()
        image_filter.set_name("Raw drive images")
        image_filter.add_pattern("*.img")
        dialog.add_filter(image_filter)
        response = dialog.run()
        filename = dialog.get_filename() if response == Gtk.ResponseType.OK else ""
        dialog.destroy()
        if not filename:
            return
        filename = os.path.abspath(filename)
        if os.path.lexists(filename):
            self.plan = None
            self.output_path = ""
            self.destination.set_text("")
            self.plan_label.set_text("Destination refused: existing files and symbolic links are never replaced.")
            self.status.set_text("Choose a new destination path.")
            self.confirmation.set_text("")
            return
        self.output_path = filename
        self.destination.set_text(filename)
        self.parent_window.settings["backup_directory"] = os.path.dirname(filename)
        self.plan = None
        self.confirmation.set_text("")
        self.refresh_plan()

    def refresh_plan(self):
        if self.running or not self.output_path:
            return
        self.plan_generation += 1
        generation = self.plan_generation
        self.plan = None
        self.run_button.set_sensitive(False)
        self.status.set_text("Calculating a read-only source and destination plan…")
        self.plan_label.set_text("Checking source identity, capacity, destination space, collision, and disk separation…")
        try:
            command = backup_build_dry_run_command(self.binary, self.device, self.identity, self.output_path)
        except ValueError as exc:
            self.status.set_text(str(exc))
            return
        threading.Thread(target=self._plan_worker, args=(command, generation), daemon=True).start()

    def _plan_worker(self, command, generation):
        try:
            completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=30)
            if completed.returncode != 0:
                raise RuntimeError((completed.stderr or completed.stdout or "Backup planning failed.").strip())
            payload = backup_normalize_plan(json.loads(completed.stdout))
            if payload["device"]["path"] != self.device:
                raise ValueError("Backup plan no longer refers to the selected device.")
            if payload["identity"] != self.identity:
                raise ValueError("Backup plan no longer refers to the selected device identity.")
            if payload["destination"]["path"] != self.output_path:
                raise ValueError("Backup plan returned a different destination path.")
            GLib.idle_add(self._plan_ready, generation, payload, "")
        except Exception as exc:
            GLib.idle_add(self._plan_ready, generation, None, str(exc))

    def _plan_ready(self, generation, payload, error):
        if self.closed or generation != self.plan_generation or self.running:
            return False
        if error:
            self.plan = None
            self.plan_label.set_text("Backup plan unavailable.")
            self.status.set_text(error)
            self.confirm_label.set_text("The exact confirmation phrase appears after planning.")
        else:
            self.plan = payload
            self.plan_label.set_text(backup_plan_summary(payload))
            phrase = backup_confirmation_phrase(self.device, self.output_path)
            self.confirm_label.set_text(f"Type exactly: {phrase}")
            self.status.set_text("Review the plan, type the exact SAVE phrase, then authenticate.")
        self.confirmation_changed()
        return False

    def confirmation_changed(self, *_):
        enabled = False
        if self.plan and self.output_path and not self.running:
            try:
                expected = backup_confirmation_phrase(self.device, self.output_path)
                enabled = self.confirmation.get_text().strip() == expected and not os.path.lexists(self.output_path)
            except ValueError:
                enabled = False
        self.run_button.set_sensitive(enabled)

    def set_running(self, running):
        self.running = bool(running)
        self.choose_button.set_sensitive(not self.running)
        self.confirmation.set_sensitive(not self.running)
        self.run_button.set_sensitive(False)
        self.cancel_button.set_sensitive(self.running)
        self.close_button.set_sensitive(not self.running)
        if self.running:
            self.parent_window.active_job = "backup"
            self.parent_window.set_busy(True)
        else:
            if self.parent_window.active_job == "backup":
                self.parent_window.active_job = ""
            self.parent_window.set_busy(False)
            self.confirmation_changed()

    def start_run(self, *_):
        if self.running or not self.plan or not self.output_path:
            return
        try:
            expected = backup_confirmation_phrase(self.device, self.output_path)
            if self.confirmation.get_text().strip() != expected:
                raise ValueError("Type the exact SAVE phrase before authentication.")
            command = backup_build_run_command(self.pkexec, self.binary, self.device, self.identity, self.output_path)
        except ValueError as exc:
            self.status.set_text(str(exc))
            return
        self.run_generation += 1
        generation = self.run_generation
        self.last_progress_done = 0
        self.progress.set_fraction(0.0)
        self.progress.set_text("Waiting for administrator authentication…")
        self.result.get_buffer().set_text("Backup in progress…")
        self.set_running(True)
        self.status.set_text("Authenticate to begin the read-only capture.")
        threading.Thread(target=self._run_worker, args=(command, generation), daemon=True).start()

    def _run_worker(self, command, generation):
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
            self.process = process
            planned = int(self.plan["destination"]["required_bytes"])
            last_done = 0
            for line in process.stderr:
                progress = backup_decode_progress_line(line)
                if progress is not None:
                    if progress["total"] != planned or progress["done"] < last_done:
                        raise ValueError("Backup progress violated the planned byte accounting.")
                    last_done = progress["done"]
                    GLib.idle_add(self._progress_ready, generation, progress)
                    continue
                text = line.strip()
                if text and len(diagnostics) < 64 and diagnostics_size + len(text) <= 32768:
                    diagnostics.append(text)
                    diagnostics_size += len(text)
            stdout = process.stdout.read()
            returncode = process.wait()
            self.process = None
            if stdout.strip():
                payload = backup_normalize_report(json.loads(stdout))
            if payload is None:
                raise RuntimeError("Drive-image backup did not return its final report.")
            if payload["planned_bytes"] != planned:
                raise ValueError("Backup report does not match the reviewed plan.")
            if (returncode == 0) != (payload["status"] == "passed"):
                raise ValueError("Backup report status does not match the helper exit status.")
            if payload["status"] == "passed":
                info = os.lstat(self.output_path)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_size != payload["completed_bytes"]
                    or info.st_uid != os.getuid()
                ):
                    raise ValueError("The completed destination file does not match the verified report or desktop user.")
            GLib.idle_add(self._run_ready, generation, payload, "\n".join(diagnostics), returncode)
        except Exception as exc:
            process = self.process
            self.process = None
            if process is not None:
                self._terminate_and_reap(process)
            detail = str(exc)
            if diagnostics:
                detail += "\n\nDiagnostics:\n" + "\n".join(diagnostics)
            GLib.idle_add(self._run_ready, generation, None, detail, returncode)

    @staticmethod
    def _terminate_and_reap(process):
        """Stop and reap only the process group created for this backup."""
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                pass

    def _progress_ready(self, generation, progress):
        if self.closed or generation != self.run_generation or not self.running:
            return False
        done = progress["done"]
        if done < self.last_progress_done:
            return False
        self.last_progress_done = done
        fraction = min(1.0, done / progress["total"])
        self.progress.set_fraction(fraction)
        self.progress.set_text(backup_progress_summary(progress))
        self.status.set_text("Reading the source and writing the temporary image. Do not disconnect the drive.")
        return False

    def _run_ready(self, generation, payload, diagnostics, returncode):
        if self.closed or generation != self.run_generation:
            return False
        self.process = None
        self.set_running(False)
        self.confirmation.set_text("")
        self.completed = True
        if payload is None:
            self.progress.set_text("Backup could not complete")
            self.status.set_text("Drive-image backup could not complete. No verified final image should be used.")
            self.result.get_buffer().set_text(diagnostics)
            self.parent_window.append_log("Drive-image backup failed to run:\n" + diagnostics)
        else:
            summary = backup_report_summary(payload, self.output_path)
            self.status.set_text(summary)
            rendered = json.dumps(payload, indent=2, sort_keys=True)
            if diagnostics:
                rendered += "\n\nDiagnostics:\n" + diagnostics
            self.result.get_buffer().set_text(rendered)
            self.parent_window.append_log("Drive-image backup result:\n" + rendered)
            if payload["status"] == "passed" and returncode == 0:
                self.progress.set_fraction(1.0)
                self.progress.set_text("Verified image complete")
                self.plan = None
                self.choose_button.set_sensitive(False)
            elif payload["status"] == "cancelled":
                self.progress.set_text("Cancelled safely")
                self.plan = None
            else:
                self.progress.set_text("Backup failed")
                self.plan = None
        self.parent_window.refresh_devices()
        return False

    def cancel_run(self, *_):
        process = self.process
        if not process or process.poll() is not None:
            return
        self.cancel_button.set_sensitive(False)
        self.status.set_text("Cancelling after the current read operation; incomplete temporary output will be removed…")
        self.progress.set_text("Cancelling safely…")
        try:
            os.killpg(process.pid, signal.SIGTERM)
            GLib.timeout_add_seconds(5, self._force_kill, process)
        except (ProcessLookupError, PermissionError) as exc:
            self.status.set_text(f"Could not request cancellation: {exc}")

    def _force_kill(self, process):
        if self.process is process and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
        return False

    def on_delete_event(self, *_):
        if self.running:
            self.cancel_run()
            self.status.set_text("Closing requested. Cancelling the backup before the dialog can close…")
            return True
        self.closed = True
        self.plan_generation += 1
        self.run_generation += 1
        return False


def _walk_widgets(widget):
    yield widget
    if isinstance(widget, Gtk.Container):
        for child in widget.get_children():
            yield from _walk_widgets(child)


def _find_target_action_box(window):
    for widget in _walk_widgets(window):
        if isinstance(widget, Gtk.Box):
            children = widget.get_children()
            if window.refresh_button in children and window.qualify_button in children:
                return widget
    raise RuntimeError("Could not locate the USB target action row.")


def _update_backup_sensitivity(window):
    button = getattr(window, "backup_button", None)
    if button is None:
        return
    index = window.target_combo.get_active()
    selected = window.devices[index] if 0 <= index < len(window.devices) else None
    ready = bool((selected or {}).get("path") and (selected or {}).get("identity"))
    button.set_sensitive(not window.busy and not window.device_refreshing and ready)


def install_drive_backup(window_class):
    """Install the backup action before the first RufusWindow instance is created."""
    if getattr(window_class, "_drive_backup_installed", False):
        return
    original_init = window_class.__init__
    original_set_busy = window_class.set_busy

    def integrated_init(window, app):
        original_init(window, app)
        actions = _find_target_action_box(window)
        window.backup_button = Gtk.Button(label="Save drive image…")
        window.backup_button.set_tooltip_text("Save a verified byte-for-byte image of the selected removable drive")
        window.backup_button.connect("clicked", window.open_drive_backup)
        actions.pack_start(window.backup_button, False, False, 0)
        window.target_combo.connect("changed", lambda *_: _update_backup_sensitivity(window))
        _update_backup_sensitivity(window)

    def integrated_set_busy(window, busy):
        original_set_busy(window, busy)
        _update_backup_sensitivity(window)

    def open_drive_backup(window, *_):
        if window.busy:
            return
        index = window.target_combo.get_active()
        selected = window.devices[index] if 0 <= index < len(window.devices) else None
        device = str((selected or {}).get("path") or "")
        identity = str((selected or {}).get("identity") or "")
        if not device or not identity:
            window.progress_detail.set_text("Choose a removable drive and refresh the device list before saving an image.")
            return
        dialog = DriveImageBackupDialog(window, device, identity, DEVICE_BACKUP, "/usr/bin/pkexec")
        dialog.run()
        dialog.closed = True
        dialog.plan_generation += 1
        dialog.run_generation += 1
        dialog.destroy()
        window.save_settings()

    window_class.__init__ = integrated_init
    window_class.set_busy = integrated_set_busy
    window_class.open_drive_backup = open_drive_backup
    window_class._drive_backup_installed = True


def run_rufusarm64(argv=None):
    """Run the packaged application with the backup integration installed."""
    from rufusarm64 import RufusApp, RufusWindow

    install_drive_backup(RufusWindow)
    return RufusApp().run(list(sys.argv[1:] if argv is None else argv))
