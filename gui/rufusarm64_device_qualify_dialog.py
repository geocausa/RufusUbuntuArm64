"""Guarded GTK dialog for destructive USB qualification."""

import json
import os
import signal
import subprocess
import tempfile
import threading

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import GLib, Gtk

from rufusarm64_device_qualify import (
    build_qualification_command,
    normalize_qualification_event,
    qualification_progress_fraction,
    qualification_progress_text,
    qualification_result_summary,
)
from rufusarm64_logic import device_label, human_bytes


class DeviceQualificationDialog(Gtk.Dialog):
    """Run the package-owned qualification helper against one selected device."""

    def __init__(self, parent, pkexec_path, helper_path, device):
        super().__init__(
            title="Test USB drive",
            transient_for=parent,
            modal=True,
            destroy_with_parent=True,
        )
        self.parent_window = parent
        self.pkexec_path = pkexec_path
        self.helper_path = helper_path
        self.device = dict(device or {})
        self.device_path = str(self.device.get("path") or "")
        self.identity = str(self.device.get("identity") or "")
        self.process = None
        self.running = False
        self.cancel_requested = False
        self.closed = False
        self.generation = 0
        self.parent_busy = False
        self.set_default_size(660, 520)
        self.connect("delete-event", self._delete_event)
        self.connect("destroy", self._destroyed)

        box = self.get_content_area()
        box.set_spacing(12)
        box.set_border_width(18)

        title = Gtk.Label()
        title.set_markup("<span size='large' weight='bold'>Check for bad blocks and false capacity</span>")
        title.set_xalign(0)
        box.pack_start(title, False, False, 0)

        selected = Gtk.Label(label=device_label(self.device) if self.device_path else "No USB drive selected")
        selected.set_xalign(0)
        selected.set_line_wrap(True)
        selected.set_selectable(True)
        box.pack_start(selected, False, False, 0)

        warning = Gtk.Label(
            label=(
                "This is separate from Create USB and is destructive. Every region touched by the selected test is "
                "overwritten; existing files and partitions may become unusable. Choose the exact USB drive again "
                "from the main window after the test finishes."
            )
        )
        warning.set_xalign(0)
        warning.set_line_wrap(True)
        warning.get_style_context().add_class("warning")
        box.pack_start(warning, False, False, 0)

        profile_grid = Gtk.Grid(column_spacing=12, row_spacing=8)
        profile_label = Gtk.Label(label="Test profile")
        profile_label.set_xalign(0)
        self.profile = Gtk.ComboBoxText()
        self.profile.append("quick", "Quick — sampled regions, 2 patterns")
        self.profile.append("full", "Full — entire reported capacity, 4 patterns")
        self.profile.set_active_id("quick")
        self.profile.connect("changed", self._profile_changed)
        profile_grid.attach(profile_label, 0, 0, 1, 1)
        profile_grid.attach(self.profile, 1, 0, 1, 1)
        box.pack_start(profile_grid, False, False, 0)

        self.profile_note = Gtk.Label()
        self.profile_note.set_xalign(0)
        self.profile_note.set_line_wrap(True)
        self.profile_note.get_style_context().add_class("dim-label")
        box.pack_start(self.profile_note, False, False, 0)
        self._profile_changed()

        confirmation_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        confirmation_label = Gtk.Label(
            label=f"Type ERASE {self.device_path} to authorize this test:"
        )
        confirmation_label.set_xalign(0)
        confirmation_box.pack_start(confirmation_label, False, False, 0)
        self.confirmation = Gtk.Entry()
        self.confirmation.set_placeholder_text(f"ERASE {self.device_path}")
        self.confirmation.connect("changed", self._confirmation_changed)
        confirmation_box.pack_start(self.confirmation, False, False, 0)
        box.pack_start(confirmation_box, False, False, 0)

        self.progress = Gtk.ProgressBar()
        self.progress.set_show_text(False)
        box.pack_start(self.progress, False, False, 0)
        self.status = Gtk.Label(label="Ready. No device has been opened.")
        self.status.set_xalign(0)
        self.status.set_line_wrap(True)
        self.status.set_selectable(True)
        box.pack_start(self.status, False, False, 0)

        result_scroll = Gtk.ScrolledWindow()
        result_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        result_scroll.set_min_content_height(120)
        self.result = Gtk.TextView()
        self.result.set_editable(False)
        self.result.set_cursor_visible(False)
        self.result.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.result.get_buffer().set_text(
            "The result will state whether all tested addresses reproduced their data and whether aliasing was detected."
        )
        result_scroll.add(self.result)
        box.pack_start(result_scroll, True, True, 0)

        action = self.get_action_area()
        self.close_button = Gtk.Button(label="Close")
        self.close_button.connect("clicked", self._close_clicked)
        action.pack_end(self.close_button, False, False, 0)
        self.cancel_button = Gtk.Button(label="Cancel test")
        self.cancel_button.set_sensitive(False)
        self.cancel_button.connect("clicked", self._cancel_clicked)
        action.pack_end(self.cancel_button, False, False, 0)
        self.start_button = Gtk.Button(label="Start test")
        self.start_button.get_style_context().add_class("destructive-action")
        self.start_button.set_sensitive(False)
        self.start_button.connect("clicked", self._start_clicked)
        action.pack_end(self.start_button, False, False, 0)
        self.show_all()

    def _profile_changed(self, *_):
        if self.profile.get_active_id() == "full":
            self.profile_note.set_text(
                "Full test: writes and verifies four address-derived patterns across the complete capacity reported by "
                "the device. It can take many hours and overwrites the whole drive repeatedly."
            )
        else:
            self.profile_note.set_text(
                "Quick test: samples up to 32 evenly spaced regions with two address-derived patterns. It is faster, "
                "but it cannot provide the same coverage as the full-capacity test."
            )

    def _confirmation_changed(self, *_):
        expected = f"ERASE {self.device_path}"
        ready = (
            not self.running
            and bool(self.identity)
            and self.confirmation.get_text().strip() == expected
        )
        self.start_button.set_sensitive(ready)

    def _set_running(self, running):
        self.running = bool(running)
        if running and not self.parent_busy:
            self.parent_window.active_job = "qualification"
            self.parent_window.set_busy(True)
            self.parent_busy = True
        elif not running and self.parent_busy:
            self.parent_window.active_job = ""
            self.parent_window.set_busy(False)
            self.parent_busy = False
        self.profile.set_sensitive(not running)
        self.confirmation.set_sensitive(not running)
        ready = bool(self.identity) and self.confirmation.get_text().strip() == f"ERASE {self.device_path}"
        self.start_button.set_sensitive(not running and ready)
        self.cancel_button.set_sensitive(running and not self.cancel_requested)
        self.close_button.set_sensitive(not running)

    def _start_clicked(self, *_):
        if self.running:
            return
        try:
            command = build_qualification_command(
                self.pkexec_path,
                self.helper_path,
                self.device_path,
                self.identity,
                self.profile.get_active_id() or "quick",
            )
        except ValueError as exc:
            self.status.set_text(str(exc))
            return
        if self.confirmation.get_text().strip() != f"ERASE {self.device_path}":
            self.status.set_text("The exact erase confirmation does not match the selected drive.")
            return

        self.generation += 1
        generation = self.generation
        self.cancel_requested = False
        self.progress.set_fraction(0.0)
        self.status.set_text("Waiting for administrator authentication…")
        self.result.get_buffer().set_text("USB qualification is starting…")
        self._set_running(True)
        threading.Thread(target=self._run_process, args=(command, generation), daemon=True).start()

    def _run_process(self, command, generation):
        process = None
        report = None
        failure = ""
        try:
            with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as error_file:
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=error_file,
                    text=True,
                    bufsize=1,
                    start_new_session=True,
                )
                self.process = process
                if self.cancel_requested:
                    self._terminate_process(process)
                for raw_line in process.stdout:
                    line = raw_line.strip()
                    if not line:
                        continue
                    event = normalize_qualification_event(json.loads(line))
                    if event["event"] == "progress":
                        GLib.idle_add(self._apply_progress, generation, event)
                    else:
                        report = event["report"]
                return_code = process.wait()
                error_file.seek(0)
                stderr = error_file.read().strip()
                if report is None:
                    failure = stderr or f"USB qualification exited with status {return_code} without a result report."
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            failure = str(exc)
        finally:
            if self.process is process:
                self.process = None
        GLib.idle_add(self._finish_process, generation, report, failure)

    def _apply_progress(self, generation, event):
        if self.closed or generation != self.generation:
            return False
        fraction = qualification_progress_fraction(event["done"], event["total"])
        self.progress.set_fraction(fraction)
        self.status.set_text(
            qualification_progress_text(
                event["stage"],
                event["pass"],
                event["pattern"],
                event["done"],
                event["total"],
                human_bytes,
            )
        )
        return False

    def _finish_process(self, generation, report, failure):
        if self.closed or generation != self.generation:
            return False
        self._set_running(False)
        self.cancel_requested = False
        if failure:
            self.progress.set_fraction(0.0)
            self.status.set_text("USB qualification could not be completed.")
            self.result.get_buffer().set_text(failure)
            self._append_log(f"USB qualification failed to run: {failure}")
            return False

        summary = qualification_result_summary(report, human_bytes)
        self.result.get_buffer().set_text(summary)
        status = report["status"]
        self.progress.set_fraction(1.0 if status == "passed" else qualification_progress_fraction(report["completed_bytes"], report["planned_bytes"]))
        self.status.set_text(
            "USB qualification passed."
            if status == "passed"
            else "USB qualification was cancelled."
            if status == "cancelled"
            else "USB qualification found a problem."
        )
        self._append_log("USB qualification report:\n" + json.dumps(report, indent=2, sort_keys=True))
        return False

    def _append_log(self, text):
        append = getattr(self.parent_window, "append_log", None)
        if callable(append):
            append(text)

    def _cancel_clicked(self, *_):
        if not self.running:
            return
        self.cancel_requested = True
        self.cancel_button.set_sensitive(False)
        self.status.set_text("Cancelling safely after the current I/O operation…")
        process = self.process
        if process is not None:
            self._terminate_process(process)

    @staticmethod
    def _terminate_process(process):
        if process.poll() is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            pass

    def _close_clicked(self, *_):
        if not self.running:
            self.destroy()

    def _delete_event(self, *_):
        if self.running:
            self._cancel_clicked()
            return True
        return False

    def _destroyed(self, *_):
        self.closed = True
        self.generation += 1
        process = self.process
        if process is not None:
            self._terminate_process(process)
        if self.parent_busy:
            self.parent_window.active_job = ""
            self.parent_window.set_busy(False)
            self.parent_busy = False
