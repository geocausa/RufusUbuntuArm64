"""GTK dialog for explicit destructive USB qualification."""

import json
import os
import subprocess
import threading

from gi.repository import GLib, Gtk

from rufusarm64_device_qualify import (
    build_dry_run_command,
    build_run_command,
    normalize_plan,
    normalize_report,
    plan_summary,
    report_summary,
)


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
        self.set_default_size(700, 520)
        self.add_button("Close", Gtk.ResponseType.CLOSE)
        self.close_button = self.get_widget_for_response(Gtk.ResponseType.CLOSE)
        self.connect("delete-event", self.on_delete_event)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_border_width(18)
        self.get_content_area().pack_start(box, True, True, 0)

        intro = Gtk.Label(
            label=(
                "This is a separate destructive USB qualification test. It overwrites every tested region and does not "
                "preserve files or partitions. The normal Create USB workflow is not changed."
            )
        )
        intro.set_xalign(0)
        intro.set_line_wrap(True)
        box.pack_start(intro, False, False, 0)

        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        row.pack_start(Gtk.Label(label="Test profile"), False, False, 0)
        self.profile = Gtk.ComboBoxText()
        self.profile.append("quick", "Quick capacity and alias check")
        self.profile.append("full", "Full-device multi-region verification")
        self.profile.set_active_id("quick")
        self.profile.connect("changed", self.plan_changed)
        row.pack_start(self.profile, True, True, 0)
        box.pack_start(row, False, False, 0)

        self.plan_label = Gtk.Label(label="Calculating a read-only plan…")
        self.plan_label.set_xalign(0)
        self.plan_label.set_line_wrap(True)
        self.plan_label.set_selectable(True)
        box.pack_start(self.plan_label, False, False, 0)

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
        box.pack_start(warning, False, False, 0)

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
        result_scroll.set_vexpand(True)
        self.result = Gtk.TextView(editable=False, cursor_visible=False, monospace=True, wrap_mode=Gtk.WrapMode.WORD_CHAR)
        self.result.get_buffer().set_text("No qualification report is available yet.")
        result_scroll.add(self.result)
        box.pack_start(result_scroll, True, True, 0)

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
