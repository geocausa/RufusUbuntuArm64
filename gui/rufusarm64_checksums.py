#!/usr/bin/env python3
"""Unprivileged GTK dialog for descriptor-bound selected-image checksums."""

import json
import subprocess
import threading

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import GLib, Gtk

from rufusarm64_logic import build_checksum_command, checksum_summary, normalize_checksum_result


class ChecksumDialog(Gtk.Dialog):
    """Calculate all Rufus-compatible checksums without entering a write path."""

    def __init__(self, parent, helper, image_path):
        super().__init__(title="Image checksums", transient_for=parent, modal=True)
        self.parent_window = parent
        self.helper = helper
        self.image_path = image_path
        self.running = False
        self.closed = False
        self.generation = 0
        self.report = ""
        self.set_default_size(760, 520)
        self.add_button("Close", Gtk.ResponseType.CLOSE)
        self.close_button = self.get_widget_for_response(Gtk.ResponseType.CLOSE)
        self.connect("delete-event", self.on_delete_event)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_border_width(18)
        self.get_content_area().pack_start(box, True, True, 0)

        intro = Gtk.Label(label=(
            "Calculate MD5, SHA-1, SHA-256, and SHA-512 for the selected image in one read-only pass. "
            "The image is not mounted or modified, no USB device is opened, and administrator authentication is not used."
        ))
        intro.set_xalign(0)
        intro.set_line_wrap(True)
        box.pack_start(intro, False, False, 0)

        path_label = Gtk.Label(label=image_path)
        path_label.set_xalign(0)
        path_label.set_line_wrap(True)
        path_label.set_selectable(True)
        path_label.get_style_context().add_class("dim-label")
        box.pack_start(path_label, False, False, 0)

        warning = Gtk.InfoBar()
        warning.set_message_type(Gtk.MessageType.INFO)
        warning_label = Gtk.Label(label=(
            "MD5 and SHA-1 are included only for comparison with legacy published values. "
            "They are not used by RufusArm64 for trust, signatures, downloads, or write assurance."
        ))
        warning_label.set_xalign(0)
        warning_label.set_line_wrap(True)
        warning.get_content_area().add(warning_label)
        box.pack_start(warning, False, False, 0)

        action_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.calculate_button = Gtk.Button(label="Calculate")
        self.calculate_button.get_style_context().add_class("suggested-action")
        self.calculate_button.connect("clicked", self.start)
        action_row.pack_start(self.calculate_button, False, False, 0)
        self.copy_button = Gtk.Button(label="Copy report")
        self.copy_button.set_sensitive(False)
        self.copy_button.connect("clicked", self.copy_report)
        action_row.pack_start(self.copy_button, False, False, 0)
        self.spinner = Gtk.Spinner()
        action_row.pack_start(self.spinner, False, False, 0)
        self.status = Gtk.Label(label="Select Calculate to hash the exact image file.")
        self.status.set_xalign(0)
        self.status.set_line_wrap(True)
        action_row.pack_start(self.status, True, True, 0)
        box.pack_start(action_row, False, False, 0)

        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scroll.set_hexpand(True)
        scroll.set_vexpand(True)
        self.result_view = Gtk.TextView(
            editable=False,
            cursor_visible=False,
            monospace=True,
            wrap_mode=Gtk.WrapMode.WORD_CHAR,
        )
        self.result_view.get_buffer().set_text("No checksums have been calculated.")
        scroll.add(self.result_view)
        box.pack_start(scroll, True, True, 0)
        self.show_all()

    def on_delete_event(self, *_):
        if self.running:
            self.status.set_text("Checksum calculation is still running. Wait for it to finish before closing this dialog.")
            return True
        self.closed = True
        self.generation += 1
        return False

    def set_running(self, running):
        self.running = bool(running)
        self.calculate_button.set_sensitive(not self.running)
        self.close_button.set_sensitive(not self.running)
        self.copy_button.set_sensitive(not self.running and bool(self.report))
        if self.running:
            self.spinner.start()
        else:
            self.spinner.stop()

    def start(self, *_):
        if self.running:
            return
        try:
            command = build_checksum_command(self.helper, self.image_path)
        except ValueError as exc:
            self.status.set_text(str(exc))
            return
        self.generation += 1
        generation = self.generation
        self.report = ""
        self.set_running(True)
        self.status.set_text("Reading the selected image and calculating four checksums…")
        self.result_view.get_buffer().set_text("Checksum calculation in progress…")
        threading.Thread(target=self._run, args=(command, generation), daemon=True).start()

    def _run(self, command, generation):
        payload = None
        failure = ""
        try:
            completed = subprocess.run(
                command,
                check=False,
                text=True,
                capture_output=True,
                timeout=900,
            )
            if completed.returncode != 0:
                failure = completed.stderr.strip() or "The checksum helper failed."
            elif not completed.stdout.strip():
                failure = "The checksum helper returned no result."
            else:
                payload = normalize_checksum_result(json.loads(completed.stdout))
        except subprocess.TimeoutExpired:
            failure = "Checksum calculation exceeded the fifteen-minute safety limit."
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            failure = str(exc)
        GLib.idle_add(self._finish, generation, payload, failure)

    def _finish(self, generation, payload, failure):
        if self.closed or generation != self.generation:
            return False
        self.set_running(False)
        if failure:
            self.status.set_text("Checksums could not be calculated.")
            self.result_view.get_buffer().set_text(failure)
            self.parent_window.append_log(f"Image checksum calculation failed: {failure}")
            return False
        self.report = checksum_summary(payload)
        self.result_view.get_buffer().set_text(self.report)
        self.status.set_text("Checksums calculated successfully.")
        self.copy_button.set_sensitive(True)
        self.parent_window.append_log("Selected-image checksums:\n" + json.dumps(payload, indent=2, sort_keys=True))
        return False

    def copy_report(self, *_):
        if not self.report:
            return
        Gtk.Clipboard.get_default(self.get_display()).set_text(self.report, -1)
        self.status.set_text("Checksum report copied to the clipboard.")
