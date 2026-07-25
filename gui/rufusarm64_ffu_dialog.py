#!/usr/bin/env python3
"""Read-only GTK review for authenticated Full Flash Update images."""

import json
import os
import subprocess
import threading

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import GLib, Gtk

from rufusarm64_logic import (
    build_ffu_review_command,
    ffu_review_summary,
    normalize_ffu_review,
)


class FFUReviewDialog(Gtk.Dialog):
    """Collect explicit trust inputs and run only the unprivileged FFU review."""

    def __init__(self, parent, helper, image, device):
        super().__init__(
            title="Review Full Flash Update",
            transient_for=parent,
            modal=True,
        )
        self.set_default_size(760, 620)
        self.set_resizable(True)
        self.add_button("Close", Gtk.ResponseType.CLOSE)
        self.set_default_response(Gtk.ResponseType.CLOSE)
        self.connect("delete-event", self.on_delete_event)
        self.connect("response", self.on_response)

        self.parent_window = parent
        self.helper = helper
        self.image = image
        self.device = dict(device or {})
        self.running = False
        self.closed = False
        self.generation = 0
        self.review = None

        content = self.get_content_area()
        content.set_spacing(12)
        content.set_border_width(18)

        warning = Gtk.Label()
        warning.set_xalign(0)
        warning.set_line_wrap(True)
        warning.set_markup(
            "<b>Experimental, read-only review</b> — this verifies the signed FFU, "
            "publisher policy, exact removable target and planned changed bytes. "
            "It does not open, unmount or modify the target."
        )
        content.pack_start(warning, False, False, 0)

        summary = Gtk.Label(
            label=(
                f"Image: {image}\n"
                f"Target: {self.device.get('path', '')} — "
                f"{self.device.get('vendor', '')} {self.device.get('model', '')}"
            )
        )
        summary.set_xalign(0)
        summary.set_line_wrap(True)
        content.pack_start(summary, False, False, 0)

        grid = Gtk.Grid(column_spacing=12, row_spacing=10)
        content.pack_start(grid, False, False, 0)

        self.trust_store = Gtk.FileChooserButton(
            title="Choose the authenticated FFU trust-store folder",
            action=Gtk.FileChooserAction.SELECT_FOLDER,
        )
        self.metadata_policy = Gtk.FileChooserButton(
            title="Choose the FFU trust-metadata public-key policy",
            action=Gtk.FileChooserAction.OPEN,
        )
        self.publisher_policy = Gtk.FileChooserButton(
            title="Choose the explicit FFU publisher policy",
            action=Gtk.FileChooserAction.OPEN,
        )
        policy_filter = Gtk.FileFilter()
        policy_filter.set_name("JSON policy files")
        policy_filter.add_pattern("*.json")
        policy_filter.add_pattern("*.JSON")
        self.metadata_policy.add_filter(policy_filter)
        self.publisher_policy.add_filter(policy_filter)

        for row, (label_text, chooser) in enumerate(
            (
                ("Authenticated trust store", self.trust_store),
                ("Trust-metadata policy", self.metadata_policy),
                ("Publisher policy", self.publisher_policy),
            )
        ):
            label = Gtk.Label(label=label_text)
            label.set_xalign(0)
            grid.attach(label, 0, row, 1, 1)
            chooser.set_hexpand(True)
            grid.attach(chooser, 1, row, 1, 1)

        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.spinner = Gtk.Spinner()
        actions.pack_start(self.spinner, False, False, 0)
        self.review_button = Gtk.Button(label="Authenticate and review")
        self.review_button.connect("clicked", self.start_review)
        actions.pack_start(self.review_button, False, False, 0)
        self.status = Gtk.Label(label="Choose all three explicit trust inputs.")
        self.status.set_xalign(0)
        self.status.set_line_wrap(True)
        actions.pack_start(self.status, True, True, 0)
        content.pack_start(actions, False, False, 0)

        result_scroll = Gtk.ScrolledWindow()
        result_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        result_scroll.set_vexpand(True)
        self.result = Gtk.TextView()
        self.result.set_editable(False)
        self.result.set_cursor_visible(False)
        self.result.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.result.get_buffer().set_text(
            "No review has been performed. The ordinary Create USB action remains disabled for FFU images."
        )
        result_scroll.add(self.result)
        content.pack_start(result_scroll, True, True, 0)
        self.show_all()

    def set_running(self, running):
        self.running = bool(running)
        for chooser in (self.trust_store, self.metadata_policy, self.publisher_policy):
            chooser.set_sensitive(not self.running)
        self.review_button.set_sensitive(not self.running)
        if self.running:
            self.spinner.start()
        else:
            self.spinner.stop()

    def selected_inputs(self):
        return (
            self.trust_store.get_filename() or "",
            self.metadata_policy.get_filename() or "",
            self.publisher_policy.get_filename() or "",
        )

    def start_review(self, *_):
        if self.running:
            return
        trust_store, metadata_policy, publisher_policy = self.selected_inputs()
        try:
            command = build_ffu_review_command(
                self.helper,
                self.image,
                self.device,
                trust_store,
                metadata_policy,
                publisher_policy,
            )
        except ValueError as exc:
            self.status.set_text(str(exc))
            return
        self.generation += 1
        generation = self.generation
        self.review = None
        self.set_running(True)
        self.status.set_text("Authenticating the FFU and rediscovering the exact target…")
        self.result.get_buffer().set_text(
            "Review in progress. The target is not being opened or modified."
        )
        threading.Thread(
            target=self._run_review,
            args=(command, generation),
            daemon=True,
        ).start()

    def _run_review(self, command, generation):
        payload = None
        failure = ""
        try:
            completed = subprocess.run(
                command,
                check=False,
                text=True,
                capture_output=True,
                timeout=300,
            )
            if completed.stdout.strip():
                payload = json.loads(completed.stdout)
                normalize_ffu_review(payload)
            if completed.returncode != 0:
                failure = completed.stderr.strip() or completed.stdout.strip() or "FFU review failed."
            elif payload is None:
                failure = "The FFU reviewer returned no evidence."
        except subprocess.TimeoutExpired:
            failure = "The authenticated FFU review exceeded the five-minute safety limit."
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            failure = str(exc)
        GLib.idle_add(self._finish_review, generation, payload, failure)

    def _finish_review(self, generation, payload, failure):
        if self.closed or generation != self.generation:
            return False
        self.set_running(False)
        if failure:
            self.status.set_text("Review could not be completed.")
            self.result.get_buffer().set_text(failure)
            self.parent_window.append_log(f"FFU review failed: {failure}")
            return False
        try:
            self.review = normalize_ffu_review(payload)
            report = ffu_review_summary(payload)
        except ValueError as exc:
            self.status.set_text("Review evidence was rejected.")
            self.result.get_buffer().set_text(str(exc))
            self.parent_window.append_log(f"FFU review evidence rejected: {exc}")
            return False
        self.status.set_text("Authenticated read-only review passed.")
        self.result.get_buffer().set_text(report)
        self.parent_window.append_log(
            "Authenticated FFU review:\n" + json.dumps(payload, indent=2, sort_keys=True)
        )
        return False

    def on_response(self, dialog, response_id):
        if self.running:
            self.status.set_text("The read-only review is still running; close it after completion.")
            dialog.stop_emission_by_name("response")

    def on_delete_event(self, *_):
        if self.running:
            self.status.set_text("The read-only review is still running; close it after completion.")
            return True
        self.closed = True
        self.generation += 1
        return False
