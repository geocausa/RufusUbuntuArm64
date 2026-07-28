#!/usr/bin/env python3
"""GTK review and guarded privileged launch for authenticated FFU images."""

import copy
import json
import os
import subprocess
import threading

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import GLib, Gtk

from rufusarm64_ffu_json import communicate_bounded, strict_json_loads
from rufusarm64_process import schedule_process_group_termination, terminate_and_reap, terminate_process_group
from rufusarm64_ffu_restore_logic import (
    build_ffu_restore_command,
    ffu_restore_summary,
    normalize_ffu_restore_output,
)
from rufusarm64_logic import (
    build_ffu_review_command,
    ffu_review_summary,
    normalize_ffu_review,
)




class FFUReviewDialog(Gtk.Dialog):
    """Review one FFU and allow one exact, evidence-bound restore attempt."""

    def __init__(self, parent, pkexec, helper, image, device):
        super().__init__(
            title="Review Full Flash Update",
            transient_for=parent,
            modal=True,
        )
        self.set_default_size(780, 720)
        self.set_resizable(True)
        self.add_button("Close", Gtk.ResponseType.CLOSE)
        self.set_default_response(Gtk.ResponseType.CLOSE)
        self.connect("delete-event", self.on_delete_event)
        self.connect("response", self.on_response)

        self.parent_window = parent
        self.pkexec = pkexec
        self.helper = helper
        self.image = image
        self.device = dict(device or {})
        self.running = False
        self.restoring = False
        self.closed = False
        self.generation = 0
        self.review = None
        self.review_payload = None
        self.restore_attempted = False
        self.process = None
        self.cancel_requested = False

        content = self.get_content_area()
        content.set_spacing(12)
        content.set_border_width(18)

        warning = Gtk.Label()
        warning.set_xalign(0)
        warning.set_line_wrap(True)
        warning.set_markup(
            "<b>Experimental FFU provider</b> — authenticate and review first. "
            "Restoration is available only for an already-unmounted removable whole disk "
            "and destroys data on the exact reviewed target."
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
            chooser.connect("file-set", self.review_input_changed)
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

        destructive = Gtk.Frame(label="Exact destructive confirmation")
        destructive_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        destructive_box.set_border_width(12)
        destructive.add(destructive_box)
        destructive_note = Gtk.Label()
        destructive_note.set_xalign(0)
        destructive_note.set_line_wrap(True)
        destructive_note.set_markup(
            "After a successful unmounted-target review, type the displayed phrase exactly. "
            "Administrator authentication then reruns every source, policy, trust-generation, "
            "target and geometry check before any write."
        )
        destructive_box.pack_start(destructive_note, False, False, 0)
        self.confirmation_entry = Gtk.Entry()
        self.confirmation_entry.set_placeholder_text(
            "RESTORE AUTHENTICATED FFU TO /dev/DEVICE SIZE N BYTES"
        )
        self.confirmation_entry.connect("changed", self.confirmation_changed)
        destructive_box.pack_start(self.confirmation_entry, False, False, 0)
        destructive_actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.restore_button = Gtk.Button(label="Restore authenticated FFU")
        self.restore_button.connect("clicked", self.start_restore)
        destructive_actions.pack_start(self.restore_button, False, False, 0)
        self.cancel_button = Gtk.Button(label="Cancel restore")
        self.cancel_button.connect("clicked", self.cancel_restore)
        destructive_actions.pack_start(self.cancel_button, False, False, 0)
        destructive_box.pack_start(destructive_actions, False, False, 0)
        content.pack_start(destructive, False, False, 0)

        self.show_all()
        self.update_restore_controls()

    def selected_inputs(self):
        return (
            self.trust_store.get_filename() or "",
            self.metadata_policy.get_filename() or "",
            self.publisher_policy.get_filename() or "",
        )

    def invalidate_review(self, clear_result=False):
        self.review = None
        self.review_payload = None
        self.restore_attempted = False
        self.confirmation_entry.set_text("")
        if clear_result:
            self.result.get_buffer().set_text(
                "The previous review is no longer valid. Authenticate and review again."
            )
        self.update_restore_controls()

    def review_input_changed(self, *_):
        if not self.running and self.review_payload is not None:
            self.invalidate_review(clear_result=True)
            self.status.set_text("Trust inputs changed; authenticate and review again.")

    def confirmation_changed(self, *_):
        self.update_restore_controls()

    def set_running(self, running, restoring=False):
        self.running = bool(running)
        self.restoring = self.running and bool(restoring)
        for chooser in (self.trust_store, self.metadata_policy, self.publisher_policy):
            chooser.set_sensitive(not self.running)
        self.review_button.set_sensitive(not self.running)
        if self.running:
            self.spinner.start()
        else:
            self.spinner.stop()
        self.update_restore_controls()

    def update_restore_controls(self):
        review_ready = (
            self.review is not None
            and self.review_payload is not None
            and not self.review.get("unmount_required")
            and not self.review.get("mounted_targets")
            and not self.restore_attempted
        )
        phrase_matches = (
            review_ready
            and self.confirmation_entry.get_text()
            == self.review.get("exact_confirmation_phrase")
        )
        auth_ready = (
            os.path.isfile(self.pkexec)
            and os.access(self.pkexec, os.X_OK)
            and os.path.isfile(self.helper)
            and os.access(self.helper, os.X_OK)
        )
        self.confirmation_entry.set_sensitive(review_ready and not self.running)
        self.restore_button.set_sensitive(
            bool(review_ready and phrase_matches and auth_ready and not self.running)
        )
        self.cancel_button.set_sensitive(bool(self.running and self.restoring))

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
        self.invalidate_review()
        self.set_running(True, restoring=False)
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
        process = None
        payload = None
        failure = ""
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            stdout, stderr = communicate_bounded(
                process,
                timeout=300,
                terminate=lambda force: terminate_process_group(process, force=force),
            )
            if stdout.strip():
                payload = strict_json_loads(stdout)
                normalize_ffu_review(payload)
            if process.returncode != 0:
                failure = stderr.strip() or stdout.strip() or "FFU review failed."
            elif payload is None:
                failure = "The FFU reviewer returned no evidence."
        except subprocess.TimeoutExpired:
            failure = "The authenticated FFU review exceeded the five-minute safety limit."
        except (OSError, ValueError) as exc:
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
            self.invalidate_review()
            return False
        try:
            review = normalize_ffu_review(payload)
            report = ffu_review_summary(payload)
        except ValueError as exc:
            self.status.set_text("Review evidence was rejected.")
            self.result.get_buffer().set_text(str(exc))
            self.parent_window.append_log(f"FFU review evidence rejected: {exc}")
            self.invalidate_review()
            return False
        self.review = review
        self.review_payload = copy.deepcopy(payload)
        self.restore_attempted = False
        self.status.set_text("Authenticated read-only review passed.")
        if review["unmount_required"]:
            self.status.set_text(
                "Review passed, but the target is mounted. Unmount it outside RufusArm64, refresh, and review again."
            )
        self.result.get_buffer().set_text(report)
        self.parent_window.append_log(
            "Authenticated FFU review:\n" + json.dumps(payload, indent=2, sort_keys=True)
        )
        self.update_restore_controls()
        return False

    def start_restore(self, *_):
        if self.running or self.review_payload is None or self.restore_attempted:
            return
        confirmation = self.confirmation_entry.get_text()
        try:
            command = build_ffu_restore_command(
                self.pkexec,
                self.helper,
                self.review_payload,
                confirmation,
            )
        except ValueError as exc:
            self.status.set_text(str(exc))
            return
        self.restore_attempted = True
        self.cancel_requested = False
        self.generation += 1
        generation = self.generation
        expected_review = copy.deepcopy(self.review_payload)
        self.set_running(True, restoring=True)
        self.status.set_text("Requesting administrator authentication for the exact reviewed FFU restore…")
        self.result.get_buffer().set_text(
            "Restoration is starting. Do not disconnect the source or target. "
            "Cancellation after writing begins can leave the target partially modified."
        )
        threading.Thread(
            target=self._run_restore,
            args=(command, generation, expected_review),
            daemon=True,
        ).start()

    def _run_restore(self, command, generation, expected_review):
        process = None
        payload = None
        normalized = None
        failure = ""
        uncertain = False
        return_code = 1
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            self.process = process
            if self.cancel_requested and process.poll() is None:
                try:
                    terminate_process_group(process)
                except (ProcessLookupError, PermissionError, OSError):
                    pass
            stdout, stderr = communicate_bounded(
                process,
                terminate=lambda force: terminate_process_group(process, force=force),
            )
            return_code = process.returncode
            if stdout.strip():
                try:
                    payload = strict_json_loads(stdout)
                    normalized = normalize_ffu_restore_output(payload, expected_review)
                except ValueError as exc:
                    failure = str(exc)
                    uncertain = True
            if normalized is None:
                failure = failure or stderr.strip() or stdout.strip() or "The privileged FFU provider returned no verifiable result evidence."
                uncertain = True
            elif stderr.strip():
                failure = stderr.strip()
        except (OSError, ValueError) as exc:
            if process is not None and process.returncode is not None:
                return_code = process.returncode
            failure = str(exc)
            uncertain = True
        finally:
            if self.process is process:
                self.process = None
        GLib.idle_add(
            self._finish_restore,
            generation,
            return_code,
            payload,
            normalized,
            failure,
            uncertain,
        )

    def cancel_restore(self, *_):
        if not self.running or not self.restoring:
            return
        self.cancel_requested = True
        self.cancel_button.set_sensitive(False)
        self.status.set_text(
            "Cancellation requested. Waiting for the provider's final evidence; the target state is not yet known."
        )
        process = self.process
        if process is not None and process.poll() is None:
            schedule_process_group_termination(process, grace_seconds=5)
    def _finish_restore(
        self,
        generation,
        return_code,
        payload,
        normalized,
        failure,
        uncertain,
    ):
        if self.closed or generation != self.generation:
            return False
        was_cancelled = self.cancel_requested
        self.cancel_requested = False
        self.set_running(False)
        self.confirmation_entry.set_sensitive(False)
        self.restore_button.set_sensitive(False)
        if payload is not None:
            self.parent_window.append_log(
                "Privileged FFU restore evidence:\n" + json.dumps(payload, indent=2, sort_keys=True)
            )
        if normalized is not None and not uncertain:
            report = ffu_restore_summary(normalized)
            if failure:
                report += "\n\nProvider diagnostic:\n" + failure
            self.result.get_buffer().set_text(report)
            outcome = normalized["outcome"]
            if outcome == "verified":
                self.status.set_text("FFU restoration completed and readback-verified.")
                self.parent_window.message(
                    "The authenticated FFU was restored, synchronized, and verified by complete readback.",
                    Gtk.MessageType.INFO,
                )
            elif outcome == "unchanged":
                self.status.set_text("FFU restoration did not write target bytes.")
                self.parent_window.message(
                    "The restore did not begin writing. Perform a fresh review before retrying.",
                    Gtk.MessageType.WARNING,
                )
            else:
                self.status.set_text("FFU target may be modified and is not safe to boot.")
                self.parent_window.message(
                    "The FFU target may be partially modified or unverified. Do not boot it; perform a fresh full restoration.",
                    Gtk.MessageType.ERROR,
                )
        else:
            report = (
                "DANGER: RufusArm64 could not validate final FFU execution evidence.\n"
                "The target state is unknown and it may have been modified. Do not boot, mount, or reuse it. "
                "Perform a fresh full restoration before trusting the device."
            )
            if was_cancelled:
                report += "\nCancellation was requested, but no trustworthy final mutation state was returned."
            if return_code is not None:
                report += f"\nProvider exit status: {return_code}"
            if failure:
                report += "\nProvider diagnostic: " + failure
            self.result.get_buffer().set_text(report)
            self.status.set_text("FFU target state is unknown; do not boot or reuse it.")
            self.parent_window.append_log(report)
            self.parent_window.message(
                "No trustworthy final FFU evidence was returned. Treat the target as possibly modified and do not boot it.",
                Gtk.MessageType.ERROR,
            )
        self.review = None
        self.review_payload = None
        return False

    def on_response(self, dialog, response_id):
        if self.running:
            operation = "restore" if self.restoring else "read-only review"
            self.status.set_text(f"The {operation} is still running; close it after completion.")
            dialog.stop_emission_by_name("response")

    def on_delete_event(self, *_):
        if self.running:
            operation = "restore" if self.restoring else "read-only review"
            self.status.set_text(f"The {operation} is still running; close it after completion.")
            return True
        self.closed = True
        self.generation += 1
        return False
