"""GTK integration for guarded non-bootable removable-media formatting."""

import json
import os
import signal
import subprocess
import tempfile
import threading

from gi.repository import GLib, Gtk

from rufusarm64_nonbootable import (
    build_dry_run_command,
    build_run_command,
    confirmation_phrase,
    normalize_plan,
    normalize_report,
    plan_summary,
    report_summary,
)


NONBOOTABLE_FORMATTER = "/usr/lib/rufusarm64/rufusarm64-nonbootable-format"
PKEXEC = "/usr/bin/pkexec"


class NonBootableFormatDialog(Gtk.Dialog):
    """Create one verified data-only partition on the selected removable drive."""

    def __init__(self, parent, device, identity, binary=NONBOOTABLE_FORMATTER, pkexec=PKEXEC):
        super().__init__(title="Create non-bootable media", transient_for=parent, modal=True)
        self.parent_window = parent
        self.device = device
        self.identity = identity
        self.binary = binary
        self.pkexec = pkexec
        self.plan = None
        self.process = None
        self.cancel_path = ""
        self.running = False
        self.closed = False
        self.plan_generation = 0
        self.run_generation = 0
        self.set_default_size(760, 560)
        self.set_resizable(True)
        self.add_button("Close", Gtk.ResponseType.CLOSE)
        self.close_button = self.get_widget_for_response(Gtk.ResponseType.CLOSE)
        self.connect("delete-event", self.on_delete_event)

        content_scroll = Gtk.ScrolledWindow()
        content_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        content_scroll.set_hexpand(True)
        content_scroll.set_vexpand(True)
        self.get_content_area().pack_start(content_scroll, True, True, 0)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_border_width(18)
        content_scroll.add(box)

        title = Gtk.Label()
        title.set_markup("<span size='large' weight='bold'>Non bootable — data-only media</span>")
        title.set_xalign(0)
        box.pack_start(title, False, False, 0)

        intro = Gtk.Label(
            label=(
                "This separate workflow erases the complete selected removable drive, creates one data partition, "
                "checks the new filesystem, and explicitly does not claim the result is bootable."
            )
        )
        intro.set_xalign(0)
        intro.set_line_wrap(True)
        box.pack_start(intro, False, False, 0)

        controls = Gtk.Grid(column_spacing=12, row_spacing=10)
        box.pack_start(controls, False, False, 0)

        controls.attach(self._label("Partition scheme"), 0, 0, 1, 1)
        self.scheme = Gtk.ComboBoxText()
        self.scheme.append("gpt", "GPT")
        self.scheme.append("mbr", "MBR")
        saved_scheme = str(parent.settings.get("nonbootable_scheme") or "gpt")
        self.scheme.set_active_id(saved_scheme if saved_scheme in {"gpt", "mbr"} else "gpt")
        self.scheme.connect("changed", self.selection_changed)
        controls.attach(self.scheme, 1, 0, 1, 1)

        controls.attach(self._label("File system"), 0, 1, 1, 1)
        self.filesystem = Gtk.ComboBoxText()
        self.filesystem.append("fat32", "FAT32")
        self.filesystem.append("exfat", "exFAT")
        self.filesystem.append("ntfs", "NTFS")
        self.filesystem.append("ext4", "ext4")
        saved_filesystem = str(parent.settings.get("nonbootable_filesystem") or "fat32")
        self.filesystem.set_active_id(
            saved_filesystem if saved_filesystem in {"fat32", "exfat", "ntfs", "ext4"} else "fat32"
        )
        self.filesystem.connect("changed", self.selection_changed)
        controls.attach(self.filesystem, 1, 1, 1, 1)

        controls.attach(self._label("Volume label"), 0, 2, 1, 1)
        self.volume_label = Gtk.Entry()
        self.volume_label.set_placeholder_text("Optional")
        self.volume_label.set_text(str(parent.settings.get("nonbootable_label") or ""))
        self.volume_label.connect("changed", self.selection_changed)
        controls.attach(self.volume_label, 1, 2, 1, 1)

        self.plan_label = Gtk.Label(label="Calculating the unprivileged formatting plan…")
        self.plan_label.set_xalign(0)
        self.plan_label.set_line_wrap(True)
        self.plan_label.set_selectable(True)
        box.pack_start(self.plan_label, False, False, 0)

        warning = Gtk.InfoBar()
        warning.set_message_type(Gtk.MessageType.WARNING)
        warning_label = Gtk.Label(
            label=(
                "Everything on the selected drive will be permanently erased. Cancelling after erasure may leave intentionally "
                "incomplete media that must be formatted again before use."
            )
        )
        warning_label.set_xalign(0)
        warning_label.set_line_wrap(True)
        warning.get_content_area().add(warning_label)
        box.pack_start(warning, False, False, 0)

        self.confirm_label = Gtk.Label(label="The exact FORMAT phrase appears after the read-only plan is validated.")
        self.confirm_label.set_xalign(0)
        self.confirm_label.set_line_wrap(True)
        self.confirm_label.set_selectable(True)
        box.pack_start(self.confirm_label, False, False, 0)

        self.confirmation = Gtk.Entry()
        self.confirmation.set_placeholder_text("Type the exact FORMAT phrase")
        self.confirmation.connect("changed", self.confirmation_changed)
        box.pack_start(self.confirmation, False, False, 0)

        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.run_button = Gtk.Button(label="Format data-only media")
        self.run_button.get_style_context().add_class("destructive-action")
        self.run_button.set_sensitive(False)
        self.run_button.connect("clicked", self.start_run)
        actions.pack_start(self.run_button, False, False, 0)
        self.cancel_button = Gtk.Button(label="Cancel formatting")
        self.cancel_button.set_sensitive(False)
        self.cancel_button.connect("clicked", self.cancel_run)
        actions.pack_start(self.cancel_button, False, False, 0)
        self.status = Gtk.Label(label="Preparing a read-only plan…")
        self.status.set_xalign(0)
        self.status.set_line_wrap(True)
        actions.pack_start(self.status, True, True, 0)
        box.pack_start(actions, False, False, 0)

        self.progress = Gtk.ProgressBar(show_text=True)
        self.progress.set_text("Not started")
        box.pack_start(self.progress, False, False, 0)

        result_scroll = Gtk.ScrolledWindow()
        result_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        result_scroll.set_min_content_height(160)
        result_scroll.set_max_content_height(240)
        result_scroll.set_propagate_natural_height(True)
        self.result = Gtk.TextView(editable=False, cursor_visible=False, monospace=True, wrap_mode=Gtk.WrapMode.WORD_CHAR)
        self.result.get_buffer().set_text("No formatting report is available yet.")
        result_scroll.add(self.result)
        box.pack_start(result_scroll, False, False, 0)

        self.show_all()
        self.refresh_plan()

    @staticmethod
    def _label(text):
        label = Gtk.Label(label=text)
        label.set_xalign(0)
        return label

    def current_choices(self):
        scheme = self.scheme.get_active_id() or "gpt"
        filesystem = self.filesystem.get_active_id() or "fat32"
        label = self.volume_label.get_text()
        if filesystem == "fat32":
            label = label.upper()
        return scheme, filesystem, label

    def selection_changed(self, *_):
        if self.running:
            return
        self.plan = None
        self.confirmation.set_text("")
        self.refresh_plan()

    def refresh_plan(self):
        if self.running or self.closed:
            return
        self.plan_generation += 1
        generation = self.plan_generation
        scheme, filesystem, label = self.current_choices()
        self.plan = None
        self.run_button.set_sensitive(False)
        self.status.set_text("Calculating the exact data-only plan without administrator access…")
        self.plan_label.set_text("Checking identity, capacity, sector size, layout, filesystem tools, and safety warnings…")
        try:
            command = build_dry_run_command(self.binary, self.device, self.identity, scheme, filesystem, label)
        except ValueError as exc:
            self._plan_ready(generation, None, str(exc))
            return
        threading.Thread(target=self._plan_worker, args=(command, generation, scheme, filesystem, label), daemon=True).start()

    def _plan_worker(self, command, generation, scheme, filesystem, label):
        try:
            completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=30)
            if completed.returncode != 0:
                raise RuntimeError((completed.stderr or completed.stdout or "Formatting plan failed.").strip())
            payload = normalize_plan(json.loads(completed.stdout))
            if payload["plan"]["device_path"] != self.device or payload["identity"] != self.identity:
                raise ValueError("Formatting plan no longer refers to the selected device.")
            if (
                payload["plan"]["scheme"] != scheme
                or payload["plan"]["filesystem"] != filesystem
                or payload["plan"]["label"] != label
            ):
                raise ValueError("Formatting plan no longer matches the selected layout choices.")
            GLib.idle_add(self._plan_ready, generation, payload, "")
        except Exception as exc:
            GLib.idle_add(self._plan_ready, generation, None, str(exc))

    def _plan_ready(self, generation, payload, error):
        if self.closed or self.running or generation != self.plan_generation:
            return False
        if error:
            self.plan = None
            self.plan_label.set_text("Non-bootable formatting plan unavailable.")
            self.confirm_label.set_text("The exact FORMAT phrase appears after the read-only plan is validated.")
            self.status.set_text(error)
        else:
            self.plan = payload
            self.plan_label.set_text(plan_summary(payload))
            self.confirm_label.set_text(f"Type exactly: {confirmation_phrase(payload)}")
            self.status.set_text("Review every detail, type the exact FORMAT phrase, then authenticate.")
            self.parent_window.settings["nonbootable_scheme"] = payload["plan"]["scheme"]
            self.parent_window.settings["nonbootable_filesystem"] = payload["plan"]["filesystem"]
            self.parent_window.settings["nonbootable_label"] = payload["plan"]["label"]
        self.confirmation_changed()
        return False

    def confirmation_changed(self, *_):
        enabled = False
        if self.plan and not self.running:
            try:
                enabled = self.confirmation.get_text().strip() == confirmation_phrase(self.plan)
            except ValueError:
                enabled = False
        self.run_button.set_sensitive(enabled)

    def set_running(self, running):
        self.running = bool(running)
        for widget in (self.scheme, self.filesystem, self.volume_label, self.confirmation):
            widget.set_sensitive(not self.running)
        self.run_button.set_sensitive(False)
        self.cancel_button.set_sensitive(self.running)
        self.close_button.set_sensitive(not self.running)
        if self.running:
            self.parent_window.active_job = "nonbootable-format"
            self.parent_window.set_busy(True)
            self.progress.pulse()
            GLib.timeout_add(250, self.pulse_progress)
        else:
            if self.parent_window.active_job == "nonbootable-format":
                self.parent_window.active_job = ""
            self.parent_window.set_busy(False)
            self.confirmation_changed()

    def pulse_progress(self):
        if not self.running:
            return False
        self.progress.pulse()
        return True

    def start_run(self, *_):
        if self.running or not self.plan:
            return
        try:
            expected = confirmation_phrase(self.plan)
            if self.confirmation.get_text().strip() != expected:
                raise ValueError("Type the exact FORMAT phrase before authentication.")
            self.cancel_path = self._new_cancel_path()
            scheme, filesystem, label = self.current_choices()
            command = build_run_command(
                self.pkexec,
                self.binary,
                self.device,
                self.identity,
                scheme,
                filesystem,
                label,
                self.cancel_path,
            )
        except (OSError, ValueError) as exc:
            self._remove_cancel_path()
            self.status.set_text(str(exc))
            return
        self.run_generation += 1
        generation = self.run_generation
        self.progress.set_fraction(0.0)
        self.progress.set_text("Waiting for administrator authentication…")
        self.result.get_buffer().set_text("Formatting in progress…")
        self.set_running(True)
        self.status.set_text("Authenticate to erase the drive and create the reviewed data-only filesystem.")
        threading.Thread(target=self._run_worker, args=(command, generation, self.plan), daemon=True).start()

    @staticmethod
    def _new_cancel_path():
        runtime_dir = f"/run/user/{os.getuid()}"
        fd, path = tempfile.mkstemp(prefix="rufusarm64-format-", suffix=".cancel", dir=runtime_dir)
        os.close(fd)
        os.unlink(path)
        return path

    def _run_worker(self, command, generation, reviewed):
        diagnostics = []
        diagnostics_size = 0
        payload = None
        returncode = 1
        process = None
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            self.process = process
            stdout, stderr = process.communicate()
            returncode = process.returncode
            self.process = None
            for line in stderr.splitlines():
                text = line.strip()
                if text and len(diagnostics) < 64 and diagnostics_size + len(text) <= 32768:
                    diagnostics.append(text)
                    diagnostics_size += len(text)
            if stdout.strip():
                payload = normalize_report(json.loads(stdout), reviewed)
            if payload is None:
                raise RuntimeError("Non-bootable formatting did not return its final report.")
            if (returncode == 0) != (payload["status"] == "passed"):
                raise ValueError("Formatting report status does not match the helper exit status.")
            GLib.idle_add(self._run_ready, generation, payload, "\n".join(diagnostics), returncode)
        except Exception as exc:
            self.process = None
            if process is not None:
                self._terminate_and_reap(process)
            detail = str(exc)
            if diagnostics:
                detail += "\n\nDiagnostics:\n" + "\n".join(diagnostics)
            GLib.idle_add(self._run_ready, generation, None, detail, returncode)

    @staticmethod
    def _terminate_and_reap(process):
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

    def _run_ready(self, generation, payload, diagnostics, returncode):
        if self.closed or generation != self.run_generation:
            return False
        self.process = None
        self._remove_cancel_path()
        self.set_running(False)
        self.confirmation.set_text("")
        if payload is None:
            self.progress.set_text("Formatting could not complete")
            self.status.set_text(
                "No trustworthy final report was returned. Inspect the drive before reuse; it may be intentionally incomplete."
            )
            self.result.get_buffer().set_text(diagnostics)
            self.parent_window.append_log("Non-bootable formatting failed to return a report:\n" + diagnostics)
        else:
            summary = report_summary(payload)
            self.status.set_text(summary)
            rendered = json.dumps(payload, indent=2, sort_keys=True)
            if diagnostics:
                rendered += "\n\nDiagnostics:\n" + diagnostics
            self.result.get_buffer().set_text(rendered)
            self.parent_window.append_log("Non-bootable formatting result:\n" + rendered)
            if payload["status"] == "passed" and returncode == 0:
                self.progress.set_fraction(1.0)
                self.progress.set_text("Verified data-only media ready")
                self.plan = None
            elif payload["status"] == "cancelled":
                self.progress.set_text("Formatting cancelled")
                self.plan = None
            else:
                self.progress.set_text("Formatting failed")
                self.plan = None
        self.parent_window.refresh_devices()
        return False

    def cancel_run(self, *_):
        if not self.running or not self.cancel_path:
            return
        self.cancel_button.set_sensitive(False)
        self.status.set_text(
            "Cancellation requested. The current guarded disk operation will finish before the helper returns a precise media-state report."
        )
        self.progress.set_text("Cancelling safely…")
        try:
            descriptor = os.open(self.cancel_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(descriptor)
        except FileExistsError:
            pass
        except OSError as exc:
            self.status.set_text(f"Could not create the private cancellation marker: {exc}")
            self.cancel_button.set_sensitive(True)

    def _remove_cancel_path(self):
        if not self.cancel_path:
            return
        try:
            os.unlink(self.cancel_path)
        except FileNotFoundError:
            pass
        self.cancel_path = ""

    def on_delete_event(self, *_):
        if self.running:
            self.cancel_run()
            self.status.set_text("Closing requested. Cancelling formatting and waiting for the final media-state report…")
            return True
        self.closed = True
        self.plan_generation += 1
        self.run_generation += 1
        self._remove_cancel_path()
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


def _update_sensitivity(window):
    button = getattr(window, "nonbootable_button", None)
    if button is None:
        return
    index = window.target_combo.get_active()
    selected = window.devices[index] if 0 <= index < len(window.devices) else None
    ready = bool((selected or {}).get("path") and (selected or {}).get("identity"))
    button.set_sensitive(not window.busy and not window.device_refreshing and ready)


def install_nonbootable(window_class):
    """Install the data-only formatter before the first RufusWindow instance is created."""
    if getattr(window_class, "_nonbootable_installed", False):
        return
    original_init = window_class.__init__
    original_set_busy = window_class.set_busy

    def integrated_init(window, app):
        original_init(window, app)
        actions = _find_target_action_box(window)
        window.nonbootable_button = Gtk.Button(label="Non bootable…")
        window.nonbootable_button.set_tooltip_text(
            "Erase the selected removable drive and create one verified data-only filesystem"
        )
        window.nonbootable_button.connect("clicked", window.open_nonbootable_format)
        actions.pack_start(window.nonbootable_button, False, False, 0)
        window.target_combo.connect("changed", lambda *_: _update_sensitivity(window))
        _update_sensitivity(window)

    def integrated_set_busy(window, busy):
        original_set_busy(window, busy)
        _update_sensitivity(window)

    def open_nonbootable_format(window, *_):
        if window.busy:
            return
        index = window.target_combo.get_active()
        selected = window.devices[index] if 0 <= index < len(window.devices) else None
        device = str((selected or {}).get("path") or "")
        identity = str((selected or {}).get("identity") or "")
        if not device or not identity:
            window.progress_detail.set_text("Choose a removable drive and refresh the device list before formatting it.")
            return
        dialog = NonBootableFormatDialog(window, device, identity)
        dialog.run()
        if dialog.running:
            return
        dialog.closed = True
        dialog.plan_generation += 1
        dialog.run_generation += 1
        dialog._remove_cancel_path()
        dialog.destroy()
        window.save_settings()

    window_class.__init__ = integrated_init
    window_class.set_busy = integrated_set_busy
    window_class.open_nonbootable_format = open_nonbootable_format
    window_class._nonbootable_installed = True
