"""GTK integration for guarded x86 BIOS/Legacy FreeDOS media creation."""

import json
import os
import signal
import subprocess
import tempfile
import threading

from gi.repository import GLib, Gtk

from rufusarm64_freedos import (
    build_dry_run_command,
    build_run_command,
    confirmation_phrase,
    decode_progress_line,
    normalize_plan,
    normalize_report,
    plan_summary,
    progress_summary,
    report_summary,
)


FREEDOS_FORMATTER = "/usr/lib/rufusarm64/rufusarm64-freedos-format"
PKEXEC = "/usr/bin/pkexec"


class FreeDOSFormatDialog(Gtk.Dialog):
    """Create verified FreeDOS media on one selected removable whole disk."""

    def __init__(self, parent, device, identity, binary=FREEDOS_FORMATTER, pkexec=PKEXEC):
        super().__init__(title="Create FreeDOS media", transient_for=parent, modal=True)
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
        self.last_progress_done = 0
        self.has_determinate_progress = False
        self.set_default_size(780, 560)
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

        title = Gtk.Label()
        title.set_markup("<span size='large' weight='bold'>FreeDOS 1.4 — x86 BIOS/Legacy media</span>")
        title.set_xalign(0)
        detail_box.pack_start(title, False, False, 0)

        intro = Gtk.Label(
            label=(
                "This separate workflow erases the complete selected removable drive and constructs one "
                "deterministic FAT32 FreeDOS volume from checksum-pinned package payloads."
            )
        )
        intro.set_xalign(0)
        intro.set_line_wrap(True)
        detail_box.pack_start(intro, False, False, 0)

        controls = Gtk.Grid(column_spacing=12, row_spacing=10)
        detail_box.pack_start(controls, False, False, 0)
        controls.attach(self._label("Volume label"), 0, 0, 1, 1)
        self.volume_label = Gtk.Entry()
        self.volume_label.set_max_length(11)
        self.volume_label.set_placeholder_text("FREEDOS")
        saved_label = str(parent.settings.get("freedos_label") or "FREEDOS").upper()
        self.volume_label.set_text(saved_label)
        self.volume_label.connect("changed", self.selection_changed)
        controls.attach(self.volume_label, 1, 0, 1, 1)

        self.plan_label = Gtk.Label(label="Calculating the unprivileged FreeDOS plan…")
        self.plan_label.set_xalign(0)
        self.plan_label.set_line_wrap(True)
        self.plan_label.set_selectable(True)
        detail_box.pack_start(self.plan_label, False, False, 0)

        warning = Gtk.InfoBar()
        warning.set_message_type(Gtk.MessageType.WARNING)
        warning_label = Gtk.Label(
            label=(
                "Everything on the selected drive will be permanently erased. The resulting media runs only "
                "on x86-compatible computers using BIOS or UEFI Legacy/CSM. It will not boot ARM64 or "
                "UEFI-only systems. Software verification cannot prove that a physical PC will boot it."
            )
        )
        warning_label.set_xalign(0)
        warning_label.set_line_wrap(True)
        warning.get_content_area().add(warning_label)
        detail_box.pack_start(warning, False, False, 0)

        self.confirm_label = Gtk.Label(
            label="The exact WRITE FREEDOS phrase appears after the read-only plan is validated."
        )
        self.confirm_label.set_xalign(0)
        self.confirm_label.set_line_wrap(True)
        self.confirm_label.set_selectable(True)
        box.pack_start(self.confirm_label, False, False, 0)

        self.confirmation = Gtk.Entry()
        self.confirmation.set_placeholder_text("Type the exact WRITE FREEDOS phrase")
        self.confirmation.connect("changed", self.confirmation_changed)
        box.pack_start(self.confirmation, False, False, 0)

        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.run_button = Gtk.Button(label="Create FreeDOS media")
        self.run_button.get_style_context().add_class("destructive-action")
        self.run_button.set_sensitive(False)
        self.run_button.connect("clicked", self.start_run)
        actions.pack_start(self.run_button, False, False, 0)

        self.cancel_button = Gtk.Button(label="Cancel creation")
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
        result_scroll.set_min_content_height(140)
        result_scroll.set_max_content_height(220)
        result_scroll.set_propagate_natural_height(True)
        self.result = Gtk.TextView(
            editable=False,
            cursor_visible=False,
            monospace=True,
            wrap_mode=Gtk.WrapMode.WORD_CHAR,
        )
        self.result.get_buffer().set_text("No FreeDOS report is available yet.")
        result_scroll.add(self.result)
        box.pack_start(result_scroll, False, False, 0)

        self.show_all()
        self.refresh_plan()

    @staticmethod
    def _label(text):
        label = Gtk.Label(label=text)
        label.set_xalign(0)
        return label

    def current_label(self):
        return self.volume_label.get_text().upper()

    def selection_changed(self, *_):
        if self.running:
            return
        value = self.volume_label.get_text().upper()
        if value != self.volume_label.get_text():
            position = self.volume_label.get_position()
            self.volume_label.set_text(value)
            self.volume_label.set_position(position)
            return
        self.plan = None
        self.confirmation.set_text("")
        self.refresh_plan()

    def refresh_plan(self):
        if self.running or self.closed:
            return
        self.plan_generation += 1
        generation = self.plan_generation
        label = self.current_label()
        self.plan = None
        self.run_button.set_sensitive(False)
        self.status.set_text("Calculating the exact FreeDOS plan without administrator access…")
        self.plan_label.set_text(
            "Checking target identity, capacity, 512-byte sectors, FAT32 geometry, pinned payload, and platform warnings…"
        )
        try:
            command = build_dry_run_command(self.binary, self.device, self.identity, label)
        except ValueError as exc:
            self._plan_ready(generation, None, str(exc))
            return
        threading.Thread(
            target=self._plan_worker,
            args=(command, generation, label),
            daemon=True,
        ).start()

    def _plan_worker(self, command, generation, label):
        try:
            completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=30)
            if completed.returncode != 0:
                raise RuntimeError((completed.stderr or completed.stdout or "FreeDOS planning failed.").strip())
            payload = normalize_plan(json.loads(completed.stdout))
            if payload["plan"]["device_path"] != self.device or payload["identity"] != self.identity:
                raise ValueError("FreeDOS plan no longer refers to the selected device.")
            if payload["plan"]["label"] != label:
                raise ValueError("FreeDOS plan no longer matches the selected volume label.")
            GLib.idle_add(self._plan_ready, generation, payload, "")
        except Exception as exc:
            GLib.idle_add(self._plan_ready, generation, None, str(exc))

    def _plan_ready(self, generation, payload, error):
        if self.closed or self.running or generation != self.plan_generation:
            return False
        if error:
            self.plan = None
            self.plan_label.set_text("FreeDOS creation plan unavailable.")
            self.confirm_label.set_text(
                "The exact WRITE FREEDOS phrase appears after the read-only plan is validated."
            )
            self.status.set_text(error)
        else:
            self.plan = payload
            self.plan_label.set_text(plan_summary(payload))
            self.confirm_label.set_text(f"Type exactly: {confirmation_phrase(payload)}")
            self.status.set_text(
                "Review the x86 BIOS/Legacy boundary, type the exact phrase, then authenticate."
            )
            self.parent_window.settings["freedos_label"] = payload["plan"]["label"]
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
        for widget in (self.volume_label, self.confirmation):
            widget.set_sensitive(not self.running)
        self.run_button.set_sensitive(False)
        self.cancel_button.set_sensitive(self.running)
        self.close_button.set_sensitive(not self.running)
        if self.running:
            self.parent_window.active_job = "freedos-format"
            self.parent_window.set_busy(True)
            self.progress.pulse()
            GLib.timeout_add(250, self.pulse_progress)
        else:
            if self.parent_window.active_job == "freedos-format":
                self.parent_window.active_job = ""
            self.parent_window.set_busy(False)
            self.confirmation_changed()

    def pulse_progress(self):
        if not self.running or self.has_determinate_progress:
            return False
        self.progress.pulse()
        return True

    def start_run(self, *_):
        if self.running or not self.plan:
            return
        try:
            expected = confirmation_phrase(self.plan)
            if self.confirmation.get_text().strip() != expected:
                raise ValueError("Type the exact WRITE FREEDOS phrase before authentication.")
            self.cancel_path = self._new_cancel_path()
            command = build_run_command(
                self.pkexec,
                self.binary,
                self.device,
                self.identity,
                self.current_label(),
                self.cancel_path,
            )
        except (OSError, ValueError) as exc:
            self._remove_cancel_path()
            self.status.set_text(str(exc))
            return
        self.run_generation += 1
        generation = self.run_generation
        self.last_progress_done = 0
        self.has_determinate_progress = False
        self.progress.set_fraction(0.0)
        self.progress.set_text("Waiting for administrator authentication…")
        self.result.get_buffer().set_text("FreeDOS creation in progress…")
        self.set_running(True)
        self.status.set_text(
            "Authenticate to erase the drive and create the reviewed x86 BIOS/Legacy FreeDOS media."
        )
        threading.Thread(
            target=self._run_worker,
            args=(command, generation, self.plan),
            daemon=True,
        ).start()

    @staticmethod
    def _new_cancel_path():
        runtime_dir = f"/run/user/{os.getuid()}"
        fd, path = tempfile.mkstemp(
            prefix="rufusarm64-freedos-",
            suffix=".cancel",
            dir=runtime_dir,
        )
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
                bufsize=1,
                start_new_session=True,
            )
            self.process = process
            expected_total = int(reviewed["plan"]["device_size_bytes"]) * 2
            last_done = 0
            for line in process.stderr:
                progress = decode_progress_line(line)
                if progress is not None:
                    if progress["overall_total"] != expected_total:
                        raise ValueError("FreeDOS helper progress does not match the reviewed full-device I/O total.")
                    if progress["overall_done"] < last_done:
                        raise ValueError("FreeDOS helper progress moved backwards.")
                    last_done = progress["overall_done"]
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
                payload = normalize_report(json.loads(stdout), reviewed)
            if payload is None:
                raise RuntimeError("FreeDOS creation did not return its final media-state report.")
            if (returncode == 0) != (payload["status"] == "succeeded"):
                raise ValueError("FreeDOS report status does not match the helper exit status.")
            GLib.idle_add(
                self._run_ready,
                generation,
                payload,
                "\n".join(diagnostics),
                returncode,
            )
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

    def _progress_ready(self, generation, progress):
        if self.closed or generation != self.run_generation or not self.running:
            return False
        done = progress["overall_done"]
        if done < self.last_progress_done:
            return False
        self.last_progress_done = done
        self.has_determinate_progress = True
        self.progress.set_fraction(min(1.0, done / progress["overall_total"]))
        summary = progress_summary(progress)
        self.progress.set_text(f"{progress['phase'].capitalize()}: {done * 100.0 / progress['overall_total']:.1f}%")
        self.status.set_text(summary)
        return False

    def _run_ready(self, generation, payload, diagnostics, returncode):
        if self.closed or generation != self.run_generation:
            return False
        self.process = None
        self._remove_cancel_path()
        self.set_running(False)
        self.confirmation.set_text("")
        if payload is None:
            self.progress.set_text("FreeDOS creation could not complete")
            self.status.set_text(
                "No trustworthy final report was returned. Inspect the drive before reuse; it may be intentionally incomplete."
            )
            self.result.get_buffer().set_text(diagnostics)
            self.parent_window.append_log(
                "FreeDOS creation failed to return a report:\n" + diagnostics
            )
        else:
            summary = report_summary(payload)
            self.status.set_text(summary)
            rendered = json.dumps(payload, indent=2, sort_keys=True)
            if diagnostics:
                rendered += "\n\nDiagnostics:\n" + diagnostics
            self.result.get_buffer().set_text(rendered)
            self.parent_window.append_log("FreeDOS creation result:\n" + rendered)
            if payload["status"] == "succeeded" and returncode == 0:
                self.progress.set_fraction(1.0)
                self.progress.set_text("Verified FreeDOS media ready")
            elif payload["status"] == "cancelled":
                self.progress.set_text("FreeDOS creation cancelled")
            else:
                self.progress.set_text("FreeDOS creation failed")
            self.plan = None
        self.parent_window.refresh_devices()
        return False

    def cancel_run(self, *_):
        if not self.running or not self.cancel_path:
            return
        self.cancel_button.set_sensitive(False)
        self.status.set_text(
            "Cancellation requested. The guarded disk operation will finish its current boundary before returning the exact media state."
        )
        self.progress.set_text("Cancelling safely…")
        try:
            descriptor = os.open(
                self.cancel_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
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
            self.status.set_text(
                "Closing requested. Cancelling FreeDOS creation and waiting for the final media-state report…"
            )
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
    button = getattr(window, "freedos_button", None)
    if button is None:
        return
    index = window.target_combo.get_active()
    selected = window.devices[index] if 0 <= index < len(window.devices) else None
    ready = bool((selected or {}).get("path") and (selected or {}).get("identity"))
    button.set_sensitive(not window.busy and not window.device_refreshing and ready)


def install_freedos(window_class):
    """Install the FreeDOS action before the first RufusWindow is created."""
    if getattr(window_class, "_freedos_installed", False):
        return
    original_init = window_class.__init__
    original_set_busy = window_class.set_busy

    def integrated_init(window, app):
        original_init(window, app)
        actions = _find_target_action_box(window)
        window.freedos_button = Gtk.Button(label="FreeDOS…")
        window.freedos_button.set_tooltip_text(
            "Erase the selected removable drive and create verified x86 BIOS/Legacy FreeDOS 1.4 media"
        )
        window.freedos_button.connect("clicked", window.open_freedos_format)
        actions.pack_start(window.freedos_button, False, False, 0)
        window.target_combo.connect("changed", lambda *_: _update_sensitivity(window))
        _update_sensitivity(window)

    def integrated_set_busy(window, busy):
        original_set_busy(window, busy)
        _update_sensitivity(window)

    def open_freedos_format(window, *_):
        if window.busy:
            return
        index = window.target_combo.get_active()
        selected = window.devices[index] if 0 <= index < len(window.devices) else None
        device = str((selected or {}).get("path") or "")
        identity = str((selected or {}).get("identity") or "")
        if not device or not identity:
            window.progress_detail.set_text(
                "Choose a removable drive and refresh the device list before creating FreeDOS media."
            )
            return
        dialog = FreeDOSFormatDialog(window, device, identity)
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
    window_class.open_freedos_format = open_freedos_format
    window_class._freedos_installed = True
