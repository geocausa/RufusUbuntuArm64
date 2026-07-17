#!/usr/bin/env python3
"""Identity-bound GTK wizard for persistent Ubuntu/Debian live USB creation."""

import json
import os
import signal
import subprocess
import tempfile
import threading
from datetime import datetime, timezone

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import GLib, Gtk

from rufusarm64_logic import device_label, human_bytes, human_duration, progress_status
from rufusarm64_persistence_logic import (
    build_analyze_command,
    build_create_command,
    inspect_source_identity,
    normalize_boot_label,
    normalize_persistence_gib,
    normalize_plan,
    plan_summary,
)

APP_ID = "io.github.geocausa.RufusArm64.Persistence"
HELPER = "/usr/lib/rufusarm64/rufusarm64-helper"
PERSISTENCE_HELPER = "/usr/lib/rufusarm64/rufusarm64-persistence-helper"
PKEXEC = "/usr/bin/pkexec"


class Window(Gtk.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="RufusArm64 Persistent Live USB")
        self.set_default_size(760, 700)
        self.devices = []
        self.process = None
        self.busy = False
        self.closed = False
        self.device_generation = 0
        self.device_refreshing = False
        self.job = ""
        self.cancel_requested = False
        self.cancel_path = None
        self.started = None
        self.plan = None
        self.plan_key = None
        self.last_status = None
        self.connect("delete-event", self.on_delete)

        header = Gtk.HeaderBar(title="RufusArm64 Persistent Live USB", subtitle="Ubuntu casper and Debian live-boot")
        header.set_show_close_button(True)
        self.set_titlebar(header)
        scroll = Gtk.ScrolledWindow()
        self.add(scroll)
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        outer.set_border_width(18)
        scroll.add(outer)

        title = Gtk.Label()
        title.set_markup("<span size='large' weight='bold'>Create a persistent live Linux USB</span>")
        title.set_xalign(0)
        outer.pack_start(title, False, False, 0)
        intro = Gtk.Label(label=(
            "The live system is copied to a writable FAT32 boot partition. A separate ext4 partition stores "
            "supported file, setting, and package changes across reboots. This remains a live environment, not a normal installation."
        ))
        intro.set_xalign(0)
        intro.set_line_wrap(True)
        outer.pack_start(intro, False, False, 0)
        warning = Gtk.InfoBar()
        warning.set_message_type(Gtk.MessageType.WARNING)
        warning_label = Gtk.Label(label=(
            "Experimental hardware scope: Ubuntu 20.04+ casper or Debian live-boot, GPT/UEFI, FAT32-safe files, "
            "and a matching fallback EFI loader. A real boot and reboot qualification is still required."
        ))
        warning_label.set_xalign(0)
        warning_label.set_line_wrap(True)
        warning.get_content_area().add(warning_label)
        outer.pack_start(warning, False, False, 0)

        grid = Gtk.Grid(column_spacing=12, row_spacing=12)
        outer.pack_start(grid, False, False, 0)
        self._label(grid, "Linux ISO", 0)
        self.image = Gtk.FileChooserButton(title="Choose a plain Linux ISOHybrid image", action=Gtk.FileChooserAction.OPEN)
        image_filter = Gtk.FileFilter()
        image_filter.set_name("Linux ISO images")
        image_filter.add_pattern("*.iso")
        image_filter.add_pattern("*.ISO")
        self.image.add_filter(image_filter)
        self.image.connect("file-set", self.selection_changed)
        grid.attach(self.image, 1, 0, 2, 1)

        self._label(grid, "USB drive", 1)
        self.target = Gtk.ComboBoxText()
        self.target.set_hexpand(True)
        self.target.connect("changed", self.selection_changed)
        grid.attach(self.target, 1, 1, 1, 1)
        self.refresh_button = Gtk.Button.new_from_icon_name("view-refresh-symbolic", Gtk.IconSize.BUTTON)
        self.refresh_button.connect("clicked", lambda *_: self.refresh_devices())
        grid.attach(self.refresh_button, 2, 1, 1, 1)

        self._label(grid, "Persistent storage", 2)
        size_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.size = Gtk.SpinButton.new_with_range(0, 1024, 1)
        self.size.set_value(16)
        self.size.connect("value-changed", self.selection_changed)
        size_row.pack_start(self.size, False, False, 0)
        size_row.pack_start(Gtk.Label(label="GiB (0 = suitable remaining space)"), False, False, 0)
        grid.attach(size_row, 1, 2, 2, 1)

        self._label(grid, "Boot volume label", 3)
        self.volume_label = Gtk.Entry()
        self.volume_label.set_max_length(11)
        self.volume_label.set_text("RUFUS-LIVE")
        self.volume_label.connect("changed", self.selection_changed)
        grid.attach(self.volume_label, 1, 3, 2, 1)

        frame = Gtk.Frame(label="Mandatory compatibility analysis")
        frame_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        frame_box.set_border_width(12)
        frame.add(frame_box)
        outer.pack_start(frame, False, False, 0)
        note = Gtk.Label(label=(
            "Analysis mounts only the identity-bound ISO in a private read-only workspace. The USB is not opened. "
            "Creation remains disabled until the current image, target capacity, and requested size pass."
        ))
        note.set_xalign(0)
        note.set_line_wrap(True)
        frame_box.pack_start(note, False, False, 0)
        self.analyze_button = Gtk.Button(label="Analyze selected image")
        self.analyze_button.set_halign(Gtk.Align.START)
        self.analyze_button.connect("clicked", self.analyze)
        frame_box.pack_start(self.analyze_button, False, False, 0)
        self.summary = Gtk.Label(label="Choose an ISO and removable USB, then run the mandatory analysis.")
        self.summary.set_xalign(0)
        self.summary.set_line_wrap(True)
        self.summary.set_selectable(True)
        frame_box.pack_start(self.summary, False, False, 0)

        self.progress = Gtk.ProgressBar(show_text=True)
        self.progress.set_text("Ready")
        outer.pack_start(self.progress, False, False, 0)
        self.detail = Gtk.Label(label="No destructive action is available until analysis succeeds.")
        self.detail.set_xalign(0)
        self.detail.set_line_wrap(True)
        outer.pack_start(self.detail, False, False, 0)

        details = Gtk.Expander(label="Details and diagnostics")
        log_scroll = Gtk.ScrolledWindow()
        log_scroll.set_min_content_height(170)
        self.log = Gtk.TextView(editable=False, cursor_visible=False, monospace=True, wrap_mode=Gtk.WrapMode.WORD_CHAR)
        log_scroll.add(self.log)
        details.add(log_scroll)
        outer.pack_start(details, True, True, 0)

        buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        buttons.set_halign(Gtk.Align.END)
        outer.pack_start(buttons, False, False, 0)
        self.cancel_button = Gtk.Button(label="Cancel")
        self.cancel_button.set_sensitive(False)
        self.cancel_button.connect("clicked", self.cancel)
        buttons.pack_start(self.cancel_button, False, False, 0)
        self.create_button = Gtk.Button(label="Erase and create persistent USB")
        self.create_button.get_style_context().add_class("destructive-action")
        self.create_button.set_sensitive(False)
        self.create_button.connect("clicked", self.create)
        buttons.pack_start(self.create_button, False, False, 0)
        self.refresh_devices()

    @staticmethod
    def _label(grid, text, row):
        label = Gtk.Label(label=text)
        label.set_xalign(0)
        grid.attach(label, 0, row, 1, 1)

    def append_log(self, text):
        text = str(text or "").strip()
        if text:
            stamp = datetime.now().astimezone().strftime("%H:%M:%S")
            buffer_ = self.log.get_buffer()
            buffer_.insert(buffer_.get_end_iter(), f"[{stamp}] {text}\n")
        return False

    def selection_changed(self, *_):
        if not self.busy:
            self.plan = self.plan_key = None
            self.create_button.set_sensitive(False)
            self.summary.set_text("Selection changed. Run compatibility analysis again before creation.")

    def selection(self):
        image = self.image.get_filename() or ""
        index = self.target.get_active()
        if not image:
            raise ValueError("Choose a plain Linux ISO image first.")
        if not 0 <= index < len(self.devices):
            raise ValueError("Connect and select a removable USB drive first.")
        device = self.devices[index]
        target_identity = str(device.get("identity") or "").strip()
        target_size = int(device.get("size") or 0)
        if not target_identity or target_size <= 0:
            raise ValueError("The selected USB does not expose a complete safety identity and capacity. Refresh the list.")
        image, source_identity = inspect_source_identity(image)
        size_gib = normalize_persistence_gib(self.size.get_value_as_int())
        label = normalize_boot_label(self.volume_label.get_text())
        key = (image, source_identity, target_identity, target_size, size_gib)
        return image, source_identity, device, target_identity, target_size, size_gib, label, key

    def refresh_devices(self):
        if self.busy or self.device_refreshing or self.closed:
            return
        self.device_generation += 1
        generation = self.device_generation
        self.device_refreshing = True
        self.target.remove_all()
        self.devices = []
        self.plan = self.plan_key = None
        self.create_button.set_sensitive(False)
        self.progress.set_text("Scanning removable drives…")
        self.set_busy(self.busy)
        threading.Thread(target=self._run_device_refresh, args=(generation,), daemon=True).start()

    def _run_device_refresh(self, generation):
        devices = []
        error = ""
        try:
            result = subprocess.run([HELPER, "list", "--json"], check=True, text=True, capture_output=True, timeout=15)
            devices = json.loads(result.stdout)
            if not isinstance(devices, list):
                raise ValueError("Drive enumeration returned invalid data.")
        except Exception as exc:
            error = str(exc)
        GLib.idle_add(self._finish_device_refresh, generation, devices, error)

    def _finish_device_refresh(self, generation, devices, error):
        if self.closed or generation != self.device_generation:
            return False
        self.device_refreshing = False
        self.devices = devices if not error else []
        self.target.remove_all()
        for device in self.devices:
            self.target.append_text(device_label(device))
        if error:
            self.append_log(f"Could not list removable USB drives: {error}")
            self.progress.set_text("Drive detection failed")
        elif self.devices:
            self.target.set_active(0)
            self.progress.set_text("Ready for compatibility analysis")
        else:
            self.progress.set_text("No removable USB drive found")
        self.set_busy(self.busy)
        return False

    @staticmethod
    def new_cancel_path():
        fd, path = tempfile.mkstemp(prefix="rufusarm64-persistence-", suffix=".cancel", dir=f"/run/user/{os.getuid()}")
        os.close(fd)
        os.unlink(path)
        return path

    def set_busy(self, busy, job=""):
        self.busy = busy
        self.job = job if busy else ""
        for widget in (self.image, self.target, self.size, self.volume_label):
            widget.set_sensitive(not busy)
        self.refresh_button.set_sensitive(not busy and not self.device_refreshing)
        self.analyze_button.set_sensitive(not busy and not self.device_refreshing)
        self.create_button.set_sensitive(
            not busy and not self.device_refreshing and self.plan is not None and self.plan_key is not None
        )
        self.cancel_button.set_sensitive(busy)

    def analyze(self, *_):
        try:
            image, source_id, _device, _target_id, target_size, size_gib, _label, key = self.selection()
            cancel_path = self.new_cancel_path()
            command = build_analyze_command(PKEXEC, HELPER, image, source_id, target_size, size_gib, cancel_path)
        except (ValueError, OSError) as exc:
            self.message(str(exc), Gtk.MessageType.ERROR)
            return
        if not os.access(PKEXEC, os.X_OK):
            self.message("Administrator authentication through pkexec is not installed.", Gtk.MessageType.ERROR)
            return
        self.cancel_path = cancel_path
        self.cancel_requested = False
        self.started = datetime.now(timezone.utc)
        self.plan = self.plan_key = None
        self.log.get_buffer().set_text("")
        self.append_log(f"Read-only analysis: {image}")
        self.append_log(f"Planned target capacity only: {human_bytes(target_size)}; the USB is not opened")
        self.set_busy(True, "analyze")
        self.progress.pulse()
        self.progress.set_text("Requesting read-only analysis permission…")
        self.detail.set_text("The ISO will be mounted privately and read-only; the USB is not accessed.")
        GLib.timeout_add_seconds(1, self.pulse)
        threading.Thread(target=self.run_analysis, args=(command, key), daemon=True).start()

    def run_analysis(self, command, key):
        process = None
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
            self.process = process
            stdout, stderr = process.communicate()
            code = process.returncode
            payload = json.loads(stdout) if code == 0 else {}
            error = (stderr.strip() or stdout.strip()) if code else ""
            GLib.idle_add(self.finish_analysis, code, payload, error, key)
        except Exception as exc:
            GLib.idle_add(self.finish_analysis, 1, {}, str(exc), key)
        finally:
            if self.process is process:
                self.process = None

    def finish_analysis(self, code, payload, error, key):
        cancelled = self.cancel_requested
        self.cleanup_cancel()
        self.cancel_requested = False
        self.set_busy(False)
        if code == 0:
            try:
                plan = normalize_plan(payload)
                if self.selection()[-1] != key:
                    raise ValueError("The ISO or USB selection changed while analysis was running.")
            except ValueError as exc:
                error = str(exc)
            else:
                self.plan, self.plan_key = plan, key
                text = plan_summary(plan, human_bytes)
                self.summary.set_text(text)
                self.append_log(text)
                self.create_button.set_sensitive(True)
                self.progress.set_fraction(1)
                self.progress.set_text("Compatibility confirmed")
                self.detail.set_text("Creation is enabled for this exact source identity, USB identity, capacity, and persistence size.")
                return False
        self.plan = self.plan_key = None
        self.create_button.set_sensitive(False)
        if cancelled:
            self.progress.set_text("Analysis cancelled")
            self.detail.set_text("The private read-only mount was cleaned up. Nothing was modified.")
        else:
            self.summary.set_text("Not compatible with the supported persistence scope.\n" + (error or "Unknown analysis error"))
            self.progress.set_text("Compatibility analysis failed")
            self.detail.set_text("The USB was not opened or modified.")
        return False

    def create(self, *_):
        if not self.plan or not self.plan_key:
            return
        try:
            image, source_id, device, target_id, target_size, size_gib, label, key = self.selection()
            if key != self.plan_key:
                raise ValueError("The image, USB, or requested size changed. Analyze again.")
            cancel_path = self.new_cancel_path()
            command = build_create_command(
                PKEXEC, PERSISTENCE_HELPER, image, source_id, device.get("path"), target_id,
                size_gib, label, cancel_path,
            )
        except (ValueError, OSError) as exc:
            self.message(str(exc), Gtk.MessageType.ERROR)
            return
        if not os.access(PERSISTENCE_HELPER, os.X_OK):
            self.message("The package-owned persistence helper is not installed or executable.", Gtk.MessageType.ERROR)
            return
        dialog = Gtk.MessageDialog(
            transient_for=self, modal=True, message_type=Gtk.MessageType.WARNING,
            buttons=Gtk.ButtonsType.CANCEL, text="Erase the selected USB and create persistent live media?",
        )
        dialog.format_secondary_text(
            f"ALL DATA on {device.get('path')} ({human_bytes(target_size)}) will be permanently erased.\n\n"
            f"{plan_summary(self.plan, human_bytes)}\n\n"
            "This is a persistent live system, not a conventional installed OS. Software checks cannot guarantee firmware boot. "
            "After creation, boot this exact USB and complete start/reboot/verify qualification."
        )
        dialog.add_button("Erase and create persistent USB", Gtk.ResponseType.OK)
        dialog.set_default_response(Gtk.ResponseType.CANCEL)
        response = dialog.run()
        dialog.destroy()
        if response != Gtk.ResponseType.OK:
            return
        self.cancel_path = cancel_path
        self.cancel_requested = False
        self.started = datetime.now(timezone.utc)
        self.last_status = None
        self.log.get_buffer().set_text("")
        self.append_log(f"Image: {image}")
        self.append_log(f"Target: {device_label(device)}")
        self.append_log(plan_summary(self.plan, human_bytes))
        self.set_busy(True, "create")
        self.progress.set_fraction(0)
        self.progress.set_text("Requesting administrator permission…")
        self.detail.set_text("The privileged helper repeats source and target identity checks before erasure.")
        threading.Thread(target=self.run_create, args=(command,), daemon=True).start()

    def run_create(self, command):
        process = None
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, start_new_session=True)
            self.process = process
            for raw in process.stdout or ():
                line = raw.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    GLib.idle_add(self.append_log, line)
                else:
                    GLib.idle_add(self.handle_event, event)
            code = process.wait()
            GLib.idle_add(self.finish_create, code)
        except Exception as exc:
            GLib.idle_add(self.append_log, f"Persistent USB creation failed: {exc}")
            GLib.idle_add(self.finish_create, 1)
        finally:
            if self.process is process:
                self.process = None

    def handle_event(self, event):
        message = str(event.get("message") or "")
        stage = str(event.get("stage") or "working")
        event_type = event.get("event")
        done, total = int(event.get("done") or 0), int(event.get("total") or 0)
        rate = float(event.get("rate") or 0)
        status = (stage, message)
        if event_type == "log" or (message and status != self.last_status):
            self.append_log(message)
            self.last_status = status
        if total > 0:
            self.progress.set_fraction(min(1, done / total))
            self.progress.set_text(f"{stage.replace('_', ' ').title()}: {done / total * 100:.1f}%")
            self.detail.set_text(progress_status(stage, done, total, rate))
        elif event_type in {"stage", "preflight"}:
            self.progress.pulse()
            self.progress.set_text(message or stage.replace("_", " ").title())
            self.detail.set_text(message or "Working…")
        elif event_type == "complete":
            self.progress.set_fraction(1)
            self.progress.set_text(message or "Complete")
        return False

    def finish_create(self, code):
        cancelled = self.cancel_requested
        self.cleanup_cancel()
        self.cancel_requested = False
        self.set_busy(False)
        self.plan = self.plan_key = None
        self.create_button.set_sensitive(False)
        if code == 0:
            self.progress.set_fraction(1)
            self.progress.set_text("Persistent live USB creation completed")
            self.detail.set_text("Internal checks passed. Boot the USB, then qualify persistence across one reboot.")
            self.message(
                "Persistent live media was created and checked.\n\nBoot it and run:\n\n"
                "sudo rufusarm64-cli qualify start --record /cdrom/.rufusarm64/creation.json --output ~/rufusarm64-initial.json\n\n"
                "Reboot the same USB, then run qualify verify with a new output file. Until that passes, treat this image/hardware combination as unqualified.",
                Gtk.MessageType.INFO,
            )
        elif cancelled:
            self.progress.set_text("Creation cancelled")
            self.detail.set_text("The USB is incomplete and must be recreated before use.")
            self.message("Creation stopped. The USB is incomplete and must be recreated.", Gtk.MessageType.WARNING)
        else:
            self.progress.set_text("Creation failed — see Details")
            self.detail.set_text("Nothing is being written now. The USB may be incomplete.")
            self.message("Persistent USB creation failed. Recreate the USB before use.", Gtk.MessageType.ERROR)
        self.refresh_devices()
        return False

    def pulse(self):
        if not self.busy or self.job != "analyze":
            return False
        self.progress.pulse()
        elapsed = (datetime.now(timezone.utc) - self.started).total_seconds() if self.started else 0
        action = "Cleaning up the private read-only mount" if self.cancel_requested else "Read-only analysis is running"
        self.detail.set_text(f"{action} ({human_duration(elapsed)} elapsed). The USB is not accessed.")
        return True

    def cancel(self, *_):
        if not self.busy:
            return
        self.cancel_requested = True
        self.cancel_button.set_sensitive(False)
        self.progress.set_text("Cancelling safely…")
        self.detail.set_text("Do not unplug the USB until cleanup is confirmed.")
        if self.cancel_path:
            try:
                fd = os.open(self.cancel_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                os.close(fd)
            except FileExistsError:
                pass
            except OSError as exc:
                self.append_log(f"Could not create cancellation marker: {exc}")
        if self.process and self.process.poll() is None:
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass

    def cleanup_cancel(self):
        if self.cancel_path:
            try:
                os.unlink(self.cancel_path)
            except FileNotFoundError:
                pass
            self.cancel_path = None

    def on_delete(self, *_):
        if self.busy:
            self.message("An operation is running. Cancel it and wait for cleanup before closing.", Gtk.MessageType.WARNING)
            return True
        self.closed = True
        self.device_generation += 1
        return False

    def message(self, text, kind):
        dialog = Gtk.MessageDialog(transient_for=self, modal=True, message_type=kind, buttons=Gtk.ButtonsType.OK, text=text)
        dialog.run()
        dialog.destroy()


class App(Gtk.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID)

    def do_activate(self):
        window = self.props.active_window or Window(self)
        window.show_all()
        window.present()


if __name__ == "__main__":
    raise SystemExit(App().run(None))
