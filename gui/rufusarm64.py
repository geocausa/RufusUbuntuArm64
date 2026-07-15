#!/usr/bin/env python3
"""RufusArm64 GTK front end.

The GUI never writes block devices itself. It delegates destructive work to the
small Go helper through pkexec so Ubuntu's normal administrator-authentication
prompt is used and the UI can remain unprivileged.
"""

import json
import os
import shutil
import signal
import subprocess
import threading

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import GLib, Gtk

APP_ID = "io.github.geocausa.RufusArm64"
APP_NAME = "RufusArm64"
VERSION = "0.2.0"
INSTALLED_HELPER = "/usr/lib/rufusarm64/rufusarm64-helper"


def helper_path():
    if os.path.isfile(INSTALLED_HELPER) and os.access(INSTALLED_HELPER, os.X_OK):
        return INSTALLED_HELPER
    return shutil.which("rufusarm64-helper") or INSTALLED_HELPER


def human_bytes(value):
    value = float(value or 0)
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return "0 B"


class RufusWindow(Gtk.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app)
        self.set_default_size(760, 620)
        self.set_border_width(18)
        self.devices = []
        self.process = None

        header = Gtk.HeaderBar(title=APP_NAME, subtitle="Bootable USB creator for Ubuntu ARM64")
        header.set_show_close_button(True)
        self.set_titlebar(header)

        about_button = Gtk.Button.new_from_icon_name("help-about-symbolic", Gtk.IconSize.BUTTON)
        about_button.set_tooltip_text("About RufusArm64")
        about_button.connect("clicked", self.show_about)
        header.pack_end(about_button)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        self.add(outer)

        intro = Gtk.Label()
        intro.set_markup("<span size='large' weight='bold'>Create a bootable USB drive</span>")
        intro.set_xalign(0)
        outer.pack_start(intro, False, False, 0)

        description = Gtk.Label(
            label=(
                "Choose an image and a USB drive. Linux ISOHybrid/raw images are written directly. "
                "Standard Windows installation ISOs are prepared as UEFI FAT32 media, with large "
                "install.wim files split automatically."
            )
        )
        description.set_xalign(0)
        description.set_line_wrap(True)
        outer.pack_start(description, False, False, 0)

        grid = Gtk.Grid(column_spacing=12, row_spacing=12)
        grid.set_hexpand(True)
        outer.pack_start(grid, False, False, 0)

        image_label = Gtk.Label(label="Boot image")
        image_label.set_xalign(0)
        grid.attach(image_label, 0, 0, 1, 1)

        self.image_chooser = Gtk.FileChooserButton(
            title="Choose an ISO or disk image", action=Gtk.FileChooserAction.OPEN
        )
        self.image_chooser.set_hexpand(True)
        self.image_chooser.connect("file-set", self.image_changed)
        image_filter = Gtk.FileFilter()
        image_filter.set_name("ISO and disk images")
        for pattern in ("*.iso", "*.img", "*.raw", "*.bin", "*.ISO", "*.IMG", "*.RAW", "*.BIN"):
            image_filter.add_pattern(pattern)
        self.image_chooser.add_filter(image_filter)
        all_filter = Gtk.FileFilter()
        all_filter.set_name("All files")
        all_filter.add_pattern("*")
        self.image_chooser.add_filter(all_filter)
        grid.attach(self.image_chooser, 1, 0, 2, 1)

        target_label = Gtk.Label(label="USB drive")
        target_label.set_xalign(0)
        grid.attach(target_label, 0, 1, 1, 1)

        self.target_combo = Gtk.ComboBoxText()
        self.target_combo.set_hexpand(True)
        grid.attach(self.target_combo, 1, 1, 1, 1)

        self.refresh_button = Gtk.Button.new_from_icon_name("view-refresh-symbolic", Gtk.IconSize.BUTTON)
        self.refresh_button.set_tooltip_text("Refresh connected USB drives")
        self.refresh_button.connect("clicked", lambda *_: self.refresh_devices())
        grid.attach(self.refresh_button, 2, 1, 1, 1)

        mode_label = Gtk.Label(label="Image handling")
        mode_label.set_xalign(0)
        grid.attach(mode_label, 0, 2, 1, 1)
        self.mode_value = Gtk.Label(label="Automatic")
        self.mode_value.set_xalign(0)
        self.mode_value.set_tooltip_text("The helper detects raw/Linux images and Windows installation ISOs automatically.")
        grid.attach(self.mode_value, 1, 2, 2, 1)

        self.verify = Gtk.CheckButton(label="Verify copied data after writing")
        self.verify.set_active(True)
        self.verify.set_tooltip_text("Recommended. Verification takes additional time but detects faulty media or writes.")
        grid.attach(self.verify, 1, 3, 2, 1)

        arm_note = Gtk.Label(
            label="For Windows on Surface Pro 11 X1E, choose an official Windows ARM64 ISO. An x86-64 ISO will not boot that device."
        )
        arm_note.set_xalign(0)
        arm_note.set_line_wrap(True)
        arm_note.get_style_context().add_class("dim-label")
        grid.attach(arm_note, 1, 4, 2, 1)

        warning = Gtk.InfoBar()
        warning.set_message_type(Gtk.MessageType.WARNING)
        warning.set_show_close_button(False)
        warning_label = Gtk.Label(label="Everything on the selected USB drive will be permanently erased.")
        warning_label.set_xalign(0)
        warning.get_content_area().add(warning_label)
        outer.pack_start(warning, False, False, 0)

        self.progress = Gtk.ProgressBar(show_text=True)
        self.progress.set_text("Ready")
        outer.pack_start(self.progress, False, False, 0)

        details = Gtk.Expander(label="Details")
        details.set_expanded(True)
        details.set_vexpand(True)
        scroll = Gtk.ScrolledWindow()
        scroll.set_hexpand(True)
        scroll.set_vexpand(True)
        scroll.set_min_content_height(210)
        self.log = Gtk.TextView(
            editable=False,
            cursor_visible=False,
            monospace=True,
            wrap_mode=Gtk.WrapMode.WORD_CHAR,
        )
        scroll.add(self.log)
        details.add(scroll)
        outer.pack_start(details, True, True, 0)

        buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        buttons.set_halign(Gtk.Align.END)
        outer.pack_start(buttons, False, False, 0)

        self.cancel_button = Gtk.Button(label="Cancel")
        self.cancel_button.set_sensitive(False)
        self.cancel_button.connect("clicked", self.cancel)
        buttons.pack_start(self.cancel_button, False, False, 0)

        self.start_button = Gtk.Button(label="Create USB")
        self.start_button.get_style_context().add_class("suggested-action")
        self.start_button.connect("clicked", self.start)
        buttons.pack_start(self.start_button, False, False, 0)

        self.refresh_devices()

    def append_log(self, text):
        text = str(text).strip()
        if not text:
            return False
        buffer_ = self.log.get_buffer()
        buffer_.insert(buffer_.get_end_iter(), text + "\n")
        mark = buffer_.create_mark(None, buffer_.get_end_iter(), False)
        self.log.scroll_to_mark(mark, 0.0, True, 0.0, 1.0)
        return False

    def set_busy(self, busy):
        self.start_button.set_sensitive(not busy)
        self.image_chooser.set_sensitive(not busy)
        self.target_combo.set_sensitive(not busy)
        self.refresh_button.set_sensitive(not busy)
        self.verify.set_sensitive(not busy)
        self.cancel_button.set_sensitive(busy)

    def image_changed(self, *_):
        path = self.image_chooser.get_filename()
        if not path:
            self.mode_value.set_text("Automatic")
            return
        lower = path.lower()
        if lower.endswith(".iso"):
            self.mode_value.set_text("Automatic — Linux ISOHybrid or Windows UEFI installer")
        else:
            self.mode_value.set_text("Raw disk-image writing")

    def refresh_devices(self):
        self.target_combo.remove_all()
        self.devices = []
        helper = helper_path()
        try:
            result = subprocess.run(
                [helper, "list", "--json"], check=True, text=True, capture_output=True, timeout=15
            )
            self.devices = json.loads(result.stdout)
            for device in self.devices:
                model = " ".join(
                    value for value in (device.get("vendor", ""), device.get("model", "")) if value
                ).strip() or "USB drive"
                transport = (device.get("tran") or "unknown").upper()
                label = f"{device.get('path')} — {model} — {human_bytes(device.get('size'))} — {transport}"
                self.target_combo.append_text(label)
            if self.devices:
                self.target_combo.set_active(0)
                self.progress.set_text("Ready")
                self.start_button.set_sensitive(True)
            else:
                self.progress.set_text("No removable USB drive found")
                self.start_button.set_sensitive(False)
        except Exception as exc:
            self.append_log(f"Could not list USB drives: {exc}")
            self.progress.set_text("Drive detection failed")
            self.start_button.set_sensitive(False)

    def start(self, *_):
        image = self.image_chooser.get_filename()
        index = self.target_combo.get_active()
        if not image:
            self.message("Choose an ISO or disk image first.", Gtk.MessageType.INFO)
            return
        if index < 0 or index >= len(self.devices):
            self.message("Connect and select a USB drive first.", Gtk.MessageType.INFO)
            return

        device = self.devices[index]
        path = device.get("path")
        model = " ".join(
            value for value in (device.get("vendor", ""), device.get("model", "")) if value
        ).strip() or "USB drive"
        dialog = Gtk.MessageDialog(
            transient_for=self,
            modal=True,
            message_type=Gtk.MessageType.WARNING,
            buttons=Gtk.ButtonsType.CANCEL,
            text="Erase the selected USB drive?",
        )
        dialog.format_secondary_text(
            f"All data on {path} ({model}, {human_bytes(device.get('size'))}) will be permanently erased. "
            "Check the device carefully before continuing."
        )
        dialog.add_button("Erase and create USB", Gtk.ResponseType.OK)
        response = dialog.run()
        dialog.destroy()
        if response != Gtk.ResponseType.OK:
            return

        self.log.get_buffer().set_text("")
        self.append_log(f"Image: {image}")
        self.append_log(f"Target: {path} — {model} — {human_bytes(device.get('size'))}")
        self.set_busy(True)
        self.progress.set_fraction(0)
        self.progress.set_text("Requesting administrator permission…")

        command = [
            "pkexec",
            helper_path(),
            "write",
            "--image",
            image,
            "--device",
            path,
            "--mode",
            "auto",
            "--yes",
            "--json-progress",
        ]
        if self.verify.get_active():
            command.append("--verify")
        threading.Thread(target=self.run_writer, args=(command,), daemon=True).start()

    def run_writer(self, command):
        try:
            self.process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                start_new_session=True,
            )
            assert self.process.stdout is not None
            for raw in self.process.stdout:
                line = raw.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    GLib.idle_add(self.append_log, line)
                    continue
                GLib.idle_add(self.handle_event, event)
            return_code = self.process.wait()
            GLib.idle_add(self.finish, return_code)
        except Exception as exc:
            GLib.idle_add(self.append_log, f"Failed to start the writer: {exc}")
            GLib.idle_add(self.finish, 1)
        finally:
            self.process = None

    def handle_event(self, event):
        message = event.get("message", "")
        if message:
            self.append_log(message)
        total = int(event.get("total") or 0)
        done = int(event.get("done") or 0)
        stage = (event.get("stage") or "Working").replace("_", " ").title()
        if total > 0:
            fraction = min(1.0, done / total)
            self.progress.set_fraction(fraction)
            self.progress.set_text(f"{stage}: {fraction * 100:.1f}%")
        elif event.get("event") in ("stage", "log", "preflight"):
            self.progress.pulse()
            if message:
                self.progress.set_text(message)
        elif event.get("event") == "complete":
            self.progress.set_fraction(1.0)
            self.progress.set_text(message or "Complete")
        return False

    def finish(self, return_code):
        self.set_busy(False)
        if return_code == 0:
            self.progress.set_fraction(1.0)
            self.progress.set_text("USB created successfully")
            self.message(
                "The bootable USB was created successfully. Close any file-manager window for it, then remove it safely.",
                Gtk.MessageType.INFO,
            )
        else:
            self.progress.set_text("Failed — see Details")
            self.message(
                "The USB could not be created. Nothing is being written now. Open Details for the exact error.",
                Gtk.MessageType.ERROR,
            )
        self.refresh_devices()
        return False

    def cancel(self, *_):
        process = self.process
        if process and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                self.append_log("Cancellation requested. Do not remove the USB until the operation stops.")
                self.progress.set_text("Cancelling safely…")
            except ProcessLookupError:
                pass

    def message(self, text, kind):
        dialog = Gtk.MessageDialog(
            transient_for=self,
            modal=True,
            message_type=kind,
            buttons=Gtk.ButtonsType.OK,
            text=text,
        )
        dialog.run()
        dialog.destroy()

    def show_about(self, *_):
        dialog = Gtk.AboutDialog(transient_for=self, modal=True)
        dialog.set_program_name(APP_NAME)
        dialog.set_version(VERSION)
        dialog.set_comments(
            "An unofficial Ubuntu ARM64 bootable-USB creator for raw/Linux images and modern Windows UEFI installation ISOs."
        )
        dialog.set_website("https://github.com/geocausa/RufusArm64")
        dialog.set_license_type(Gtk.License.GPL_3_0)
        dialog.run()
        dialog.destroy()


class RufusApp(Gtk.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID)

    def do_activate(self):
        window = self.props.active_window or RufusWindow(self)
        window.show_all()
        window.present()


if __name__ == "__main__":
    raise SystemExit(RufusApp().run(None))
