#!/usr/bin/env python3
from pathlib import Path
import re

path = Path("gui/rufusarm64.py")
text = path.read_text(encoding="utf-8")


def literal(old, new):
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected one literal match, found {count}")
    text = text.replace(old, new, 1)


def methods(start, end, replacement):
    global text
    pattern = rf"(?ms)^    def {re.escape(start)}\(.*?(?=^    def {re.escape(end)}\()"
    text, count = re.subn(pattern, replacement.rstrip() + "\n\n", text, count=1)
    if count != 1:
        raise SystemExit(f"expected one method range {start}..{end}, found {count}")


literal(
    "        self.busy = False\n        self.cancel_requested = False\n",
    "        self.busy = False\n        self.closed = False\n        self.inspection_generation = 0\n        self.inspection_running = False\n        self.device_generation = 0\n        self.device_refreshing = False\n        self.cancel_requested = False\n",
)
literal(
    '''    def set_busy(self, busy):
        self.busy = bool(busy)
        usable = not busy and bool(self.devices) and bool(self.inspection.get("recognized"))
        self.start_button.set_sensitive(usable)
        for widget in (self.image_chooser, self.download_button, self.target_combo, self.refresh_button, self.verify, self.open_persistence_button):
            widget.set_sensitive(not busy)
        self.persistence_button.set_sensitive(
            not busy
            and bool(self.devices)
            and bool(self.inspection.get("recognized"))
            and self.inspection.get("mode") == "raw"
        )
''',
    '''    def set_busy(self, busy):
        self.busy = bool(busy)
        background_idle = not self.inspection_running and not self.device_refreshing
        usable = not busy and background_idle and bool(self.devices) and bool(self.inspection.get("recognized"))
        self.start_button.set_sensitive(usable)
        for widget in (self.image_chooser, self.download_button, self.target_combo, self.verify, self.open_persistence_button):
            widget.set_sensitive(not busy)
        self.refresh_button.set_sensitive(not busy and not self.device_refreshing)
        self.persistence_button.set_sensitive(
            not busy
            and background_idle
            and bool(self.devices)
            and bool(self.inspection.get("recognized"))
            and self.inspection.get("mode") == "raw"
        )
''',
)
methods(
    "on_delete_event",
    "update_layout",
    '''    def on_delete_event(self, *_):
        if self.busy:
            self.message(
                "An operation is still running. Click Cancel and wait for RufusArm64 to confirm it has stopped before closing the window.",
                Gtk.MessageType.WARNING,
            )
            return True
        self.closed = True
        self.inspection_generation += 1
        self.device_generation += 1
        self.save_settings()
        return False

    def image_changed(self, *_):
        path = self.image_chooser.get_filename()
        self.inspection_generation += 1
        generation = self.inspection_generation
        self.inspection_running = False
        self.inspection = {}
        self.windows_options = {}
        if not path:
            self.update_layout({})
            self.set_busy(self.busy)
            return
        if not supported_image_name(path):
            self.update_layout({"description": "Unsupported filename", "recognized": False})
            self.set_busy(self.busy)
            return
        self.inspection_running = True
        self.update_layout({"description": "Inspecting image…", "recognized": False})
        self.set_busy(self.busy)
        threading.Thread(target=self._run_image_inspection, args=(path, generation), daemon=True).start()

    def _run_image_inspection(self, path, generation):
        inspection = {}
        try:
            result = subprocess.run(
                [helper_path(), "inspect", "--image", path, "--json"],
                check=False,
                text=True,
                capture_output=True,
                timeout=20,
            )
            if result.stdout.strip():
                inspection = json.loads(result.stdout)
            if result.returncode != 0 and not inspection:
                raise RuntimeError(result.stderr.strip() or "Image inspection failed")
        except Exception as exc:
            inspection = {"recognized": False, "description": str(exc)}
        GLib.idle_add(self._finish_image_inspection, path, generation, inspection)

    def _finish_image_inspection(self, path, generation, inspection):
        if self.closed or generation != self.inspection_generation or self.image_chooser.get_filename() != path:
            return False
        self.inspection_running = False
        self.inspection = inspection
        self.update_layout(inspection)
        self.set_busy(self.busy)
        return False''',
)
methods(
    "refresh_devices",
    "choose_windows_options",
    '''    def refresh_devices(self):
        if self.busy or self.device_refreshing or self.closed:
            return
        self.device_generation += 1
        generation = self.device_generation
        self.device_refreshing = True
        self.target_combo.remove_all()
        self.devices = []
        self.progress.set_text("Scanning removable drives…")
        self.set_busy(self.busy)
        threading.Thread(target=self._run_device_refresh, args=(generation,), daemon=True).start()

    def _run_device_refresh(self, generation):
        devices = []
        error = ""
        try:
            result = subprocess.run([helper_path(), "list", "--json"], check=True, text=True, capture_output=True, timeout=15)
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
        self.target_combo.remove_all()
        for device in self.devices:
            self.target_combo.append_text(device_label(device))
        if error:
            self.append_log(f"Could not list USB drives: {error}")
            self.progress.set_text("Drive detection failed")
        elif self.devices:
            self.target_combo.set_active(0)
            self.progress.set_text("Ready")
        else:
            self.progress.set_text("No removable USB drive found")
        self.set_busy(self.busy)
        return False''',
)
path.write_text(text, encoding="utf-8")
