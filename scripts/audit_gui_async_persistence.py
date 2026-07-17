#!/usr/bin/env python3
from pathlib import Path
import re

path = Path("gui/rufusarm64_persistence.py")
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
    "        self.busy = False\n        self.job = \"\"\n",
    "        self.busy = False\n        self.closed = False\n        self.device_generation = 0\n        self.device_refreshing = False\n        self.job = \"\"\n",
)
methods(
    "refresh_devices",
    "new_cancel_path",
    '''    def refresh_devices(self):
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
    def new_cancel_path():''',
)
literal(
    '''    def set_busy(self, busy, job=""):
        self.busy = busy
        self.job = job if busy else ""
        for widget in (self.image, self.target, self.refresh_button, self.size, self.volume_label, self.analyze_button):
            widget.set_sensitive(not busy)
        self.create_button.set_sensitive(not busy and self.plan is not None and self.plan_key is not None)
        self.cancel_button.set_sensitive(busy)
''',
    '''    def set_busy(self, busy, job=""):
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
''',
)
literal(
    '''    def on_delete(self, *_):
        if self.busy:
            self.message("An operation is running. Cancel it and wait for cleanup before closing.", Gtk.MessageType.WARNING)
            return True
        return False
''',
    '''    def on_delete(self, *_):
        if self.busy:
            self.message("An operation is running. Cancel it and wait for cleanup before closing.", Gtk.MessageType.WARNING)
            return True
        self.closed = True
        self.device_generation += 1
        return False
''',
)
path.write_text(text, encoding="utf-8")
