#!/usr/bin/env python3
import pathlib

root = pathlib.Path(__file__).resolve().parents[1]
path = root / "gui/rufusarm64.py"
text = path.read_text()

old_busy = '''    def set_busy(self, busy):
        self.busy = bool(busy)
        background_idle = not self.inspection_running and not self.device_refreshing
        usable = not busy and background_idle and bool(self.devices) and bool(self.inspection.get("recognized"))
        self.start_button.set_sensitive(usable)
        for widget in (
            self.image_chooser,
            self.download_button,
            self.target_combo,
            self.verify,
            self.open_persistence_button,
            self.uefi_validation_button,
        ):
            widget.set_sensitive(not busy)
        selected_image = self.image_chooser.get_filename() or ""
        self.checksum_button.set_sensitive(
            not busy and background_idle and bool(selected_image) and os.path.isfile(selected_image)
        )
        self.refresh_button.set_sensitive(not busy and not self.device_refreshing)
        self.persistence_button.set_sensitive(
            not busy
            and background_idle
            and bool(self.devices)
            and bool(self.inspection.get("recognized"))
            and self.inspection.get("mode") == "raw"
        )
        windows_controls = not busy and self.inspection.get("mode") == "windows"
        for widget in (self.partition_combo, self.target_system_combo, self.filesystem_combo, self.cluster_combo, self.volume_label, self.driver_chooser, self.dbx_chooser, self.dbx_update_button, self.quick_format, self.bad_block_check):
            widget.set_sensitive(windows_controls)
        if not busy:
            self.bad_block_toggled()
        self.cancel_button.set_sensitive(busy and self.active_job in {"writer", "download", "persistence-plan"})
'''
new_busy = '''    def set_busy(self, busy):
        self.busy = bool(busy)
        background_idle = not self.inspection_running and not self.device_refreshing
        for widget in (self.image_chooser, self.target_combo, self.uefi_validation_button):
            widget.set_sensitive(not busy)
        # Direct operating-system downloads are intentionally not implemented.
        self.download_button.set_sensitive(False)
        selected_image = self.image_chooser.get_filename() or ""
        self.checksum_button.set_sensitive(
            not busy and background_idle and bool(selected_image) and os.path.isfile(selected_image)
        )
        self.refresh_button.set_sensitive(not busy and not self.device_refreshing)
        windows_controls = not busy and self.inspection.get("mode") == "windows"
        for widget in (self.partition_combo, self.target_system_combo, self.filesystem_combo, self.cluster_combo, self.volume_label, self.driver_chooser, self.dbx_chooser, self.dbx_update_button, self.quick_format, self.bad_block_check):
            widget.set_sensitive(windows_controls)
        if not busy:
            self.bad_block_toggled()
        self.update_layout(self.inspection)
        self.cancel_button.set_sensitive(busy and self.active_job in {"writer", "download", "persistence-plan"})
'''
if text.count(old_busy) != 1:
    raise SystemExit(f"set_busy anchor count {text.count(old_busy)}")
text = text.replace(old_busy, new_busy, 1)

old_ready = '''        raw_ready = bool(self.devices) and bool(info.get("recognized")) and info.get("mode") == "raw"
        persistence_on = self.persistence_enabled.get_active()
        self.persistence_enabled.set_sensitive(not self.busy and raw_ready)
'''
new_ready = '''        raw_ready = bool(self.devices) and bool(info.get("recognized")) and info.get("mode") == "raw"
        persistence_on = self.persistence_enabled.get_active()
        if persistence_on and not raw_ready:
            self.persistence_enabled.set_active(False)
            persistence_on = False
            self.persistence_plan = None
            self.persistence_plan_key = None
            self.persistence_source_identity = ""
        self.persistence_enabled.set_sensitive(not self.busy and raw_ready)
'''
if text.count(old_ready) != 1:
    raise SystemExit(f"raw-ready anchor count {text.count(old_ready)}")
text = text.replace(old_ready, new_ready, 1)
path.write_text(text)

test = root / "gui/test_unified_persistence_ui.py"
source = test.read_text()
insert = '''
    def test_busy_state_cannot_reenable_download_or_reference_removed_button(self):
        self.assertNotIn("self.open_persistence_button", self.source)
        self.assertIn("self.download_button.set_sensitive(False)", self.source)
        self.assertNotIn("self.download_button,\\n", self.source)

    def test_unsupported_image_turns_persistence_off(self):
        self.assertIn("if persistence_on and not raw_ready:", self.source)
        self.assertIn("self.persistence_enabled.set_active(False)", self.source)
'''
anchor = '\n\nif __name__ == "__main__":'
if source.count(anchor) != 1:
    raise SystemExit("test insertion anchor missing")
test.write_text(source.replace(anchor, insert + anchor, 1))
