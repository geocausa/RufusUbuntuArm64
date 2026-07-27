import ast
import pathlib
import unittest


class DeviceBackupDialogStructureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = pathlib.Path(__file__).resolve().parents[1]
        cls.dialog_source = (root / "gui" / "rufusarm64_device_qualify_dialog.py").read_text(encoding="utf-8")
        cls.format_source = (root / "gui" / "rufusarm64_drive_backup_formats.py").read_text(encoding="utf-8")
        cls.iso_source = (root / "gui" / "rufusarm64_drive_backup_iso.py").read_text(encoding="utf-8")
        cls.iso_contract_source = (root / "gui" / "rufusarm64_iso_capture.py").read_text(encoding="utf-8")
        cls.launcher_source = (root / "packaging" / "rufusarm64").read_text(encoding="utf-8")
        cls.package_source = (root / "scripts" / "build-deb.sh").read_text(encoding="utf-8")
        cls.policy_source = (root / "packaging" / "io.github.geocausa.RufusArm64.policy").read_text(encoding="utf-8")
        tree = ast.parse(cls.dialog_source)
        ast.parse(cls.format_source)
        ast.parse(cls.iso_source)
        ast.parse(cls.iso_contract_source)
        backup_class = next(
            node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "DriveImageBackupDialog"
        )
        cls.backup_class_source = ast.get_source_segment(cls.dialog_source, backup_class)

    def test_sources_are_valid_and_launcher_activates_integration(self):
        ast.parse(self.dialog_source)
        ast.parse(self.format_source)
        ast.parse(self.iso_source)
        ast.parse(self.iso_contract_source)
        self.assertIn("run_rufusarm64", self.launcher_source)
        self.assertIn("install_drive_backup_formats", self.launcher_source)
        self.assertIn("install_drive_backup_iso", self.launcher_source)
        self.assertIn('exec /usr/bin/python3 -I - "$@"', self.launcher_source)
        self.assertIn('gi.require_version("Gtk", "3.0")', self.launcher_source)
        self.assertIn('sys.path.insert(0, "/usr/lib/rufusarm64")', self.launcher_source)
        self.assertIn("install_appearance(RufusWindow)", self.launcher_source)
        self.assertIn('return run_rufusarm64(["rufusarm64", *arguments])', self.launcher_source)
        self.assertNotIn("PYTHONPATH", self.launcher_source)
        self.assertNotIn("exec /usr/bin/python3 /usr/lib/rufusarm64/rufusarm64.py", self.launcher_source)

    def test_backup_is_separate_and_read_only_with_respect_to_source(self):
        self.assertIn("class DriveImageBackupDialog(Gtk.Dialog):", self.dialog_source)
        self.assertIn("source is opened read-only", self.backup_class_source)
        self.assertNotIn("ERASE", self.backup_class_source)
        self.assertNotIn("build_writer_command", self.backup_class_source)
        self.assertNotIn("destructive-action", self.backup_class_source)
        self.assertIn("dynamic sparse containers verified against the held source", self.format_source)
        self.assertIn("private read-only view", self.iso_source)
        self.assertIn("filesystem remaster, not a physical-disk image", self.iso_contract_source)

    def test_new_destination_plan_and_exact_confirmation_precede_authentication(self):
        self.assertIn("Gtk.FileChooserAction.SAVE", self.backup_class_source)
        self.assertIn("os.path.lexists", self.backup_class_source)
        self.assertIn("backup_build_dry_run_command", self.format_source)
        self.assertIn("backup_normalize_plan", self.format_source)
        self.assertIn("backup_confirmation_phrase", self.format_source)
        self.assertIn("Type exactly:", self.backup_class_source)
        self.assertIn("backup_build_run_command", self.format_source)
        self.assertIn('payload["destination"]["format"] != format_name', self.format_source)
        self.assertIn("--expected-source-node", self.iso_contract_source)
        self.assertIn("--expected-source-mount", self.iso_contract_source)
        self.assertIn("SAVE FILESYSTEM", self.iso_contract_source)

    def test_format_selector_and_filename_contract_are_explicit(self):
        self.assertIn('"raw": "Raw image (.img)"', self.format_source)
        self.assertIn('"vhd": "Dynamic VHD (.vhd)"', self.format_source)
        self.assertIn('"vhdx": "Dynamic VHDX (.vhdx)"', self.format_source)
        self.assertIn('formats._FORMAT_LABELS["iso"] = "Filesystem ISO/UDF (.iso)"', self.iso_source)
        self.assertIn('formats._FORMAT_EXTENSIONS["iso"] = ".iso"', self.iso_source)
        self.assertIn("dialog.format_selector = Gtk.ComboBoxText()", self.format_source)
        self.assertIn("dialog.format_selector.set_sensitive(not dialog.running)", self.format_source)
        self.assertIn("if not filename.lower().endswith(extension)", self.format_source)
        self.assertIn("filename += extension", self.format_source)

    def test_small_screen_layout_keeps_confirmation_actions_and_report_visible(self):
        self.assertIn("self.set_default_size(760, 560)", self.backup_class_source)
        self.assertIn("self.set_resizable(True)", self.backup_class_source)
        self.assertIn("detail_scroll = Gtk.ScrolledWindow()", self.backup_class_source)
        self.assertIn("detail_box.pack_start(note, False, False, 0)", self.backup_class_source)
        self.assertIn("box.pack_start(self.confirm_label, False, False, 0)", self.backup_class_source)
        self.assertIn("box.pack_start(self.confirmation, False, False, 0)", self.backup_class_source)
        self.assertIn("box.pack_start(actions, False, False, 0)", self.backup_class_source)
        self.assertIn("result_scroll.set_max_content_height(220)", self.backup_class_source)
        self.assertIn("box.pack_start(result_scroll, False, False, 0)", self.backup_class_source)
        self.assertIn("details.reorder_child(row, 1)", self.format_source)

    def test_progress_final_report_and_destination_are_revalidated(self):
        self.assertIn("start_new_session=True", self.format_source)
        self.assertIn("backup_decode_progress_line", self.format_source)
        self.assertIn("last_by_phase", self.format_source)
        self.assertIn("phase in _SOURCE_PHASES", self.format_source)
        self.assertIn("backup_normalize_report", self.format_source)
        self.assertIn("os.lstat(dialog.output_path)", self.format_source)
        self.assertIn("stat.S_ISREG", self.format_source)
        self.assertIn('info.st_size != payload["output_bytes"]', self.format_source)
        self.assertIn("info.st_uid != os.getuid()", self.format_source)
        self.assertIn("Backup report status does not match", self.format_source)
        self.assertIn("source SHA-256", (pathlib.Path(__file__).resolve().parents[1] / "gui" / "rufusarm64_device_qualify.py").read_text(encoding="utf-8"))
        self.assertIn("decode_progress_line", self.iso_source)
        self.assertIn("normalize_report", self.iso_source)
        self.assertIn("source_mount", self.iso_source)
        self.assertIn("info.st_uid != os.getuid()", self.iso_source)
        self.assertIn("No physical-disk", self.iso_contract_source)

    def test_cancel_and_close_target_only_the_owned_process_group(self):
        self.assertIn("os.killpg(process.pid, signal.SIGTERM)", self.backup_class_source)
        self.assertIn("GLib.timeout_add_seconds(5, self._force_kill, process)", self.backup_class_source)
        self.assertIn("os.killpg(process.pid, signal.SIGKILL)", self.backup_class_source)
        self.assertIn("if self.process is process and process.poll() is None", self.backup_class_source)
        self.assertIn("def _terminate_and_reap(process):", self.backup_class_source)
        self.assertIn("process.communicate(timeout=5)", self.backup_class_source)
        self.assertIn("Closing requested. Cancelling", self.backup_class_source)
        self.assertIn("dialog._terminate_and_reap(process)", self.format_source)
        self.assertIn("dialog._terminate_and_reap(process)", self.iso_source)

    def test_main_window_busy_state_and_refresh_are_mutually_exclusive(self):
        self.assertIn('Gtk.Button(label="Save drive image…")', self.dialog_source)
        self.assertIn('self.parent_window.active_job = "backup"', self.backup_class_source)
        self.assertIn("self.parent_window.set_busy(True)", self.backup_class_source)
        self.assertIn("self.parent_window.set_busy(False)", self.backup_class_source)
        self.assertIn("self.parent_window.refresh_devices()", self.backup_class_source)
        self.assertIn("not window.busy and not window.device_refreshing", self.dialog_source)

    def test_package_and_privilege_contracts_remain_explicit(self):
        self.assertIn("gui/rufusarm64_device_qualify.py", self.package_source)
        self.assertIn("gui/rufusarm64_device_qualify_dialog.py", self.package_source)
        self.assertIn("gui/rufusarm64_drive_backup_formats.py", self.package_source)
        self.assertIn("gui/rufusarm64_iso_capture.py", self.package_source)
        self.assertIn("gui/rufusarm64_drive_backup_iso.py", self.package_source)
        self.assertIn("genisoimage", self.package_source)
        self.assertIn("rufusarm64-device-backup", self.package_source)
        self.assertIn('id="io.github.geocausa.RufusArm64.backup"', self.policy_source)
        self.assertIn("/usr/lib/rufusarm64/rufusarm64-device-backup", self.policy_source)


if __name__ == "__main__":
    unittest.main()
