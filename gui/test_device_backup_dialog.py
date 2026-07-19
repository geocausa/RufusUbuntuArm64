import ast
import pathlib
import unittest


class DeviceBackupDialogStructureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = pathlib.Path(__file__).resolve().parents[1]
        cls.dialog_source = (root / "gui" / "rufusarm64_device_qualify_dialog.py").read_text(encoding="utf-8")
        cls.launcher_source = (root / "packaging" / "rufusarm64").read_text(encoding="utf-8")
        cls.package_source = (root / "scripts" / "build-deb.sh").read_text(encoding="utf-8")
        cls.policy_source = (root / "packaging" / "io.github.geocausa.RufusArm64.policy").read_text(encoding="utf-8")
        tree = ast.parse(cls.dialog_source)
        backup_class = next(
            node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "DriveImageBackupDialog"
        )
        cls.backup_class_source = ast.get_source_segment(cls.dialog_source, backup_class)

    def test_sources_are_valid_and_launcher_activates_integration(self):
        ast.parse(self.dialog_source)
        self.assertIn("run_rufusarm64", self.launcher_source)
        self.assertIn("/usr/bin/python3 -I -c", self.launcher_source)
        self.assertIn('sys.path.insert(0, "/usr/lib/rufusarm64")', self.launcher_source)
        self.assertIn('run_rufusarm64(["rufusarm64", *sys.argv[1:]])', self.launcher_source)
        self.assertNotIn("PYTHONPATH", self.launcher_source)
        self.assertNotIn("exec /usr/bin/python3 /usr/lib/rufusarm64/rufusarm64.py", self.launcher_source)

    def test_backup_is_separate_and_read_only_with_respect_to_source(self):
        self.assertIn("class DriveImageBackupDialog(Gtk.Dialog):", self.dialog_source)
        self.assertIn("source is opened read-only", self.backup_class_source)
        self.assertNotIn("ERASE", self.backup_class_source)
        self.assertNotIn("build_writer_command", self.backup_class_source)
        self.assertNotIn("destructive-action", self.backup_class_source)

    def test_new_destination_plan_and_exact_confirmation_precede_authentication(self):
        self.assertIn("Gtk.FileChooserAction.SAVE", self.backup_class_source)
        self.assertIn("os.path.lexists", self.backup_class_source)
        self.assertIn("backup_build_dry_run_command", self.backup_class_source)
        self.assertIn("backup_plan_summary", self.backup_class_source)
        self.assertIn("backup_confirmation_phrase", self.backup_class_source)
        self.assertIn("Type exactly:", self.backup_class_source)
        self.assertIn("backup_build_run_command", self.backup_class_source)

    def test_progress_final_report_and_destination_are_revalidated(self):
        self.assertIn("start_new_session=True", self.backup_class_source)
        self.assertIn("backup_decode_progress_line", self.backup_class_source)
        self.assertIn("progress[\"total\"] != planned", self.backup_class_source)
        self.assertIn("backup_normalize_report", self.backup_class_source)
        self.assertIn("os.lstat(self.output_path)", self.backup_class_source)
        self.assertIn("stat.S_ISREG", self.backup_class_source)
        self.assertIn("SHA-256", self.dialog_source)

    def test_cancel_and_close_target_only_the_owned_process_group(self):
        self.assertIn("os.killpg(process.pid, signal.SIGTERM)", self.backup_class_source)
        self.assertIn("GLib.timeout_add_seconds(5, self._force_kill, process)", self.backup_class_source)
        self.assertIn("os.killpg(process.pid, signal.SIGKILL)", self.backup_class_source)
        self.assertIn("if self.process is process and process.poll() is None", self.backup_class_source)
        self.assertIn("Closing requested. Cancelling", self.backup_class_source)

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
        self.assertIn("rufusarm64-device-backup", self.package_source)
        self.assertIn('id="io.github.geocausa.RufusArm64.backup"', self.policy_source)
        self.assertIn("/usr/lib/rufusarm64/rufusarm64-device-backup", self.policy_source)


if __name__ == "__main__":
    unittest.main()
