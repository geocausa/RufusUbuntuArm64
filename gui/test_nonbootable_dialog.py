import ast
import pathlib
import unittest


class NonBootableDialogStructureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = pathlib.Path(__file__).resolve().parents[1]
        cls.dialog_source = (root / "gui" / "rufusarm64_nonbootable_dialog.py").read_text(encoding="utf-8")
        cls.logic_source = (root / "gui" / "rufusarm64_nonbootable.py").read_text(encoding="utf-8")
        cls.integrated_source = (root / "gui" / "rufusarm64_integrated.py").read_text(encoding="utf-8")
        cls.launcher_source = (root / "packaging" / "rufusarm64").read_text(encoding="utf-8")
        cls.package_source = (root / "scripts" / "build-deb.sh").read_text(encoding="utf-8")
        cls.policy_source = (root / "packaging" / "io.github.geocausa.RufusArm64.policy").read_text(encoding="utf-8")
        tree = ast.parse(cls.dialog_source)
        dialog_class = next(
            node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "NonBootableFormatDialog"
        )
        cls.dialog_class_source = ast.get_source_segment(cls.dialog_source, dialog_class)

    def test_sources_parse_and_launcher_uses_composed_entry_point(self):
        ast.parse(self.dialog_source)
        ast.parse(self.logic_source)
        ast.parse(self.integrated_source)
        self.assertIn("rufusarm64_integrated", self.launcher_source)
        self.assertIn('gi.require_version("Gtk", "3.0")', self.launcher_source)
        self.assertIn("install_drive_backup(RufusWindow)", self.integrated_source)
        self.assertIn("install_nonbootable(RufusWindow)", self.integrated_source)

    def test_main_window_exposes_separate_non_bootable_action(self):
        self.assertIn('Gtk.Button(label="Non bootable…")', self.dialog_source)
        self.assertIn("open_nonbootable_format", self.dialog_source)
        self.assertNotIn("build_writer_command", self.dialog_source)
        self.assertIn('self.parent_window.active_job = "nonbootable-format"', self.dialog_class_source)
        self.assertIn("self.parent_window.set_busy(True)", self.dialog_class_source)
        self.assertIn("self.parent_window.set_busy(False)", self.dialog_class_source)

    def test_unprivileged_plan_and_exact_confirmation_precede_authentication(self):
        self.assertIn("build_dry_run_command", self.dialog_class_source)
        self.assertIn("subprocess.run(command", self.dialog_class_source)
        self.assertIn("normalize_plan", self.dialog_class_source)
        self.assertIn("Type exactly:", self.dialog_class_source)
        self.assertIn("confirmation_phrase", self.dialog_class_source)
        self.assertIn("build_run_command", self.dialog_class_source)
        self.assertLess(
            self.dialog_class_source.index("build_dry_run_command"),
            self.dialog_class_source.index("build_run_command"),
        )

    def test_graphical_execution_stays_inside_guarded_cli_contract(self):
        self.assertIn("--expected-identity", self.logic_source)
        self.assertIn("--cancel-file", self.logic_source)
        self.assertIn("--yes", self.logic_source)
        self.assertIn("--json", self.logic_source)
        self.assertNotIn("--allow-fixed", self.logic_source)
        self.assertNotIn("--no-unmount", self.logic_source)
        self.assertIn("normalize_report(json.loads(stdout), reviewed)", self.dialog_class_source)
        self.assertIn("Formatting report status does not match", self.dialog_class_source)

    def test_cancel_marker_and_owned_process_group_are_bounded(self):
        self.assertIn("/run/user/{os.getuid()}", self.dialog_class_source)
        self.assertIn("os.O_EXCL | os.O_NOFOLLOW", self.dialog_class_source)
        self.assertIn("start_new_session=True", self.dialog_class_source)
        self.assertIn("os.killpg(process.pid, signal.SIGTERM)", self.dialog_class_source)
        self.assertIn("os.killpg(process.pid, signal.SIGKILL)", self.dialog_class_source)
        self.assertIn("waiting for the final media-state report", self.dialog_class_source)

    def test_result_never_claims_bootability_and_refreshes_devices(self):
        self.assertIn("explicitly does not claim the result is bootable", self.dialog_class_source)
        self.assertIn("Verified data-only media ready", self.dialog_class_source)
        self.assertIn("self.parent_window.refresh_devices()", self.dialog_class_source)
        self.assertIn("media_changed", self.logic_source)
        self.assertIn("must be reformatted", self.logic_source)

    def test_package_and_polkit_contracts_are_explicit(self):
        self.assertIn("gui/rufusarm64_nonbootable.py", self.package_source)
        self.assertIn("gui/rufusarm64_nonbootable_dialog.py", self.package_source)
        self.assertIn("gui/rufusarm64_integrated.py", self.package_source)
        self.assertIn('id="io.github.geocausa.RufusArm64.format-data"', self.policy_source)
        self.assertIn("/usr/lib/rufusarm64/rufusarm64-nonbootable-format", self.policy_source)
        self.assertIn('NONBOOTABLE_FORMATTER = "/usr/lib/rufusarm64/rufusarm64-nonbootable-format"', self.dialog_source)


if __name__ == "__main__":
    unittest.main()
