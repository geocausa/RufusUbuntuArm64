import ast
import pathlib
import unittest


class FreeDOSDialogStructureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = pathlib.Path(__file__).resolve().parents[1]
        cls.dialog_source = (root / "gui" / "rufusarm64_freedos_dialog.py").read_text(encoding="utf-8")
        cls.logic_source = (root / "gui" / "rufusarm64_freedos.py").read_text(encoding="utf-8")
        cls.integrated_source = (root / "gui" / "rufusarm64_integrated.py").read_text(encoding="utf-8")
        cls.launcher_source = (root / "packaging" / "rufusarm64").read_text(encoding="utf-8")
        cls.package_source = (root / "scripts" / "build-deb.sh").read_text(encoding="utf-8")
        cls.policy_source = (root / "packaging" / "io.github.geocausa.RufusArm64.policy").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(cls.dialog_source)
        dialog_class = next(
            node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "FreeDOSFormatDialog"
        )
        cls.dialog_class_source = ast.get_source_segment(cls.dialog_source, dialog_class)

    def test_sources_parse_and_launcher_uses_composed_entry_point(self):
        ast.parse(self.dialog_source)
        ast.parse(self.logic_source)
        ast.parse(self.integrated_source)
        self.assertIn("rufusarm64_integrated", self.launcher_source)
        self.assertIn('gi.require_version("Gtk", "3.0")', self.launcher_source)
        self.assertIn("install_nonbootable(RufusWindow)", self.integrated_source)
        self.assertIn("install_freedos(RufusWindow)", self.integrated_source)

    def test_main_window_exposes_separate_freedos_action(self):
        self.assertIn('Gtk.Button(label="FreeDOS…")', self.dialog_source)
        self.assertIn("open_freedos_format", self.dialog_source)
        self.assertNotIn("build_writer_command", self.dialog_source)
        self.assertIn('self.parent_window.active_job = "freedos-format"', self.dialog_class_source)
        self.assertIn("self.parent_window.set_busy(True)", self.dialog_class_source)
        self.assertIn("self.parent_window.set_busy(False)", self.dialog_class_source)

    def test_plan_and_platform_warning_precede_authentication(self):
        self.assertIn("build_dry_run_command", self.dialog_class_source)
        self.assertIn("subprocess.run(command", self.dialog_class_source)
        self.assertIn("normalize_plan", self.dialog_class_source)
        self.assertIn("WRITE FREEDOS", self.dialog_class_source)
        self.assertIn("not boot ARM64", self.dialog_class_source)
        self.assertIn("UEFI-only", self.dialog_class_source)
        self.assertIn("build_run_command", self.dialog_class_source)
        self.assertLess(
            self.dialog_class_source.index("build_dry_run_command"),
            self.dialog_class_source.index("build_run_command"),
        )

    def test_small_screen_layout_keeps_confirmation_actions_and_report_visible(self):
        self.assertIn("self.set_default_size(780, 560)", self.dialog_class_source)
        self.assertIn("self.set_resizable(True)", self.dialog_class_source)
        self.assertIn("detail_scroll = Gtk.ScrolledWindow()", self.dialog_class_source)
        self.assertIn("detail_box.pack_start(warning, False, False, 0)", self.dialog_class_source)
        self.assertIn("box.pack_start(self.confirm_label, False, False, 0)", self.dialog_class_source)
        self.assertIn("box.pack_start(self.confirmation, False, False, 0)", self.dialog_class_source)
        self.assertIn("box.pack_start(actions, False, False, 0)", self.dialog_class_source)
        self.assertIn("result_scroll.set_max_content_height(220)", self.dialog_class_source)
        self.assertIn("box.pack_start(result_scroll, False, False, 0)", self.dialog_class_source)

    def test_graphical_execution_stays_inside_guarded_contract(self):
        self.assertIn("--expected-identity", self.logic_source)
        self.assertIn("--cancel-file", self.logic_source)
        self.assertIn("--yes", self.logic_source)
        self.assertIn("--json", self.logic_source)
        self.assertNotIn("--allow-fixed", self.logic_source)
        self.assertNotIn("--no-unmount", self.logic_source)
        self.assertIn("normalize_report(json.loads(stdout), reviewed)", self.dialog_class_source)
        self.assertIn("report status does not match", self.dialog_class_source)

    def test_cancel_marker_and_owned_process_group_are_bounded(self):
        self.assertIn("/run/user/{os.getuid()}", self.dialog_class_source)
        self.assertIn("os.O_EXCL | os.O_NOFOLLOW", self.dialog_class_source)
        self.assertIn("start_new_session=True", self.dialog_class_source)
        self.assertIn("os.killpg(process.pid, signal.SIGTERM)", self.dialog_class_source)
        self.assertIn("os.killpg(process.pid, signal.SIGKILL)", self.dialog_class_source)
        self.assertIn("waiting for the final media-state report", self.dialog_class_source)

    def test_result_keeps_exact_boot_boundary_and_refreshes_devices(self):
        self.assertIn("Verified FreeDOS media ready", self.dialog_class_source)
        self.assertIn("self.parent_window.refresh_devices()", self.dialog_class_source)
        self.assertIn("x86 BIOS", self.logic_source)
        self.assertIn("not boot ARM64", self.logic_source)
        self.assertIn("physical boot remains unproven", self.logic_source)
        self.assertIn("not reusable", self.logic_source)

    def test_full_device_progress_is_streamed_into_the_dialog(self):
        self.assertIn("decode_progress_line", self.dialog_class_source)
        self.assertIn("for line in process.stderr", self.dialog_class_source)
        self.assertIn("self._progress_ready", self.dialog_class_source)
        self.assertIn("progress_summary(progress)", self.dialog_class_source)
        self.assertNotIn("process.communicate()", self.dialog_class_source)
        self.assertIn("total device I/O", self.logic_source)

    def test_package_and_polkit_contracts_are_explicit(self):
        self.assertIn("gui/rufusarm64_freedos.py", self.package_source)
        self.assertIn("gui/rufusarm64_freedos_dialog.py", self.package_source)
        self.assertIn('id="io.github.geocausa.RufusArm64.format-freedos"', self.policy_source)
        self.assertIn("/usr/lib/rufusarm64/rufusarm64-freedos-format", self.policy_source)
        self.assertIn(
            'FREEDOS_FORMATTER = "/usr/lib/rufusarm64/rufusarm64-freedos-format"',
            self.dialog_source,
        )


if __name__ == "__main__":
    unittest.main()
