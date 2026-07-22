import ast
import pathlib
import unittest


class DeviceQualificationDialogStructureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = pathlib.Path(__file__).with_name("rufusarm64_device_qualify_dialog.py").read_text(encoding="utf-8")
        tree = ast.parse(cls.source)
        qualification = next(
            node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "DeviceQualificationDialog"
        )
        cls.qualification_source = ast.get_source_segment(cls.source, qualification)

    def test_dialog_source_is_valid_python(self):
        ast.parse(self.source)

    def test_dialog_is_separate_from_create_usb(self):
        self.assertIn("class DeviceQualificationDialog(Gtk.Dialog):", self.qualification_source)
        self.assertIn("The normal Create USB workflow is not changed", self.qualification_source)
        self.assertNotIn("build_writer_command", self.qualification_source)
        self.assertNotIn("rufusarm64-helper", self.qualification_source)

    def test_plan_precedes_privileged_execution(self):
        self.assertIn("build_dry_run_command", self.qualification_source)
        self.assertIn("build_run_command", self.qualification_source)
        self.assertIn("self.refresh_plan()", self.qualification_source)
        self.assertIn("if self.running or not self.plan", self.qualification_source)

    def test_exact_erase_phrase_and_identity_are_required(self):
        self.assertIn('f"ERASE {self.device}"', self.qualification_source)
        self.assertIn("self.identity", self.qualification_source)
        self.assertIn("self.confirmation.get_text().strip() == expected", self.qualification_source)

    def test_reports_are_normalized_and_rendered(self):
        self.assertIn("normalize_plan", self.qualification_source)
        self.assertIn("normalize_report", self.qualification_source)
        self.assertIn("report_summary", self.qualification_source)
        self.assertIn("json.dumps(payload, indent=2, sort_keys=True)", self.qualification_source)

    def test_small_screen_layout_keeps_confirmation_actions_and_report_visible(self):
        self.assertIn("self.set_default_size(700, 560)", self.qualification_source)
        self.assertIn("self.set_resizable(True)", self.qualification_source)
        self.assertIn("detail_scroll = Gtk.ScrolledWindow()", self.qualification_source)
        self.assertIn("detail_box.pack_start(warning, False, False, 0)", self.qualification_source)
        self.assertIn("box.pack_start(confirm_row, False, False, 0)", self.qualification_source)
        self.assertIn("box.pack_start(actions, False, False, 0)", self.qualification_source)
        self.assertIn("result_scroll.set_min_content_height(140)", self.qualification_source)
        self.assertIn("result_scroll.set_max_content_height(220)", self.qualification_source)
        self.assertIn("box.pack_start(result_scroll, False, False, 0)", self.qualification_source)
        self.assertLess(
            self.qualification_source.index('self.add_button("Close", Gtk.ResponseType.CLOSE)'),
            self.qualification_source.index("detail_scroll = Gtk.ScrolledWindow()"),
        )

    def test_cancellation_does_not_kill_arbitrary_processes(self):
        self.assertIn("process = self.process", self.qualification_source)
        self.assertIn("process.poll() is not None", self.qualification_source)
        self.assertIn("process.terminate()", self.qualification_source)
        self.assertNotIn("os.killpg", self.qualification_source)


if __name__ == "__main__":
    unittest.main()
