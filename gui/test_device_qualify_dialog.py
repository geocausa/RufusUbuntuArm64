import pathlib
import unittest


class DeviceQualificationDialogStructureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = pathlib.Path(__file__).with_name("rufusarm64_device_qualify_dialog.py").read_text(encoding="utf-8")

    def test_dialog_is_separate_from_create_usb(self):
        self.assertIn("class DeviceQualificationDialog(Gtk.Dialog):", self.source)
        self.assertIn("The normal Create USB workflow is not changed", self.source)
        self.assertNotIn("build_writer_command", self.source)
        self.assertNotIn("rufusarm64-helper", self.source)

    def test_plan_precedes_privileged_execution(self):
        self.assertIn("build_dry_run_command", self.source)
        self.assertIn("build_run_command", self.source)
        self.assertIn("self.refresh_plan()", self.source)
        self.assertIn("if self.running or not self.plan", self.source)

    def test_exact_erase_phrase_and_identity_are_required(self):
        self.assertIn('f"ERASE {self.device}"', self.source)
        self.assertIn("self.identity", self.source)
        self.assertIn("self.confirmation.get_text().strip() == expected", self.source)

    def test_reports_are_normalized_and_rendered(self):
        self.assertIn("normalize_plan", self.source)
        self.assertIn("normalize_report", self.source)
        self.assertIn("report_summary", self.source)
        self.assertIn("json.dumps(payload, indent=2, sort_keys=True)", self.source)

    def test_cancellation_does_not_kill_arbitrary_processes(self):
        self.assertIn("process = self.process", self.source)
        self.assertIn("process.poll() is not None", self.source)
        self.assertIn("process.terminate()", self.source)
        self.assertNotIn("os.killpg", self.source)


if __name__ == "__main__":
    unittest.main()
