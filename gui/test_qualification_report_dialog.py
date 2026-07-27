import ast
import pathlib
import unittest


class QualificationReportDialogStructureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = pathlib.Path(__file__).resolve().parents[1]
        cls.dialog_source = (root / "gui" / "rufusarm64_device_qualify_dialog.py").read_text(encoding="utf-8")
        cls.package_source = (root / "scripts" / "build-deb.sh").read_text(encoding="utf-8")
        tree = ast.parse(cls.dialog_source)
        qualification_class = next(
            node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "DeviceQualificationDialog"
        )
        cls.qualification_source = ast.get_source_segment(cls.dialog_source, qualification_class)

    def test_report_export_is_explicit_and_available_only_after_a_report(self):
        self.assertIn('Gtk.Button(label="Save report…")', self.qualification_source)
        self.assertIn("self.report_payload = None", self.qualification_source)
        self.assertIn("self.save_report_button.set_sensitive", self.qualification_source)
        self.assertIn("self.report_payload is not None", self.qualification_source)
        self.assertIn("transport_mismatch", self.qualification_source)
        self.assertIn("None if transport_mismatch else payload", self.qualification_source)
        self.assertIn("not transport_mismatch", self.qualification_source)

    def test_report_export_uses_new_file_and_identity_bound_helper(self):
        self.assertIn("Gtk.FileChooserAction.SAVE", self.qualification_source)
        self.assertIn("os.path.lexists(filename)", self.qualification_source)
        self.assertIn("save_new_qualification_report(", self.qualification_source)
        self.assertIn("self.device", self.qualification_source)
        self.assertIn("self.identity", self.qualification_source)
        self.assertIn("self.report_payload", self.qualification_source)

    def test_export_module_is_packaged_and_dialog_sources_parse(self):
        ast.parse(self.dialog_source)
        self.assertIn("gui/rufusarm64_qualification_report.py", self.package_source)
        self.assertIn("rufusarm64_qualification_report.py", self.package_source)


if __name__ == "__main__":
    unittest.main()
