import pathlib
import unittest


class WindowsBIOSCapabilitySourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = pathlib.Path("gui/rufusarm64.py").read_text(encoding="utf-8")

    def test_analysis_requires_resolved_layout(self):
        self.assertIn('payload.get("default_partition_scheme")', self.source)
        self.assertIn('payload.get("default_target_system")', self.source)
        self.assertIn('default_scheme not in {"gpt", "mbr"}', self.source)
        self.assertIn('default_target not in {"uefi", "bios"}', self.source)

    def test_options_dialog_discloses_automatic_layout(self):
        self.assertIn('Automatic layout: {scheme}/{target}.', self.source)
        self.assertIn('self.capability_analysis.get("default_partition_scheme")', self.source)
        self.assertIn('self.capability_analysis.get("default_target_system")', self.source)

    def test_destructive_summary_uses_resolved_layout(self):
        self.assertIn('display_scheme = partition_scheme', self.source)
        self.assertIn('display_target = target_system', self.source)
        self.assertIn('self.windows_capability_analysis.get("default_partition_scheme")', self.source)
        self.assertIn('self.windows_capability_analysis.get("default_target_system")', self.source)


if __name__ == "__main__":
    unittest.main()
