import pathlib
import unittest


class WindowsQualityOfLifeUISourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gui = pathlib.Path("gui/rufusarm64.py").read_text(encoding="utf-8")
        cls.cli = pathlib.Path("cmd/rufus-linux/main.go").read_text(encoding="utf-8")

    def test_checkbox_is_explicit_and_discloses_removals(self):
        self.assertIn("Apply Rufus Quality of Life changes", self.gui)
        for item in ("OneDrive", "Outlook", "Teams", "Copilot"):
            self.assertIn(item, self.gui)
        self.assertIn('previous.get("quality_of_life", False)', self.gui)

    def test_capability_and_summary_are_wired(self):
        self.assertIn('apply_option_capability(self.quality_of_life, "quality_of_life")', self.gui)
        self.assertIn('"quality_of_life": self.quality_of_life.get_active()', self.gui)
        self.assertIn('Quality of Life app removals and policies', self.gui)

    def test_cli_flag_is_explicit_and_default_off(self):
        self.assertIn('fs.Bool("win-quality-of-life", false', self.cli)
        self.assertIn('QualityOfLife:        *winQualityOfLife', self.cli)


if __name__ == "__main__":
    unittest.main()
