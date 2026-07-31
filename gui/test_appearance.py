import pathlib
import unittest


class AppearanceStructureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = pathlib.Path(__file__).resolve().parents[1]
        cls.source = (root / "gui" / "rufusarm64.py").read_text(encoding="utf-8")
        cls.logic = (root / "gui" / "rufusarm64_logic.py").read_text(encoding="utf-8")

    def test_explicit_modes_are_persisted_and_visible(self):
        for fragment in (
            'APPEARANCE_MODES = ("system", "light", "dark")',
            'self.appearance_combo.append("system", "Follow desktop")',
            'self.appearance_combo.append("light", "Light")',
            'self.appearance_combo.append("dark", "Dark")',
            'self.settings["appearance"]',
        ):
            self.assertIn(fragment, self.source + self.logic)

    def test_system_mode_restores_original_desktop_preference(self):
        self.assertIn('self._desktop_dark_preference', self.source)
        self.assertIn('if mode == "system" else mode == "dark"', self.source)
        self.assertNotIn('gtk-theme-name', self.source)
        self.assertNotIn('Adwaita-dark', self.source)

    def test_theme_change_is_app_wide_and_non_destructive(self):
        self.assertIn('Gtk.Settings.get_default()', self.source)
        self.assertIn('gtk-application-prefer-dark-theme', self.source)
        for forbidden in ('pkexec', '--yes', '--allow-fixed', '--no-unmount'):
            self.assertNotIn(forbidden, self.source[self.source.index('class RufusApp'):])


if __name__ == "__main__":
    unittest.main()
