import pathlib
import unittest


class UnifiedPersistenceUISourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = pathlib.Path("gui/rufusarm64.py").read_text(encoding="utf-8")

    def test_download_is_disabled_and_not_connected(self):
        self.assertIn('Gtk.Button(label="Download unavailable")', self.source)
        self.assertIn('self.download_button.set_sensitive(False)', self.source)
        self.assertNotIn('self.download_button.connect("clicked", self.open_acquisition)', self.source)

    def test_persistence_stays_in_main_window(self):
        self.assertIn('Gtk.Expander(label="Persistent storage")', self.source)
        self.assertIn('Keep files and settings across reboots', self.source)
        self.assertNotIn('Open Persistent USB Creator…', self.source)
        self.assertNotIn('subprocess.Popen([persistence_launcher_path()]', self.source)

    def test_same_start_path_uses_restricted_helper(self):
        self.assertIn('build_persistence_create_command(', self.source)
        self.assertIn('PERSISTENCE_HELPER', self.source)
        self.assertIn('self.active_mode = "linux-persistent"', self.source)
        self.assertIn('completion_checklist()', self.source)
        self.assertNotIn('self.apply_inspection(', self.source)
        self.assertGreaterEqual(self.source.count('self.update_layout(self.inspection)'), 2)

    def test_busy_state_cannot_reenable_download_or_reference_removed_button(self):
        self.assertNotIn("self.open_persistence_button", self.source)
        self.assertIn("self.download_button.set_sensitive(False)", self.source)
        self.assertNotIn("self.download_button,\n", self.source)

    def test_unsupported_image_turns_persistence_off(self):
        self.assertIn("if persistence_on and not raw_ready:", self.source)
        self.assertIn("self.persistence_enabled.set_active(False)", self.source)

    def test_persistence_helper_is_checked_before_launch(self):
        self.assertIn("persistence_requested and not os.access(PERSISTENCE_HELPER, os.X_OK)", self.source)
        self.assertIn("package-owned persistence helper is not installed or executable", self.source)

    def test_layout_fstring_uses_python_310_compatible_quotes(self):
        self.assertIn("self.persistence_plan['size']", self.source)


if __name__ == "__main__":
    unittest.main()
