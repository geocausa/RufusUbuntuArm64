import ast
import pathlib
import unittest


class VerifiedAcquisitionUIStructureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = pathlib.Path(__file__).resolve().parents[1]
        cls.integrated_source = (root / "gui" / "rufusarm64_integrated.py").read_text(encoding="utf-8")
        cls.main_source = (root / "gui" / "rufusarm64.py").read_text(encoding="utf-8")
        cls.logic_source = (root / "gui" / "rufusarm64_logic.py").read_text(encoding="utf-8")
        cls.channel_config = (root / "packaging" / "acquisition" / "channel.json").read_text(encoding="utf-8")
        tree = ast.parse(cls.integrated_source)
        installer = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "install_verified_acquisition"
        )
        cls.installer_source = ast.get_source_segment(cls.integrated_source, installer)

    def test_composed_entry_point_enables_existing_verified_dialog(self):
        self.assertIn('set_label("Download…")', self.installer_source)
        self.assertIn('connect("clicked", window.open_acquisition)', self.installer_source)
        self.assertIn("install_verified_acquisition(RufusWindow)", self.integrated_source)
        self.assertIn("class AcquisitionDialog(Gtk.Dialog)", self.main_source)
        self.assertIn("normalize_acquisition_channel", self.main_source)
        self.assertIn("normalize_acquisition_images", self.main_source)

    def test_every_gui_download_is_resumable(self):
        self.assertIn('"build_acquisition_channel_download_command"', self.installer_source)
        self.assertIn('"build_acquisition_download_command"', self.installer_source)
        self.assertIn('command.append("--resume")', self.integrated_source)
        self.assertIn('"--json", "--json-progress"', self.logic_source)
        self.assertNotIn("--replace", self.installer_source)

    def test_cancellation_and_failure_never_claim_partial_is_installed(self):
        self.assertIn("private signed-catalog partial was retained for automatic resume", self.installer_source)
        self.assertIn("No unverified image was installed", self.installer_source)
        self.assertIn("original_finish_download(window, return_code, payload)", self.installer_source)
        self.assertIn("os.killpg(process.pid, signal.SIGTERM)", self.main_source)
        self.assertIn('self.active_job = "download"', self.main_source)

    def test_busy_state_disables_acquisition_and_idle_state_reenables_it(self):
        self.assertIn("background_idle = not window.inspection_running and not window.device_refreshing", self.installer_source)
        self.assertIn("window.download_button.set_sensitive(not busy and background_idle)", self.installer_source)
        self.assertIn('self.cancel_button.set_sensitive(busy and self.active_job in {"writer", "download", "persistence-plan"})', self.main_source)

    def test_existing_core_keeps_signed_catalog_and_storage_preflight_boundaries(self):
        self.assertIn("threshold-signed root and catalog metadata", self.main_source)
        self.assertIn("No unsigned bypass is offered", self.main_source)
        self.assertIn("The final file will be installed only after its signed size and SHA-256 match", self.main_source)
        self.assertIn('"enabled":false', self.channel_config)
        self.assertNotIn("private-key", self.integrated_source.lower())
        self.assertNotIn("pkexec", self.integrated_source.lower())
        self.assertNotIn("subprocess", self.integrated_source)

    def test_downloaded_verified_image_returns_to_normal_inspection(self):
        self.assertIn("self.image_chooser.set_filename(path)", self.main_source)
        self.assertIn("self.image_changed()", self.main_source)
        self.assertIn("resumed_bytes", self.installer_source)


if __name__ == "__main__":
    unittest.main()
