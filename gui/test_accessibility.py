import ast
import pathlib
import unittest


class AccessibilityStructureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = pathlib.Path(__file__).resolve().parents[1]
        cls.integrated_source = (root / "gui" / "rufusarm64_integrated.py").read_text(encoding="utf-8")
        cls.main_source = (root / "gui" / "rufusarm64.py").read_text(encoding="utf-8")
        tree = ast.parse(cls.integrated_source)
        installer = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "install_accessibility"
        )
        cls.installer_source = ast.get_source_segment(cls.integrated_source, installer)

    def test_accessibility_is_installed_after_every_visual_extension(self):
        calls = [
            "install_drive_backup(RufusWindow)",
            "install_nonbootable(RufusWindow)",
            "install_freedos(RufusWindow)",
            "install_linux_compatibility(RufusWindow)",
            "install_verified_acquisition(RufusWindow)",
            "install_post_operation_reuse(RufusWindow)",
            "install_accessibility(RufusWindow)",
        ]
        positions = [self.integrated_source.index(call) for call in calls]
        self.assertEqual(positions, sorted(positions))

    def test_image_and_target_have_real_mnemonic_focus_targets(self):
        self.assertIn('"Boot image": ("_Boot image", window.image_chooser)', self.installer_source)
        self.assertIn('"USB drive": ("_USB drive", window.target_combo)', self.installer_source)
        self.assertIn("widget.set_mnemonic_widget(target)", self.installer_source)

    def test_primary_actions_have_visible_mnemonics(self):
        for expected in (
            'window.download_button, "_Download…"',
            'window.checksum_button, "C_hecksums…"',
            'window.start_button, "_Create USB"',
            'window.cancel_button, "C_ancel"',
            'window.uefi_validation_button, "_Validate UEFI Media…"',
            '"Restore / for_mat…"',
            '"_FreeDOS…"',
        ):
            self.assertIn(expected, self.installer_source)

    def test_safe_shortcuts_do_not_bypass_destructive_confirmation(self):
        for expected in (
            'window.refresh_button, "<Primary>r"',
            'window.download_button, "<Primary>d"',
            'window.checksum_button, "<Primary>k"',
            'window.uefi_validation_button, "<Primary>u"',
            'about_button, "F1"',
        ):
            self.assertIn(expected, self.installer_source)
        self.assertNotIn("_add_button_accelerator(window, window.start_button", self.installer_source)
        self.assertNotIn("_add_button_accelerator(window, window.cancel_button", self.installer_source)
        self.assertIn("dialog.set_default_response(Gtk.ResponseType.CANCEL)", self.main_source)

    def test_icon_only_and_status_widgets_have_assistive_names(self):
        for expected in (
            '"Refresh USB drives"',
            '"About RufusArm64"',
            '"Image compatibility and write path"',
            '"Operation progress"',
            '"Operation status details"',
            '"Technical diagnostic log"',
            '"Post-operation actions"',
        ):
            self.assertIn(expected, self.installer_source)
        self.assertIn("accessible.set_name(name)", self.integrated_source)
        self.assertIn("accessible.set_description(description)", self.integrated_source)

    def test_dynamic_explanations_are_keyboard_selectable(self):
        self.assertIn("window.mode_value.set_selectable(True)", self.installer_source)
        self.assertIn("window.progress_detail.set_selectable(True)", self.installer_source)

    def test_accessibility_layer_has_no_privilege_or_erase_implementation(self):
        self.assertNotIn("subprocess", self.integrated_source)
        self.assertNotIn("pkexec", self.integrated_source.lower())
        self.assertNotIn("--yes", self.integrated_source)
        self.assertNotIn("--allow-fixed", self.integrated_source)
        self.assertNotIn("--no-unmount", self.integrated_source)


if __name__ == "__main__":
    unittest.main()
