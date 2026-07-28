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
        cls.constants = {}
        for node in tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                name = node.targets[0].id
                if name in {
                    "PRIMARY_LABEL_MNEMONICS",
                    "PRIMARY_BUTTON_MNEMONICS",
                    "PRIMARY_ACCELERATORS",
                    "PRIMARY_ACCESSIBILITY",
                    "ABOUT_ACCESSIBILITY",
                }:
                    cls.constants[name] = ast.literal_eval(node.value)
        installer = next(
            node for node in tree.body
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

    def test_reviewed_inventory_is_exact_and_complete(self):
        self.assertEqual(
            self.constants["PRIMARY_LABEL_MNEMONICS"],
            {
                "Boot image": ("_Boot image", "image_chooser"),
                "USB drive": ("_USB drive", "target_combo"),
            },
        )
        self.assertEqual(
            tuple(self.constants["PRIMARY_BUTTON_MNEMONICS"]),
            (
                "download_button",
                "checksum_button",
                "start_button",
                "cancel_button",
                "uefi_validation_button",
                "nonbootable_button",
                "freedos_button",
            ),
        )
        self.assertEqual(
            tuple(self.constants["PRIMARY_ACCESSIBILITY"]),
            (
                "image_chooser",
                "target_combo",
                "refresh_button",
                "download_button",
                "checksum_button",
                "qualify_button",
                "start_button",
                "cancel_button",
                "uefi_validation_button",
                "mode_value",
                "verify",
                "progress",
                "progress_detail",
                "log",
                "nonbootable_button",
                "freedos_button",
                "post_operation_bar",
            ),
        )

    def test_installer_uses_only_reviewed_inventory(self):
        for expected in (
            "PRIMARY_LABEL_MNEMONICS.get(source)",
            "PRIMARY_BUTTON_MNEMONICS.items()",
            "PRIMARY_ACCELERATORS.items()",
            "PRIMARY_ACCESSIBILITY.items()",
            "_set_accessible(about_button, *ABOUT_ACCESSIBILITY)",
            "widget.set_mnemonic_widget(getattr(window, target_attribute))",
        ):
            self.assertIn(expected, self.installer_source)

    def test_safe_shortcuts_do_not_bypass_destructive_confirmation(self):
        self.assertEqual(
            self.constants["PRIMARY_ACCELERATORS"],
            {
                "refresh_button": "<Primary>r",
                "download_button": "<Primary>d",
                "checksum_button": "<Primary>k",
                "uefi_validation_button": "<Primary>u",
            },
        )
        self.assertNotIn('"start_button":', self.integrated_source.split("PRIMARY_ACCELERATORS =", 1)[1].split("}", 1)[0])
        self.assertNotIn('"cancel_button":', self.integrated_source.split("PRIMARY_ACCELERATORS =", 1)[1].split("}", 1)[0])
        self.assertIn("dialog.set_default_response(Gtk.ResponseType.CANCEL)", self.main_source)

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
