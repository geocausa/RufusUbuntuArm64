#!/usr/bin/env python3
"""Structural contracts for the high-risk Windows silent-install UI."""

import ast
from pathlib import Path
import unittest


GUI_ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = GUI_ROOT.parent


class WindowsSilentInstallStructureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (GUI_ROOT / "rufusarm64.py").read_text(encoding="utf-8")
        cls.logic = (GUI_ROOT / "rufusarm64_logic.py").read_text(encoding="utf-8")
        cls.cli = (REPOSITORY_ROOT / "cmd" / "rufus-linux" / "main.go").read_text(encoding="utf-8")
        tree = ast.parse(cls.source, filename="rufusarm64.py")
        cls.methods = {
            (class_node.name, node.name): ast.get_source_segment(cls.source, node) or ""
            for class_node in tree.body
            if isinstance(class_node, ast.ClassDef)
            for node in class_node.body
            if isinstance(node, ast.FunctionDef)
        }

    def test_dialog_requires_exact_layout_and_prerequisites(self):
        apply_capabilities = self.methods[("WindowsOptionsDialog", "apply_capabilities")]
        sensitivity = self.methods[("WindowsOptionsDialog", "update_silent_install_sensitivity")]
        values = self.methods[("WindowsOptionsDialog", "values")]
        self.assertIn('self.selected_target_system != "uefi"', apply_capabilities)
        self.assertIn('self.selected_filesystem not in {"fat32", "ntfs"}', apply_capabilities)
        for fragment in ("local_account", "local_user", "reduce_data", "use_region", "region_locale", "region_timezone", "windows_images"):
            self.assertIn(fragment, sensitivity)
        self.assertIn("install_image_index", values)
        self.assertIn("installation image proven by the current ISO analysis", values)

    def test_separate_three_part_disk_zero_confirmation_precedes_usb_erase(self):
        confirm = self.methods[("RufusWindow", "confirm_silent_install")]
        choose = self.methods[("RufusWindow", "choose_windows_options")]
        start = self.methods[("RufusWindow", "start")]
        self.assertIn("disk 0", confirm.lower())
        self.assertIn("all(check.get_active() for check in checks)", confirm)
        self.assertIn("disconnect every other", confirm.lower())
        self.assertIn("self.confirm_silent_install(values)", choose)
        self.assertIn("Erase the selected USB drive?", start)
        self.assertLess(choose.index("dialog.values()"), choose.index("confirm_silent_install"))

    def test_privileged_command_requires_exact_acknowledgement(self):
        combined = "\n".join((self.logic, self.cli))
        self.assertIn("--win-silent-install", combined)
        self.assertIn("--win-install-image-index", combined)
        self.assertIn("--win-silent-confirm", combined)
        self.assertIn("ERASE DISK 0", combined)
        self.assertIn("verified partition-2 guard", combined)


if __name__ == "__main__":
    unittest.main()
