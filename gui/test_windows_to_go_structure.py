#!/usr/bin/env python3
"""Source-level safeguards for the graphical Windows To Go boundary."""

import ast
from pathlib import Path
import unittest


GUI = Path(__file__).with_name("rufusarm64.py")
LOGIC = Path(__file__).with_name("rufusarm64_logic.py")
HELPER = Path(__file__).parents[1] / "cmd" / "rufus-linux" / "main.go"
CAPABILITIES = Path(__file__).parents[1] / "internal" / "windowsconfig" / "capabilities.go"


class WindowsToGoStructureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gui = GUI.read_text(encoding="utf-8")
        cls.logic = LOGIC.read_text(encoding="utf-8")
        cls.helper = HELPER.read_text(encoding="utf-8")
        cls.capabilities = CAPABILITIES.read_text(encoding="utf-8")
        cls.gui_tree = ast.parse(cls.gui, filename=str(GUI))

    def method_source(self, class_name, method_name):
        for node in self.gui_tree.body:
            if isinstance(node, ast.ClassDef) and node.name == class_name:
                for child in node.body:
                    if isinstance(child, ast.FunctionDef) and child.name == method_name:
                        return ast.get_source_segment(self.gui, child) or ""
        self.fail(f"missing {class_name}.{method_name}")

    def test_dialog_exposes_a_separate_experimental_image_mode(self):
        source = self.method_source("WindowsOptionsDialog", "__init__")
        self.assertIn("Create Windows To Go instead of installation media (experimental)", source)
        self.assertIn('self.windows_to_go.connect("toggled", self.update_windows_to_go_sensitivity)', source)
        self.assertIn('previous.get("windows_to_go", False)', source)

    def test_mode_disables_every_installer_customization(self):
        source = self.method_source("WindowsOptionsDialog", "enforce_windows_image_mode")
        self.assertIn("for widget in self.standard_option_widgets()", source)
        self.assertIn("widget.set_active(False)", source)
        self.assertIn("widget.set_sensitive(False)", source)
        widgets = self.method_source("WindowsOptionsDialog", "standard_option_widgets")
        for name in (
            "bypass_hardware", "bypass_online", "local_account", "reduce_data",
            "quality_of_life", "apply_sku_si_policy", "use_ca_2023_bootloaders",
            "use_region", "silent_install", "disable_bitlocker",
        ):
            self.assertIn(f"self.{name}", widgets)

    def test_three_part_confirmation_is_distinct_from_silent_install(self):
        source = self.method_source("RufusWindow", "confirm_windows_to_go")
        self.assertIn("Microsoft removed Windows To Go support", source)
        self.assertIn("complete selected target drive will be permanently erased", source)
        self.assertIn("may not boot or complete first boot", source)
        self.assertIn("is the edition I intend to apply", source)
        self.assertIn("all(check.get_active() for check in checks)", source)
        self.assertNotIn("disk 0", source.lower())

    def test_target_geometry_is_checked_before_final_write_command(self):
        source = self.method_source("RufusWindow", "choose_windows_options")
        self.assertIn("plan_windows_to_go_target(", source)
        self.assertIn("confirm_windows_to_go(values, plan, device)", source)
        self.assertLess(source.index("plan_windows_to_go_target("), source.index("confirm_windows_to_go(values, plan, device)"))
        for fixed in (
            'self.partition_combo.set_active_id("gpt")',
            'self.target_system_combo.set_active_id("uefi")',
            'self.filesystem_combo.set_active_id("ntfs")',
            "self.driver_chooser.unselect_all()",
            "self.dbx_chooser.unselect_all()",
        ):
            self.assertIn(fixed, source)

    def test_command_builder_emits_only_the_exact_experimental_envelope(self):
        self.assertIn('"--mode", "windows-to-go"', self.logic)
        self.assertIn('"--win-to-go-confirm", WINDOWS_TO_GO_CONFIRMATION', self.logic)
        self.assertIn('WINDOWS_TO_GO_CONFIRMATION = "CREATE EXPERIMENTAL WINDOWS TO GO"', self.logic)
        special = self.logic[self.logic.index("def _windows_to_go_command"):self.logic.index("def build_writer_command")]
        for forbidden in (
            "--partition-scheme", "--target-system", "--filesystem", "--cluster-size",
            "--volume-label", "--verify", "--driver-folder", "--dbx-file",
            "--full-format", "--bad-block-check", "--win-silent-install",
        ):
            self.assertNotIn(forbidden, special)

    def test_privileged_helper_has_a_separate_exact_allowlist(self):
        self.assertIn('case "windows-to-go":', self.helper)
        self.assertIn('envelope.WinToGoConfirm != "CREATE EXPERIMENTAL WINDOWS TO GO"', self.helper)
        self.assertIn("envelope.WinToGoImageIndex < 1", self.helper)
        self.assertIn("envelope.WinBypassHardware", self.helper)
        self.assertIn("envelope.DriverFolder != \"\"", self.helper)

    def test_capability_requires_arm64_size_and_language_evidence(self):
        self.assertIn('WindowsToGo                 OptionCapability `json:"windows_to_go"`', self.capabilities)
        self.assertIn('profile.Architecture != "arm64"', self.capabilities)
        self.assertIn("image.TotalBytes == 0", self.capabilities)
        self.assertIn("image.DefaultLanguage", self.capabilities)


if __name__ == "__main__":
    unittest.main()
