#!/usr/bin/env python3
"""Source-level safeguards for optional Windows driver staging."""

import ast
from pathlib import Path
import unittest


GUI = Path(__file__).with_name("rufusarm64.py")


class DriverFolderOptInTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = GUI.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source, filename=str(GUI))

    def method_source(self, method_name):
        for node in self.tree.body:
            if isinstance(node, ast.ClassDef) and node.name == "RufusWindow":
                for child in node.body:
                    if isinstance(child, ast.FunctionDef) and child.name == method_name:
                        return ast.get_source_segment(self.source, child) or ""
        self.fail(f"missing RufusWindow.{method_name}")

    def test_constructor_requires_explicit_driver_opt_in(self):
        constructor = self.method_source("__init__")
        self.assertIn('Gtk.CheckButton(label="Include selected folder")', constructor)
        self.assertIn('self.settings.get("driver_folder_enabled", False)', constructor)
        self.assertIn('title="Choose a dedicated Windows driver folder"', constructor)
        self.assertIn('Gtk.Button(label="Clear")', constructor)

    def test_saved_folder_is_not_active_without_explicit_boolean(self):
        save = self.method_source("save_settings")
        self.assertIn('self.settings["driver_folder_enabled"] = bool(', save)
        self.assertIn('self.driver_enabled.get_active() and saved_driver_folder', save)

    def test_writer_ignores_remembered_folder_when_opt_in_is_off(self):
        start = self.method_source("start")
        self.assertIn('driver_folder = ""', start)
        self.assertIn('if self.driver_enabled.get_active():', start)
        self.assertIn('driver_folder = self.driver_chooser.get_filename() or ""', start)
        self.assertIn('Choose a dedicated Windows driver folder or turn off Include selected folder.', start)

    def test_busy_state_keeps_chooser_disabled_until_opted_in(self):
        controls = self.method_source("update_driver_folder_controls")
        self.assertIn('self.driver_enabled.set_sensitive(windows_controls)', controls)
        self.assertIn('windows_controls and self.driver_enabled.get_active()', controls)


if __name__ == "__main__":
    unittest.main()
