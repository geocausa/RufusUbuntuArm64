#!/usr/bin/env python3
"""Structural CA 2023 contracts that do not require importing GTK."""

import ast
from pathlib import Path
import unittest


GUI_ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = GUI_ROOT.parent


class WindowsCA2023StructureTests(unittest.TestCase):
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

    def test_dialog_and_command_share_analyzed_layout_evidence(self):
        choose = self.methods.get(("RufusWindow", "choose_windows_options"), "")
        start = self.methods.get(("RufusWindow", "start"), "")
        apply_capabilities = self.methods.get(("WindowsOptionsDialog", "apply_capabilities"), "")
        self.assertIn("self.filesystem_combo.get_active_id()", choose)
        self.assertIn("windows_capability_analysis=self.windows_capability_analysis", start)
        self.assertIn("self.selected_target_system != \"uefi\"", apply_capabilities)
        self.assertIn("self.selected_filesystem != \"fat32\"", apply_capabilities)
        self.assertIn("resolved_target_system", self.logic)
        self.assertIn("resolved_filesystem", self.logic)

    def test_manifest_evidence_is_logged_once_per_write(self):
        start = self.methods.get(("RufusWindow", "start"), "")
        handle = self.methods.get(("RufusWindow", "handle_event"), "")
        self.assertIn('self.last_ca2023_manifest = ""', start)
        self.assertIn("manifest SHA-256", handle)
        self.assertIn("verify_ca_2023", handle)

    def test_user_visible_text_does_not_overclaim_signature_verification(self):
        combined = "\n".join((self.source, self.logic, self.cli))
        self.assertNotIn("CA 2023-signed", combined)
        self.assertIn("embedded certificate-chain evidence", self.cli)

    def test_temporary_ca2023_automation_is_absent(self):
        forbidden = []
        for root in (REPOSITORY_ROOT / ".github" / "scripts", REPOSITORY_ROOT / ".github" / "workflows"):
            if root.is_dir():
                forbidden.extend(path for path in root.glob("*ca2023*") if path.is_file())
        self.assertEqual(
            [str(path.relative_to(REPOSITORY_ROOT)) for path in sorted(forbidden)],
            [],
            "one-use CA 2023 applicators and audit workflows must not survive on the authoritative head",
        )


if __name__ == "__main__":
    unittest.main()
