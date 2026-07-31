#!/usr/bin/env python3
"""Headless runtime regression for the graphical capability normalizer."""

import ast
from pathlib import Path
import unittest


GUI = Path(__file__).with_name("rufusarm64.py")


class WindowsCapabilityRuntimeTests(unittest.TestCase):
    @staticmethod
    def load_normalizer():
        source = GUI.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(GUI))
        re_import = next(
            (
                node
                for node in tree.body
                if isinstance(node, ast.Import)
                and any(alias.name == "re" and alias.asname is None for alias in node.names)
            ),
            None,
        )
        if re_import is None:
            raise AssertionError("rufusarm64.py uses regular expressions without importing re")
        normalizer = next(
            (
                node
                for node in tree.body
                if isinstance(node, ast.FunctionDef)
                and node.name == "normalize_windows_capability_analysis"
            ),
            None,
        )
        if normalizer is None:
            raise AssertionError("Windows capability normalizer is missing")
        module = ast.Module(body=[re_import, normalizer], type_ignores=[])
        ast.fix_missing_locations(module)
        namespace = {}
        exec(compile(module, str(GUI), "exec"), namespace)
        return namespace["normalize_windows_capability_analysis"]

    def test_valid_arm64_payload_executes_regular_expression_validation(self):
        payload = {
            "default_partition_scheme": "gpt",
            "default_target_system": "uefi",
            "default_filesystem": "fat32",
            "capabilities": {
                "recognized": True,
                "silent_install": {"enabled": True, "reason": ""},
                "windows_to_go": {"enabled": True, "reason": ""},
            },
            "metadata": {
                "image_count": 1,
                "images": [{
                    "index": 3,
                    "name": "Windows 11 Pro",
                    "default_language": "en-GB",
                    "total_bytes": 30 * 1024**3,
                }],
                "boot_language": "en-GB",
                "existing_unattend_path": "",
            },
            "windows_ca_2023": {"available": False, "reason": "not available"},
        }
        normalized = self.load_normalizer()(payload)
        self.assertEqual(normalized["default_partition_scheme"], "gpt")
        self.assertEqual(normalized["metadata"]["images"][0]["default_language"], "en-GB")
        self.assertTrue(normalized["capabilities"]["silent_install"]["enabled"])


if __name__ == "__main__":
    unittest.main()
