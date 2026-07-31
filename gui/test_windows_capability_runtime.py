#!/usr/bin/env python3
"""Runtime regression for the graphical Windows capability normalizer."""

import unittest

import rufusarm64


class WindowsCapabilityRuntimeTests(unittest.TestCase):
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
        normalized = rufusarm64.normalize_windows_capability_analysis(payload)
        self.assertEqual(normalized["default_partition_scheme"], "gpt")
        self.assertEqual(normalized["metadata"]["images"][0]["default_language"], "en-GB")
        self.assertTrue(normalized["capabilities"]["silent_install"]["enabled"])


if __name__ == "__main__":
    unittest.main()
