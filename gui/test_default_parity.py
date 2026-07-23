import pathlib
import unittest

from rufusarm64_logic import (
    DEFAULT_BAD_BLOCK_CHECK,
    DEFAULT_PERSISTENCE_ENABLED,
    DEFAULT_QUICK_FORMAT,
    DEFAULT_VERIFY_AFTER_WRITE,
    DEFAULT_WINDOWS_CLUSTER_SIZE,
    DEFAULT_WINDOWS_FILESYSTEM,
    DEFAULT_WINDOWS_PARTITION_SCHEME,
    DEFAULT_WINDOWS_TARGET_SYSTEM,
)


class DefaultParityTests(unittest.TestCase):
    def test_high_risk_defaults(self):
        self.assertFalse(DEFAULT_VERIFY_AFTER_WRITE)
        self.assertTrue(DEFAULT_QUICK_FORMAT)
        self.assertFalse(DEFAULT_BAD_BLOCK_CHECK)
        self.assertFalse(DEFAULT_PERSISTENCE_ENABLED)
        self.assertEqual(DEFAULT_WINDOWS_PARTITION_SCHEME, "auto")
        self.assertEqual(DEFAULT_WINDOWS_TARGET_SYSTEM, "auto")
        self.assertEqual(DEFAULT_WINDOWS_FILESYSTEM, "auto")
        self.assertEqual(DEFAULT_WINDOWS_CLUSTER_SIZE, "auto")

    def test_gtk_uses_shared_defaults(self):
        source = pathlib.Path(__file__).with_name("rufusarm64.py").read_text(encoding="utf-8")
        self.assertIn('settings.get("verify", DEFAULT_VERIFY_AFTER_WRITE)', source)
        self.assertIn('self.partition_combo.append("auto", "Automatic (image-derived)")', source)
        self.assertIn('self.target_system_combo.append("auto", "Automatic (image-derived)")', source)
        self.assertIn('settings.get("quick_format", DEFAULT_QUICK_FORMAT)', source)
        self.assertIn('settings.get("bad_block_check", DEFAULT_BAD_BLOCK_CHECK)', source)
        self.assertIn('set_active(DEFAULT_PERSISTENCE_ENABLED)', source)
        self.assertIn('partition_scheme = DEFAULT_WINDOWS_PARTITION_SCHEME', source)
        self.assertIn('target_system = DEFAULT_WINDOWS_TARGET_SYSTEM', source)
        self.assertNotIn('''        else:
            partition_scheme = "gpt"
            target_system = "uefi"
''', source)
        self.assertIn('target_system == "bios" and partition_scheme == "gpt"', source)


if __name__ == "__main__":
    unittest.main()
