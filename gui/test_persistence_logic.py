import os
import tempfile
import unittest

from rufusarm64_persistence_logic import (
    build_analyze_command,
    build_create_command,
    inspect_source_identity,
    normalize_boot_label,
    normalize_plan,
)


class PersistenceLogicTests(unittest.TestCase):
    def test_source_identity_uses_five_kernel_fields(self):
        with tempfile.NamedTemporaryFile() as handle:
            handle.write(b"iso")
            handle.flush()
            path, identity = inspect_source_identity(handle.name)
        self.assertTrue(os.path.isabs(path))
        self.assertEqual(len(identity.split(":")), 5)

    def test_analyze_command_is_read_only_and_identity_bound(self):
        command = build_analyze_command(
            "/usr/bin/pkexec", "/helper", "/tmp/ubuntu.iso", "1:2:3:4:5", 64 * 1024**3, 16, "/run/user/1000/cancel"
        )
        self.assertEqual(command[:4], ["/usr/bin/pkexec", "/helper", "persistence", "analyze"])
        self.assertIn("--expected-source-identity", command)
        self.assertIn("16G", command)
        self.assertNotIn("--device", command)

    def test_create_command_requires_both_identities(self):
        command = build_create_command(
            "/usr/bin/pkexec",
            "/usr/lib/rufusarm64/rufusarm64-persistence-helper",
            "/tmp/ubuntu.iso",
            "1:2:3:4:5",
            "/dev/sda",
            "target-token",
            0,
            "RUFUS-LIVE",
            "/run/user/1000/cancel",
        )
        self.assertIn("--expected-source-identity", command)
        self.assertIn("--expected-identity", command)
        self.assertIn("--json-progress", command)
        self.assertIn("--yes", command)
        self.assertIn("0", command)

    def test_label_validation(self):
        self.assertEqual(normalize_boot_label("rufus-live"), "RUFUS-LIVE")
        with self.assertRaises(ValueError):
            normalize_boot_label("TOO-LONG-LABEL")

    def test_plan_normalization(self):
        plan = normalize_plan({
            "detection": {"display_name": "Ubuntu 24.04", "family": "ubuntu-casper"},
            "plan": {
                "filesystem": "ext4",
                "filesystem_label": "casper-rw",
                "boot_parameter": "persistent",
                "size_bytes": 16 * 1024**3,
                "patch_paths": ["boot/grub/grub.cfg"],
            },
            "target_size": 64 * 1024**3,
        })
        self.assertEqual(plan["label"], "casper-rw")
        self.assertEqual(plan["parameter"], "persistent")


if __name__ == "__main__":
    unittest.main()
