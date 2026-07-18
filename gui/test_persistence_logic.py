import os
import py_compile
import tempfile
import unittest

from rufusarm64_persistence_logic import (
    build_analyze_command,
    build_create_command,
    inspect_source_identity,
    normalize_boot_label,
    normalize_plan,
    technical_plan_summary,
    user_plan_summary,
    completion_checklist,
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

    def test_wizard_source_compiles(self):
        py_compile.compile(os.path.join(os.path.dirname(__file__), "rufusarm64_persistence.py"), doraise=True)

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

    def test_plan_rejects_impossible_partition_size(self):
        with self.assertRaisesRegex(ValueError, "impossible target layout"):
            normalize_plan({
                "detection": {"display_name": "Ubuntu", "family": "ubuntu-casper"},
                "plan": {
                    "filesystem": "ext4",
                    "filesystem_label": "casper-rw",
                    "boot_parameter": "persistent",
                    "size_bytes": 64 * 1024**3,
                    "patch_paths": ["boot/grub/grub.cfg"],
                },
                "target_size": 64 * 1024**3,
            })

    def test_plan_rejects_unsafe_or_duplicate_patch_paths(self):
        base = {
            "detection": {"display_name": "Ubuntu", "family": "ubuntu-casper"},
            "plan": {
                "filesystem": "ext4",
                "filesystem_label": "casper-rw",
                "boot_parameter": "persistent",
                "size_bytes": 16 * 1024**3,
                "patch_paths": ["../boot/grub/grub.cfg"],
            },
            "target_size": 64 * 1024**3,
        }
        with self.assertRaisesRegex(ValueError, "invalid boot-file edit path"):
            normalize_plan(base)
        base["plan"]["patch_paths"] = ["boot/grub/grub.cfg", "boot/grub/grub.cfg"]
        with self.assertRaisesRegex(ValueError, "duplicate boot-file edits"):
            normalize_plan(base)

    def test_user_summary_hides_boot_internals(self):
        plan = {
            "name": "Ubuntu 24.04", "family": "ubuntu-casper", "filesystem": "ext4",
            "label": "casper-rw", "parameter": "persistent", "size": 16 * 1024**3,
            "target_size": 64 * 1024**3, "patch_paths": ["boot/grub/grub.cfg"],
        }
        summary = user_plan_summary(plan, lambda value: f"{value // 1024**3} GiB")
        self.assertIn("Ubuntu 24.04", summary)
        self.assertIn("16 GiB", summary)
        self.assertNotIn("casper-rw", summary)
        self.assertNotIn("grub.cfg", summary)
        technical = technical_plan_summary(plan, lambda value: f"{value // 1024**3} GiB")
        self.assertIn("casper-rw", technical)
        self.assertIn("grub.cfg", technical)

    def test_completion_checklist_is_plain_language(self):
        checklist = completion_checklist()
        self.assertIn("boot from the new USB", checklist)
        self.assertIn("test file", checklist)
        self.assertIn("still present", checklist)
        self.assertNotIn("rufusarm64-cli", checklist)


if __name__ == "__main__":
    unittest.main()
