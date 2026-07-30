import os
from pathlib import Path
import sys
import tempfile
import types
import unittest


fake_gi = types.ModuleType("gi")
fake_repository = types.ModuleType("gi.repository")


class FakeDialog:
    pass


fake_gtk = types.SimpleNamespace(Dialog=FakeDialog)
fake_repository.Gtk = fake_gtk
fake_gi.repository = fake_repository

fake_rufusarm64 = types.ModuleType("rufusarm64")
fake_rufusarm64.RufusWindow = object
fake_rufusarm64.build_writer_command = lambda *args, **kwargs: []

_saved_modules = {
    name: sys.modules.get(name)
    for name in ("gi", "gi.repository", "rufusarm64", "rufusarm64_iso_write_mode")
}
try:
    sys.modules["gi"] = fake_gi
    sys.modules["gi.repository"] = fake_repository
    sys.modules["rufusarm64"] = fake_rufusarm64
    sys.modules.pop("rufusarm64_iso_write_mode", None)
    from rufusarm64_iso_write_mode import (
        build_iso_write_command,
        dd_image_mode_available,
        hybrid_mode_available,
        iso_image_mode_available,
    )
finally:
    for name, module in _saved_modules.items():
        if module is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = module


class ISOImageModeTests(unittest.TestCase):
    def test_iso_mode_accepts_hybrid_and_optical_only_uefi_profiles(self):
        hybrid = {
            "mode": "raw",
            "compatibility_profile": {
                "write_path": "hybrid-direct-write",
                "hybrid": True,
                "optical": True,
                "boot_methods": ["BIOS", "UEFI"],
            },
        }
        optical = {
            "mode": "raw",
            "compatibility_profile": {
                "write_path": "optical-direct-write",
                "hybrid": False,
                "optical": True,
                "boot_methods": ["UEFI"],
            },
        }
        self.assertTrue(iso_image_mode_available(hybrid))
        self.assertTrue(hybrid_mode_available(hybrid))
        self.assertTrue(dd_image_mode_available(hybrid))
        self.assertTrue(iso_image_mode_available(optical))
        self.assertFalse(dd_image_mode_available(optical))

        for incompatible in (
            {},
            {"mode": "windows"},
            {"mode": "raw", "compatibility_profile": {"write_path": "optical-direct-write", "optical": True, "boot_methods": ["BIOS"]}},
            {"mode": "raw", "compatibility_profile": {"write_path": "raw-direct-write", "hybrid": False, "optical": False, "boot_methods": ["UEFI"]}},
        ):
            self.assertFalse(iso_image_mode_available(incompatible), incompatible)

    def test_build_iso_write_command_binds_source_target_and_cancellation(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "ubuntu.iso"
            image.write_bytes(b"identity-bound-test-image")
            cancel = Path(directory) / "rufus.cancel"
            command = build_iso_write_command(
                "/usr/bin/pkexec",
                "/usr/lib/rufusarm64/rufusarm64-persistence-helper",
                str(image),
                "/dev/sdz",
                "target-identity",
                str(cancel),
                "rufus-live",
            )
            resolved_image = os.path.realpath(image)

        self.assertEqual(command[:4], [
            "/usr/bin/pkexec",
            "/usr/lib/rufusarm64/rufusarm64-persistence-helper",
            "--operation",
            "iso",
        ])
        self.assertEqual(command[command.index("--image") + 1], resolved_image)
        source_identity = command[command.index("--expected-source-identity") + 1]
        self.assertEqual(len(source_identity.split(":")), 5)
        self.assertEqual(command[command.index("--device") + 1], "/dev/sdz")
        self.assertEqual(command[command.index("--expected-identity") + 1], "target-identity")
        self.assertEqual(command[command.index("--volume-label") + 1], "RUFUS-LIVE")
        self.assertEqual(command[command.index("--filesystem") + 1], "auto")
        self.assertEqual(command[command.index("--cluster-size") + 1], "4096")
        self.assertEqual(command[command.index("--cancel-file") + 1], str(cancel))
        self.assertIn("--json-progress", command)
        self.assertIn("--yes", command)

    def test_auto_label_preserves_unicode_until_helper_resolution(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "linux.iso"
            image.write_bytes(b"identity-bound-test-image")
            command = build_iso_write_command(
                "pkexec",
                "helper",
                str(image),
                "/dev/sdz",
                "target-identity",
                str(Path(directory) / "cancel"),
                "Rufus_日本",
                filesystem="auto",
            )
        self.assertEqual(command[command.index("--volume-label") + 1], "Rufus_日本")
        self.assertEqual(command[command.index("--filesystem") + 1], "auto")

    def test_build_iso_write_command_rejects_missing_identity(self):
        with self.assertRaisesRegex(ValueError, "identity"):
            build_iso_write_command("pkexec", "helper", "/tmp/image.iso", "/dev/sdz", "", "/tmp/cancel")


if __name__ == "__main__":
    unittest.main()
