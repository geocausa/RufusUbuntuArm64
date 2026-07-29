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

fake_repository.Gtk = types.SimpleNamespace(Dialog=FakeDialog)
fake_gi.repository = fake_repository
fake_rufusarm64 = types.ModuleType("rufusarm64")
fake_rufusarm64.RufusWindow = object
fake_rufusarm64.build_writer_command = lambda *args, **kwargs: []

_saved = {name: sys.modules.get(name) for name in ("gi", "gi.repository", "rufusarm64", "rufusarm64_iso_write_mode")}
try:
    sys.modules["gi"] = fake_gi
    sys.modules["gi.repository"] = fake_repository
    sys.modules["rufusarm64"] = fake_rufusarm64
    sys.modules.pop("rufusarm64_iso_write_mode", None)
    from rufusarm64_iso_write_mode import (
        build_iso_write_command,
        iso_layout_summary,
        iso_source_state,
        normalize_iso_cluster_size,
        normalize_iso_partition_scheme,
    )
finally:
    for name, module in _saved.items():
        if module is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = module


class ISOLayoutOptionTests(unittest.TestCase):
    def test_layout_normalization_is_bounded(self):
        self.assertEqual(normalize_iso_partition_scheme("GPT"), "gpt")
        self.assertEqual(normalize_iso_cluster_size("auto"), "4096")
        self.assertEqual(normalize_iso_cluster_size("32768"), "32768")
        with self.assertRaises(ValueError):
            normalize_iso_partition_scheme("apm")
        with self.assertRaises(ValueError):
            normalize_iso_cluster_size("65536")

    def test_source_change_resets_stale_windows_label(self):
        source, label = iso_source_state("/tmp/windows.iso", "/tmp/ubuntu.iso", "WIN11ARM64")
        self.assertEqual(source, os.path.realpath("/tmp/ubuntu.iso"))
        self.assertEqual(label, "RUFUS-LIVE")
        source2, label2 = iso_source_state(source, "/tmp/ubuntu.iso", "CUSTOM")
        self.assertEqual(source2, source)
        self.assertEqual(label2, "CUSTOM")

    def test_command_binds_gpt_cluster_and_label(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "ubuntu.iso"
            image.write_bytes(b"identity-bound-layout-test")
            cancel = Path(directory) / "cancel"
            command = build_iso_write_command(
                "/usr/bin/pkexec",
                "/usr/lib/rufusarm64/rufusarm64-persistence-helper",
                str(image),
                "/dev/sdz",
                "target-token",
                str(cancel),
                "ubuntu",
                "gpt",
                "8192",
            )
        self.assertEqual(command[command.index("--partition-scheme") + 1], "gpt")
        self.assertEqual(command[command.index("--cluster-size") + 1], "8192")
        self.assertEqual(command[command.index("--volume-label") + 1], "UBUNTU")
        self.assertIn("GPT / UEFI / FAT32 / 8 KiB clusters", iso_layout_summary("gpt", "8192", "ubuntu"))


if __name__ == "__main__":
    unittest.main()
