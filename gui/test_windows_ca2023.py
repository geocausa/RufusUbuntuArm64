import tempfile
from pathlib import Path
import unittest

from rufusarm64_logic import build_writer_command


class WindowsCA2023CommandTests(unittest.TestCase):
    def analysis(self, default_target="uefi", default_filesystem="fat32", available=True, reason=""):
        return {
            "default_target_system": default_target,
            "default_filesystem": default_filesystem,
            "windows_ca_2023": {
                "available": available,
                "reason": reason,
                "image_index": 2,
                "architecture": "arm64",
                "asset_count": 14,
                "manifest_sha256": "a" * 64,
            },
        }

    def base(self, target_system="uefi", filesystem="fat32", analysis=None, enabled=True):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "windows.iso"
            image.write_bytes(b"identity-bound-windows-image")
            return build_writer_command(
                "/usr/bin/pkexec",
                "/usr/lib/rufusarm64/rufusarm64-helper",
                str(image),
                "/dev/sdz",
                "target-token",
                False,
                str(Path(directory) / "cancel"),
                windows_options={"use_windows_ca_2023_bootloaders": enabled},
                partition_scheme="gpt",
                target_system=target_system,
                filesystem=filesystem,
                windows_capability_analysis=analysis or self.analysis(),
            )

    def test_binds_flag_for_explicit_uefi_fat32(self):
        self.assertIn("--win-use-ca-2023-bootloaders", self.base())

    def test_binds_flag_when_automatic_resolves_to_uefi_fat32(self):
        command = self.base(target_system="auto", filesystem="auto")
        self.assertIn("--win-use-ca-2023-bootloaders", command)
        self.assertIn("auto", command)

    def test_rejects_unproven_media(self):
        with self.assertRaisesRegex(ValueError, "incomplete _EX set"):
            self.base(analysis=self.analysis(available=False, reason="incomplete _EX set"))

    def test_rejects_bios_resolution(self):
        with self.assertRaisesRegex(ValueError, "requires a UEFI"):
            self.base(target_system="auto", analysis=self.analysis(default_target="bios"))

    def test_rejects_ntfs_resolution(self):
        with self.assertRaisesRegex(ValueError, "requires FAT32"):
            self.base(filesystem="auto", analysis=self.analysis(default_filesystem="ntfs"))


if __name__ == "__main__":
    unittest.main()
