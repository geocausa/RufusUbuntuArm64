import tempfile
from pathlib import Path
import unittest

from rufusarm64_logic import build_writer_command


class WindowsSilentInstallCommandTests(unittest.TestCase):
    @staticmethod
    def analysis(enabled=True, reason="", target="uefi", filesystem="ntfs"):
        return {
            "default_target_system": target,
            "default_filesystem": filesystem,
            "capabilities": {
                "silent_install": {"enabled": enabled, "reason": reason},
            },
            "metadata": {
                "image_count": 2,
                "images": [
                    {"index": 1, "name": "Windows 11 Home", "default_language": "en-GB"},
                    {"index": 4, "name": "Windows 11 Pro", "default_language": "en-GB"},
                ],
                "boot_language": "en-GB",
            },
            "windows_ca_2023": {"available": False, "reason": "not selected"},
        }

    @staticmethod
    def options(**overrides):
        value = {
            "local_user": "Tester",
            "reduce_data_collection": True,
            "use_regional_settings": True,
            "locale": "en-GB",
            "timezone": "GMT Standard Time",
            "silent_install": True,
            "install_image_index": 4,
            "install_image_name": "Windows 11 Pro",
        }
        value.update(overrides)
        return value

    def build(self, *, analysis=None, options=None, target="auto", filesystem="auto", partition="gpt"):
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
                windows_options=options or self.options(),
                partition_scheme=partition,
                target_system=target,
                filesystem=filesystem,
                windows_capability_analysis=analysis or self.analysis(),
            )

    def test_binds_exact_index_and_literal_disk_zero_acknowledgement(self):
        command = self.build()
        self.assertIn("--win-silent-install", command)
        self.assertEqual(command[command.index("--win-install-image-index") + 1], "4")
        self.assertEqual(command[command.index("--win-silent-confirm") + 1], "ERASE DISK 0")
        self.assertIn("--win-local-user", command)
        self.assertIn("--win-reduce-data-collection", command)
        self.assertIn("--win-locale", command)
        self.assertIn("--win-timezone", command)

    def test_accepts_guarded_fat32_layout(self):
        command = self.build(filesystem="fat32")
        self.assertEqual(command[command.index("--filesystem") + 1], "fat32")
        self.assertIn("--win-silent-install", command)

    def test_rejects_unqualified_media_or_non_uefi_layout(self):
        with self.assertRaisesRegex(ValueError, "pre-existing unattend"):
            self.build(analysis=self.analysis(enabled=False, reason="pre-existing unattend"))
        with self.assertRaisesRegex(ValueError, "resolved UEFI"):
            self.build(target="bios", partition="mbr")

    def test_rejects_missing_prerequisites_and_unproven_index(self):
        for options in (
            self.options(local_user=""),
            self.options(reduce_data_collection=False),
            self.options(use_regional_settings=False),
            self.options(locale=""),
            self.options(timezone=""),
            self.options(install_image_index=3),
        ):
            with self.subTest(options=options):
                with self.assertRaises(ValueError):
                    self.build(options=options)


if __name__ == "__main__":
    unittest.main()
