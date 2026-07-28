import pathlib
import unittest

from rufusarm64_iso_write_logic import (
    DD_IMAGE_MODE,
    ISO_IMAGE_MODE,
    build_iso_analysis_command,
    build_iso_create_command,
    iso_analysis_summary,
    normalize_iso_analysis,
)


ROOT = pathlib.Path(__file__).resolve().parent


def valid_analysis():
    target = 16_013_942_272
    partition_start = 1_048_576
    partition_size = target - partition_start - 33 * 512
    required = 5_500_000_000
    return {
        "layout": {
            "sector_size": 512,
            "target_size": target,
            "required_bytes": required,
            "partition": {
                "number": 1,
                "start_bytes": partition_start,
                "size_bytes": partition_size,
            },
        },
        "image_size": 6_000_000_000,
        "target_size": target,
        "manifest_entries": 1200,
        "manifest_files": 1000,
        "manifest_directories": 200,
        "manifest_bytes": 5_400_000_000,
        "fat32_required_bytes": required,
        "uefi_boot_path": "EFI/BOOT/BOOTAA64.EFI",
        "architecture": "arm64",
    }


class ISOImageModeLogicTests(unittest.TestCase):
    def test_analysis_command_contains_no_target_path(self):
        command = build_iso_analysis_command(
            "/usr/bin/pkexec",
            "/usr/lib/rufusarm64/rufusarm64-iso-helper",
            "/home/user/ubuntu.iso",
            "1:2:3:4:5",
            16_013_942_272,
            "/run/user/1000/rufus.cancel",
        )
        self.assertEqual(command[2], "analyze")
        self.assertNotIn("--device", command)
        self.assertIn("--target-size", command)
        self.assertIn("--expected-source-identity", command)
        self.assertIn("--json", command)

    def test_create_command_binds_source_and_target(self):
        command = build_iso_create_command(
            "/usr/bin/pkexec",
            "/usr/lib/rufusarm64/rufusarm64-iso-helper",
            "/home/user/ubuntu.iso",
            "1:2:3:4:5",
            "/dev/sda",
            "a" * 64,
            "/run/user/1000/rufus.cancel",
        )
        self.assertEqual(command[2], "create")
        self.assertEqual(command[command.index("--device") + 1], "/dev/sda")
        self.assertEqual(command[command.index("--expected-identity") + 1], "a" * 64)
        self.assertIn("--yes", command)
        self.assertIn("--json-progress", command)

    def test_create_command_rejects_unsafe_label(self):
        with self.assertRaises(ValueError):
            build_iso_create_command(
                "/usr/bin/pkexec",
                "/helper",
                "/image.iso",
                "1:2:3:4:5",
                "/dev/sda",
                "a" * 64,
                "/run/user/1000/cancel",
                "BAD+LABEL",
            )

    def test_normalize_analysis_accepts_consistent_layout(self):
        result = normalize_iso_analysis(valid_analysis())
        self.assertEqual(result["architecture"], "arm64")
        self.assertEqual(result["layout"]["partition"]["number"], 1)
        self.assertEqual(result["uefi_boot_path"], "EFI/BOOT/BOOTAA64.EFI")

    def test_normalize_analysis_rejects_missing_fallback_loader(self):
        payload = valid_analysis()
        payload["uefi_boot_path"] = "EFI/ubuntu/grubaa64.efi"
        with self.assertRaises(ValueError):
            normalize_iso_analysis(payload)

    def test_normalize_analysis_rejects_partition_overrun(self):
        payload = valid_analysis()
        payload["layout"]["partition"]["size_bytes"] = payload["target_size"]
        with self.assertRaises(ValueError):
            normalize_iso_analysis(payload)

    def test_summary_discloses_verified_copy_and_layout(self):
        summary = iso_analysis_summary(valid_analysis(), lambda value: f"{int(value)} bytes")
        self.assertIn("one writable GPT/UEFI/FAT32 partition", summary)
        self.assertIn("every file was hashed", summary)
        self.assertIn("EFI/BOOT/BOOTAA64.EFI", summary)

    def test_mode_constants_are_distinct(self):
        self.assertEqual(ISO_IMAGE_MODE, "linux-iso")
        self.assertEqual(DD_IMAGE_MODE, "raw")
        self.assertNotEqual(ISO_IMAGE_MODE, DD_IMAGE_MODE)

    def test_gtk_source_makes_iso_recommended_and_default(self):
        source = (ROOT / "rufusarm64_iso_write.py").read_text(encoding="utf-8")
        self.assertIn('"Write in ISO Image mode (Recommended)"', source)
        self.assertIn("iso.set_active(True)", source)
        self.assertIn('"Write in DD Image mode"', source)
        self.assertIn("dialog.set_default_response(Gtk.ResponseType.OK)", source)

    def test_dd_fallback_dialog_defaults_to_cancel(self):
        source = (ROOT / "rufusarm64_iso_write.py").read_text(encoding="utf-8")
        marker = 'text="ISO Image mode is unavailable for this image and USB"'
        start = source.index(marker)
        block = source[start : start + 900]
        self.assertIn('dialog.add_button("Use DD Image mode", Gtk.ResponseType.OK)', block)
        self.assertIn("dialog.set_default_response(Gtk.ResponseType.CANCEL)", block)


if __name__ == "__main__":
    unittest.main()
