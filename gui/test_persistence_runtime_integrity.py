import unittest

from rufusarm64_persistence_logic import build_create_command


class RuntimeIntegrityPersistenceLogicTests(unittest.TestCase):
    def base_command(self, enabled=False):
        return build_create_command(
            "/usr/bin/pkexec",
            "/usr/lib/rufusarm64/rufusarm64-persistence-helper",
            "/images/ubuntu.iso",
            "1:2:3:4:5",
            "/dev/sda",
            "target-identity",
            16,
            "RUFUS-LIVE",
            "/run/user/1000/rufusarm64.cancel",
            enabled,
        )

    def test_runtime_validation_appends_only_fixed_boolean_flag(self):
        disabled = self.base_command(False)
        enabled = self.base_command(True)
        self.assertNotIn("--runtime-uefi-validation", disabled)
        self.assertEqual(enabled.count("--runtime-uefi-validation"), 1)
        self.assertNotIn("--runtime-uefi-loader", enabled)
        self.assertNotIn("--runtime-uefi-loader-sha256", enabled)
        self.assertEqual(enabled[:-1], disabled)

    def test_runtime_validation_requires_explicit_boolean(self):
        for value in (1, "true", None, [], {}):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "explicit boolean"):
                    self.base_command(value)


class RuntimeIntegrityGUISourceTests(unittest.TestCase):
    def test_guarded_unsigned_wording_and_no_asset_picker(self):
        with open("gui/rufusarm64_persistence.py", encoding="utf-8") as handle:
            source = handle.read()
        self.assertIn("Validate media at UEFI boot", source)
        self.assertIn("Unsigned development loader — Secure Boot compatibility is not established", source)
        self.assertIn("EFI/BOOT/bootaa64_original.efi", source)
        self.assertIn("self.runtime_uefi_validation.set_sensitive(False)", source)
        self.assertIn("self.runtime_uefi_validation.set_sensitive(True)", source)
        self.assertIn("runtime_validation_requested", source)
        self.assertNotIn("Gtk.FileChooserButton(title=\"Choose an EFI", source)
        self.assertNotIn("runtime_uefi_loader_path", source)
        self.assertNotIn("runtime_uefi_loader_sha256", source)


if __name__ == "__main__":
    unittest.main()
