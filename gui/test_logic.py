import unittest

from rufusarm64_logic import (
    build_writer_command,
    device_label,
    human_bytes,
    normalize_volume_label,
    normalize_windows_locale,
    supported_image_name,
    validate_local_username,
    windows_timezone_for_iana,
)


class LogicTests(unittest.TestCase):
    def test_human_bytes(self):
        self.assertEqual(human_bytes(1024), "1.0 KiB")

    def test_supported_image_name(self):
        self.assertTrue(supported_image_name("Windows.ISO"))
        self.assertFalse(supported_image_name("archive.zip"))

    def test_device_label(self):
        label = device_label({"path": "/dev/sda", "vendor": "ACME", "model": "Stick", "size": 1024, "tran": "usb"})
        self.assertIn("/dev/sda", label)
        self.assertIn("USB", label)

    def test_username_validation(self):
        self.assertEqual(validate_local_username("geoca"), "geoca")
        for bad in ("Administrator", "a/b", "Geo & Co", "percent%name", "caret^name", "bang!name", " leading", "trailing ", "x" * 21, "trail."):
            with self.assertRaises(ValueError):
                validate_local_username(bad)

    def test_volume_label(self):
        self.assertEqual(normalize_volume_label("Win 11"), "WIN 11")
        with self.assertRaises(ValueError):
            normalize_volume_label("way-too-long-label")

    def test_writer_command_carries_windows_options(self):
        command = build_writer_command(
            "pkexec",
            "/helper",
            "/image.iso",
            "/dev/sda",
            "abc",
            True,
            "/run/user/1000/rufusarm64-x.cancel",
            "WIN11",
            {
                "bypass_hardware": True,
                "bypass_online_account": True,
                "local_user": "geoca",
                "reduce_data_collection": True,
                "disable_bitlocker": True,
                "use_regional_settings": True,
                "locale": "en_GB.UTF-8",
                "timezone": "GMT Standard Time",
            },
        )
        for flag in (
            "--expected-identity",
            "--verify",
            "--cancel-file",
            "--win-bypass-hardware",
            "--win-bypass-online-account",
            "--win-local-user",
            "--win-reduce-data-collection",
            "--win-disable-bitlocker",
            "--win-locale",
            "--win-timezone",
        ):
            self.assertIn(flag, command)
        self.assertEqual(command[command.index("--volume-label") + 1], "WIN11")


    def test_regional_normalization(self):
        self.assertEqual(normalize_windows_locale("en_GB.UTF-8"), "en-GB")
        self.assertEqual(normalize_windows_locale("C.UTF-8"), "")
        self.assertEqual(windows_timezone_for_iana("Europe/London"), "GMT Standard Time")
        self.assertEqual(windows_timezone_for_iana("Unknown/Zone"), "")

    def test_writer_command_refuses_missing_identity(self):
        with self.assertRaises(ValueError):
            build_writer_command("pkexec", "/helper", "/image.iso", "/dev/sda", "", True, "/tmp/cancel")


if __name__ == "__main__":
    unittest.main()
