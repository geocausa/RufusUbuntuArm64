import os
import tempfile
import unittest

from rufusarm64_logic import (
    acquisition_image_label,
    build_acquisition_channel_download_command,
    build_acquisition_channel_list_command,
    build_acquisition_download_command,
    build_acquisition_list_command,
    build_persistence_analyze_command,
    build_persistence_plan_command,
    build_writer_command,
    device_label,
    human_bytes,
    human_duration,
    human_rate,
    inspect_source_identity,
    normalize_acquisition_channel,
    normalize_acquisition_images,
    persistence_plan_summary,
    progress_status,
    normalize_cluster_size,
    normalize_filesystem,
    normalize_partition_scheme,
    normalize_target_system,
    normalize_volume_label,
    success_message,
    normalize_windows_locale,
    supported_image_name,
    validate_local_username,
    windows_timezone_for_iana,
)


class LogicTests(unittest.TestCase):
    def test_human_bytes(self):
        self.assertEqual(human_bytes(1024), "1.0 KiB")

    def test_progress_formatting(self):
        self.assertEqual(human_rate(1024), "1.0 KiB/s")
        self.assertEqual(human_duration(65), "1:05")
        self.assertEqual(human_duration(3661), "1:01:01")
        text = progress_status("write", 512, 1024, 256)
        self.assertIn("Write: 50.0%", text)
        self.assertIn("512 B of 1.0 KiB", text)
        self.assertIn("256 B/s", text)
        self.assertIn("0:02 remaining", text)
        self.assertEqual(progress_status("prepare", 0, 0), "Prepare")

    def test_acquisition_commands_and_catalog_normalization(self):
        command = build_acquisition_list_command("/helper", "catalog.json", "catalog.sig", "catalog.pub")
        self.assertEqual(command[-1], "--json")
        images = normalize_acquisition_images([{
            "id": "ubuntu-24.04-arm64",
            "name": "Ubuntu Desktop",
            "architecture": "arm64",
            "version": "24.04.2",
            "filename": "ubuntu.iso",
            "size": 4 * 1024**3,
            "sha256": "a" * 64,
        }])
        self.assertIn("Ubuntu Desktop 24.04.2", acquisition_image_label(images[0]))
        download = build_acquisition_download_command(
            "/helper", "catalog.json", "catalog.sig", "catalog.pub", images[0]["id"], "/downloads"
        )
        self.assertEqual(download[1:3], ["acquire", "download"])
        self.assertNotIn("pkexec", download)
        self.assertIn("--json-progress", download)
        with self.assertRaises(ValueError):
            normalize_acquisition_images([{
                "id": "duplicate", "name": "One", "filename": "one.iso", "size": 1
            }, {
                "id": "duplicate", "name": "Two", "filename": "two.iso", "size": 2
            }])

    def test_built_in_acquisition_channel_commands_and_metadata(self):
        listing = build_acquisition_channel_list_command(
            "/helper", "/usr/share/rufusarm64/acquisition/channel.json"
        )
        self.assertEqual(listing[1:4], ["acquire", "channel", "list"])
        self.assertNotIn("pkexec", listing)
        payload = normalize_acquisition_channel({
            "root_version": 2,
            "root_expires": "2027-07-16T00:00:00Z",
            "root_sha256": "d" * 64,
            "catalog_version": 7,
            "catalog_generated": "2026-07-16T12:00:00Z",
            "catalog_expires": "2026-07-23T12:00:00Z",
            "catalog_sha256": "b" * 64,
            "signing_key_ids": ["c" * 64],
            "from_cache": False,
            "images": [{
                "id": "ubuntu-24.04-arm64",
                "name": "Ubuntu Desktop",
                "architecture": "arm64",
                "version": "24.04.2",
                "filename": "ubuntu.iso",
                "size": 4 * 1024**3,
                "sha256": "a" * 64,
            }],
        })
        self.assertEqual(payload["catalog_version"], 7)
        self.assertEqual(len(payload["images"]), 1)
        download = build_acquisition_channel_download_command(
            "/helper", "/usr/share/rufusarm64/acquisition/channel.json",
            payload["images"][0]["id"], "/downloads",
        )
        self.assertEqual(download[1:4], ["acquire", "channel", "download"])
        self.assertIn("--json-progress", download)
        self.assertNotIn("--public-key", download)
        with self.assertRaises(ValueError):
            normalize_acquisition_channel({"images": []})

    def test_automatic_persistence_analysis_command_is_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            image_path = os.path.join(directory, "ubuntu.iso")
            with open(image_path, "wb") as handle:
                handle.write(b"iso")
            resolved, identity = inspect_source_identity(image_path)
        self.assertEqual(resolved, os.path.realpath(image_path))
        self.assertEqual(len(identity.split(":")), 5)
        command = build_persistence_analyze_command(
            "/usr/bin/pkexec", "/helper", resolved, identity, 64 * 1024**3, 16,
            "/run/user/1000/rufusarm64-analysis.cancel",
        )
        self.assertEqual(command[:4], ["/usr/bin/pkexec", "/helper", "persistence", "analyze"])
        self.assertIn("--expected-source-identity", command)
        self.assertIn("--cancel-file", command)
        self.assertIn("--json", command)
        self.assertNotIn("write", command)
        self.assertNotIn("--experimental-persistence", command)
        self.assertNotIn("--media-root", command)
        with self.assertRaises(ValueError):
            build_persistence_analyze_command("pkexec", "/helper", resolved, "", 1, 0, "/tmp/cancel")

    def test_persistence_plan_command_and_summary(self):
        command = build_persistence_plan_command(
            "/helper", "/images/ubuntu.iso", "/mnt/ubuntu", 64 * 1024**3, 16
        )
        self.assertEqual(command[1:3], ["persistence", "plan"])
        self.assertNotIn("write", command)
        self.assertNotIn("--experimental-persistence", command)
        self.assertEqual(command[command.index("--size") + 1], "16G")
        summary = persistence_plan_summary({
            "detection": {"display_name": "Ubuntu 24.04 ARM64", "family": "ubuntu-casper"},
            "plan": {
                "filesystem": "ext4",
                "filesystem_label": "casper-rw",
                "size_bytes": 16 * 1024**3,
                "boot_parameter": "persistent",
                "patch_paths": ["boot/grub/grub.cfg"],
            },
        })
        self.assertIn("Compatible media", summary)
        self.assertIn("16.0 GiB", summary)
        self.assertIn("guarded persistent USB creator", summary)

    def test_supported_image_name(self):
        self.assertTrue(supported_image_name("Windows.ISO"))
        self.assertTrue(supported_image_name("archive.zip"))

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


    def test_success_message_matches_verification_mode(self):
        self.assertIn("verified successfully", success_message("windows", True))
        windows_skipped = success_message("windows", False)
        self.assertIn("filesystem check passed", windows_skipped)
        self.assertIn("verification was skipped", windows_skipped)
        raw_skipped = success_message("raw", False)
        self.assertIn("Verification was skipped", raw_skipped)

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
            "mbr",
            "bios",
            "ntfs",
            "8192",
            "/drivers",
            "/cache/arm64-DBXUpdate.bin",
            False,
            True,
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
            "--partition-scheme",
            "--target-system",
            "--filesystem",
            "--cluster-size",
            "--driver-folder",
            "--dbx-file",
            "--full-format",
            "--bad-block-check",
        ):
            self.assertIn(flag, command)
        self.assertEqual(command[command.index("--volume-label") + 1], "WIN11")


    def test_drive_option_validation(self):
        self.assertEqual(normalize_partition_scheme("MBR"), "mbr")
        self.assertEqual(normalize_target_system("legacy-bios"), "bios")
        self.assertEqual(normalize_filesystem("NTFS"), "ntfs")
        self.assertEqual(normalize_cluster_size("8KiB".replace("KiB", "192")), "8192")
        with self.assertRaises(ValueError):
            normalize_partition_scheme("apm")
        with self.assertRaises(ValueError):
            normalize_target_system("openfirmware")
        with self.assertRaises(ValueError):
            normalize_filesystem("ext4")
        with self.assertRaises(ValueError):
            normalize_cluster_size("65536")

    def test_bios_requires_mbr(self):
        with self.assertRaises(ValueError):
            build_writer_command(
                "pkexec", "/helper", "/image.iso", "/dev/sda", "abc", False, "/tmp/cancel",
                partition_scheme="gpt", target_system="bios"
            )

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
