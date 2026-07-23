import os
import tempfile
import unittest

from rufusarm64_logic import (
    acquisition_image_label,
    atomic_write_json,
    build_acquisition_channel_download_command,
    build_checksum_command,
    build_acquisition_channel_list_command,
    build_acquisition_download_command,
    build_acquisition_list_command,
    build_persistence_analyze_command,
    build_persistence_plan_command,
    build_uefi_validate_command,
    build_writer_command,
    checksum_summary,
    device_label,
    human_bytes,
    human_duration,
    human_rate,
    inspect_source_identity,
    normalize_acquisition_channel,
    normalize_acquisition_images,
    normalize_checksum_result,
    persistence_plan_summary,
    progress_status,
    normalize_cluster_size,
    normalize_filesystem,
    normalize_partition_scheme,
    normalize_target_system,
    normalize_uefi_validation,
    normalize_volume_label,
    success_message,
    uefi_validation_summary,
    normalize_windows_locale,
    supported_image_name,
    validate_local_username,
    windows_timezone_for_iana,
)


class LogicTests(unittest.TestCase):
    def test_atomic_write_json_is_owner_only_and_replaces(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "settings.json")
            atomic_write_json(path, {"value": 1})
            atomic_write_json(path, {"value": 2})
            with open(path, "r", encoding="utf-8") as handle:
                self.assertEqual(handle.read(), '{\n  "value": 2\n}')
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            self.assertEqual(sorted(os.listdir(directory)), ["settings.json"])

    def test_atomic_write_json_rejects_symlink_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            real = os.path.join(directory, "real")
            linked = os.path.join(directory, "linked")
            os.mkdir(real)
            os.symlink(real, linked)
            with self.assertRaises(OSError):
                atomic_write_json(os.path.join(linked, "settings.json"), {"unsafe": True})

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

    def test_checksum_command_and_normalization_are_read_only(self):
        command = build_checksum_command("/helper", "/images/ubuntu.iso")
        self.assertEqual(command, ["/helper", "hash", "--all", "--json", "/images/ubuntu.iso"])
        self.assertNotIn("pkexec", command)
        self.assertNotIn("write", command)
        payload = normalize_checksum_result({
            "path": "/images/ubuntu.iso",
            "size": 4096,
            "digests": [
                {"algorithm": "md5", "hex": "a" * 32},
                {"algorithm": "sha1", "hex": "b" * 40},
                {"algorithm": "sha256", "hex": "c" * 64},
                {"algorithm": "sha512", "hex": "d" * 128},
            ],
        })
        self.assertEqual([item["algorithm"] for item in payload["digests"]], ["md5", "sha1", "sha256", "sha512"])
        summary = checksum_summary(payload)
        self.assertIn("MD5: " + "a" * 32, summary)
        self.assertIn("SHA-512: " + "d" * 128, summary)
        self.assertIn("legacy published checksums", summary)

    def test_checksum_normalization_rejects_incomplete_or_ambiguous_results(self):
        valid = {
            "path": "/images/ubuntu.iso",
            "size": 1,
            "digests": [
                {"algorithm": "md5", "hex": "a" * 32},
                {"algorithm": "sha1", "hex": "b" * 40},
                {"algorithm": "sha256", "hex": "c" * 64},
                {"algorithm": "sha512", "hex": "d" * 128},
            ],
        }
        for payload in (
            None,
            {**valid, "path": "relative.iso"},
            {**valid, "size": 0},
            {**valid, "digests": valid["digests"][:-1]},
            {**valid, "digests": [valid["digests"][1], valid["digests"][0], *valid["digests"][2:]]},
            {**valid, "digests": [{**valid["digests"][0], "hex": "A" * 32}, *valid["digests"][1:]]},
        ):
            with self.assertRaises(ValueError):
                normalize_checksum_result(payload)
        with self.assertRaises(ValueError):
            build_checksum_command("", "/images/ubuntu.iso")
        with self.assertRaises(ValueError):
            build_checksum_command("/helper", "")

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
        verified = success_message("windows", True)
        self.assertIn("Copied-data verification passed", verified)
        self.assertIn("does not prove firmware boot", verified)
        windows_skipped = success_message("windows", False, "ntfs")
        self.assertIn("NTFS filesystem consistency check passed", windows_skipped)
        self.assertIn("copied-file verification was skipped", windows_skipped)
        raw_skipped = success_message("raw", False)
        self.assertIn("Copied-data verification was skipped", raw_skipped)
        self.assertIn("Secure Boot acceptance", raw_skipped)

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
        self.assertEqual(normalize_partition_scheme(None), "auto")
        self.assertEqual(normalize_partition_scheme("MBR"), "mbr")
        self.assertEqual(normalize_target_system(None), "auto")
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

    def test_writer_defaults_are_image_derived_and_verification_is_opt_in(self):
        command = build_writer_command(
            "pkexec", "/helper", "/image.iso", "/dev/sda", "abc", False, "/tmp/cancel"
        )
        self.assertEqual(command[command.index("--partition-scheme") + 1], "auto")
        self.assertEqual(command[command.index("--target-system") + 1], "auto")
        self.assertEqual(command[command.index("--filesystem") + 1], "auto")
        self.assertEqual(command[command.index("--cluster-size") + 1], "auto")
        for flag in ("--verify", "--full-format", "--bad-block-check"):
            self.assertNotIn(flag, command)
        bios_auto = build_writer_command(
            "pkexec", "/helper", "/image.iso", "/dev/sda", "abc", False, "/tmp/cancel",
            partition_scheme="auto", target_system="bios",
        )
        self.assertEqual(bios_auto[bios_auto.index("--partition-scheme") + 1], "auto")
        self.assertEqual(bios_auto[bios_auto.index("--target-system") + 1], "bios")

    def test_regional_normalization(self):
        self.assertEqual(normalize_windows_locale("en_GB.UTF-8"), "en-GB")
        self.assertEqual(normalize_windows_locale("C.UTF-8"), "")
        self.assertEqual(windows_timezone_for_iana("Europe/London"), "GMT Standard Time")
        self.assertEqual(windows_timezone_for_iana("Unknown/Zone"), "")

    def test_writer_command_refuses_missing_identity(self):
        with self.assertRaises(ValueError):
            build_writer_command("pkexec", "/helper", "/image.iso", "/dev/sda", "", True, "/tmp/cancel")


    def test_uefi_validation_command_is_read_only(self):
        command = build_uefi_validate_command(
            "/helper", "/mnt/usb", "aarch64", 1024, True, "/cache/dbx.bin", False
        )
        self.assertEqual(command[:3], ["/helper", "uefi", "validate"])
        self.assertEqual(command[command.index("--arch") + 1], "arm64")
        self.assertEqual(command[command.index("--max-files") + 1], "1024")
        self.assertIn("--require-fallback=true", command)
        self.assertIn("--dbx", command)
        self.assertEqual(command[-1], "--json")
        self.assertNotIn("pkexec", command)
        self.assertNotIn("write", command)
        with self.assertRaises(ValueError):
            build_uefi_validate_command("/helper", "/mnt/usb", dbx_file="dbx.bin", firmware=True)
        with self.assertRaises(ValueError):
            build_uefi_validate_command("/helper", "/mnt/usb", max_files=4097)
        firmware_sbat = build_uefi_validate_command(
            "/helper", "/mnt/usb", firmware_sbat=True
        )
        self.assertIn("--firmware-sbat", firmware_sbat)
        local_sbat = build_uefi_validate_command(
            "/helper", "/mnt/usb", sbat_level_file="/trust/SbatLevel.csv"
        )
        self.assertEqual(local_sbat[local_sbat.index("--sbat-level") + 1], "/trust/SbatLevel.csv")
        with self.assertRaises(ValueError):
            build_uefi_validate_command(
                "/helper", "/mnt/usb", sbat_level_file="local.csv", firmware_sbat=True
            )

    def test_uefi_validation_normalization_and_summary(self):
        payload = {
            "root": "/mnt/usb",
            "architecture": "arm64",
            "fallback_path": "EFI/BOOT/BOOTAA64.EFI",
            "fallback_found": True,
            "dbx_checked": True,
            "sbat_level_checked": True,
            "sbat_level_source": "/sys/firmware/efi/efivars/SbatLevelRT-605dab50-e046-4300-abb6-3dd810dd8b23",
            "sbat_level_datestamp": "2025051000",
            "valid": True,
            "revoked": False,
            "files": [{
                "path": "EFI/BOOT/BOOTAA64.EFI",
                "machine_name": "ARM64",
                "subsystem_name": "EFI application",
                "fallback": True,
                "embedded_certificates": 2,
                "sbat": [{"component": "shim"}],
                "sbat_revoked": True,
                "sbat_revocations": [{
                    "component": "shim",
                    "image_generation": 3,
                    "minimum_generation": 4,
                }],
            }],
        }
        normalized = normalize_uefi_validation(payload)
        self.assertTrue(normalized["valid"])
        self.assertEqual(normalized["files"][0]["sbat_records"], 1)
        summary = uefi_validation_summary(payload)
        self.assertIn("Validation passed", summary)
        self.assertIn("BOOTAA64.EFI", summary)
        self.assertIn("SBAT source:", summary)
        self.assertIn("SBAT revoked: shim generation 3", summary)
        self.assertIn("does not prove", summary)
        with self.assertRaises(ValueError):
            normalize_uefi_validation({"root": "/mnt/usb", "files": []})


if __name__ == "__main__":
    unittest.main()
