import unittest

from rufusarm64_logic import (
    WINDOWS_TO_GO_CONFIRMATION,
    build_writer_command,
    plan_windows_to_go_target,
)


class WindowsToGoLogicTests(unittest.TestCase):
    @staticmethod
    def analysis(enabled=True, reason=""):
        return {
            "default_target_system": "uefi",
            "default_filesystem": "ntfs",
            "capabilities": {
                "windows_to_go": {"enabled": enabled, "reason": reason},
            },
            "metadata": {
                "image_count": 2,
                "images": [
                    {"index": 1, "name": "Windows 11 Home", "default_language": "en-GB", "total_bytes": 25_756_058_291},
                    {"index": 3, "name": "Windows 11 Pro", "default_language": "en-GB", "total_bytes": 26_512_641_594},
                ],
            },
        }

    @staticmethod
    def options(**overrides):
        value = {
            "windows_to_go": True,
            "install_image_index": 3,
            "install_image_name": "Windows 11 Pro",
        }
        value.update(overrides)
        return value

    def build(self, **kwargs):
        values = dict(
            pkexec="/usr/bin/pkexec", helper="/usr/lib/rufusarm64/rufusarm64-helper",
            image="/image.iso", path="/dev/sdz", identity="target-token", verify=False,
            cancel_path="/run/user/1000/cancel", windows_options=self.options(),
            windows_capability_analysis=self.analysis(),
        )
        values.update(kwargs)
        return build_writer_command(**values)

    def test_command_is_exact_and_has_no_installer_flags(self):
        command = self.build()
        self.assertEqual(command[command.index("--mode") + 1], "windows-to-go")
        self.assertEqual(command[command.index("--win-to-go-image-index") + 1], "3")
        self.assertEqual(command[command.index("--win-to-go-confirm") + 1], WINDOWS_TO_GO_CONFIRMATION)
        for forbidden in (
            "--partition-scheme", "--target-system", "--filesystem", "--cluster-size",
            "--volume-label", "--verify", "--win-silent-install", "--win-local-user",
            "--driver-folder", "--dbx-file", "--full-format", "--bad-block-check",
        ):
            self.assertNotIn(forbidden, command)

    def test_rejects_unqualified_or_incomplete_media(self):
        with self.assertRaisesRegex(ValueError, "not qualified"):
            self.build(windows_capability_analysis=self.analysis(False, "not qualified"))
        for options in (
            self.options(install_image_index=2),
            self.options(install_image_index=0),
        ):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.build(windows_options=options)
        incomplete = self.analysis()
        incomplete["metadata"]["images"][1]["total_bytes"] = 0
        with self.assertRaisesRegex(ValueError, "expanded-size"):
            self.build(windows_capability_analysis=incomplete)

    def test_rejects_every_installer_only_surface(self):
        cases = [
            {"windows_options": self.options(local_user="Tester")},
            {"windows_options": self.options(silent_install=True)},
            {"driver_folder": "/drivers"},
            {"dbx_file": "/dbx.bin"},
            {"quick_format": False},
            {"bad_block_check": True},
        ]
        for case in cases:
            with self.subTest(case=case), self.assertRaisesRegex(ValueError, "cannot be combined"):
                self.build(**case)

    def test_target_planner_matches_backend_geometry(self):
        plan = plan_windows_to_go_target(
            self.analysis(),
            {"size": 31_379_685_376, "logical_sector_size": 512},
            3,
        )
        self.assertEqual(plan["image"]["index"], 3)
        self.assertEqual(plan["esp_size"], 260 * 1024**2)
        self.assertGreaterEqual(plan["windows_partition_size"] - plan["image"]["total_bytes"], 2 * 1024**3)
        plan4k = plan_windows_to_go_target(
            self.analysis(),
            {"size": 32 * 1024**3, "logical_sector_size": 4096},
            1,
        )
        self.assertEqual(plan4k["logical_sector_size"], 4096)

    def test_target_planner_rejects_sector_and_capacity_failures(self):
        for device in (
            {"size": 32 * 1024**3, "logical_sector_size": 2048},
            {"size": 28 * 1024**3, "logical_sector_size": 512},
            {"size": 29 * 1024**3 + 1, "logical_sector_size": 512},
        ):
            with self.subTest(device=device), self.assertRaises(ValueError):
                plan_windows_to_go_target(self.analysis(), device, 3)
        huge = self.analysis()
        huge["metadata"]["images"][1]["total_bytes"] = 31 * 1024**3
        with self.assertRaisesRegex(ValueError, "headroom"):
            plan_windows_to_go_target(huge, {"size": 32 * 1024**3, "logical_sector_size": 512}, 3)


if __name__ == "__main__":
    unittest.main()
