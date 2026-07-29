import tempfile
from pathlib import Path
import unittest

from rufusarm64_logic import build_writer_command


class WindowsSkuSiPolicyCommandTests(unittest.TestCase):
    def base(self, target_system="uefi", options=None):
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
                windows_options=options or {},
                partition_scheme="gpt" if target_system == "uefi" else "mbr",
                target_system=target_system,
                filesystem="fat32",
            )

    def test_binds_policy_flag_for_uefi(self):
        command = self.base(options={"apply_sku_si_policy": True})
        self.assertIn("--win-apply-sku-si-policy", command)

    def test_rejects_policy_for_bios(self):
        with self.assertRaisesRegex(ValueError, "requires a UEFI"):
            self.base(target_system="bios", options={"apply_sku_si_policy": True})


if __name__ == "__main__":
    unittest.main()
