#!/usr/bin/env python3
from pathlib import Path


def replace_once(path_name, old, new):
    path = Path(path_name)
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one match, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_once(
    "gui/rufusarm64_logic.py",
    '''def success_message(mode, verify_requested, filesystem="auto"):
    """Return an accurate GUI completion message for the selected job."""
    if verify_requested:
        return "The bootable USB was created and verified successfully. Remove it safely before unplugging it."
    if mode == "windows":
        filesystem_name = "NTFS" if filesystem == "ntfs" else "FAT32" if filesystem == "fat32" else "selected"
        return (
            f"The bootable USB was created successfully. The {filesystem_name} filesystem check passed, "
            "but copied-file verification was skipped. Remove it safely before unplugging it."
        )
    return "The bootable USB was created successfully. Verification was skipped. Remove it safely before unplugging it."
''',
    '''def success_message(mode, verify_requested, filesystem="auto"):
    """Describe completed software checks without implying a firmware boot guarantee."""
    qualification = (
        "This does not prove firmware boot or Secure Boot acceptance; test the media on the intended computer. "
        "Remove it safely before unplugging it."
    )
    if verify_requested:
        return "USB media creation completed. Copied-data verification passed. " + qualification
    if mode == "windows":
        filesystem_name = "NTFS" if filesystem == "ntfs" else "FAT32" if filesystem == "fat32" else "selected"
        return (
            f"USB media creation completed. The {filesystem_name} filesystem consistency check passed, "
            "but copied-file verification was skipped. " + qualification
        )
    return "USB media creation completed. Copied-data verification was skipped. " + qualification
''',
)
replace_once(
    "gui/test_logic.py",
    '''    def test_success_message_matches_verification_mode(self):
        self.assertIn("verified successfully", success_message("windows", True))
        windows_skipped = success_message("windows", False)
        self.assertIn("filesystem check passed", windows_skipped)
        self.assertIn("verification was skipped", windows_skipped)
        raw_skipped = success_message("raw", False)
        self.assertIn("Verification was skipped", raw_skipped)
''',
    '''    def test_success_message_matches_verification_mode(self):
        verified = success_message("windows", True)
        self.assertIn("Copied-data verification passed", verified)
        self.assertIn("does not prove firmware boot", verified)
        windows_skipped = success_message("windows", False, "ntfs")
        self.assertIn("NTFS filesystem consistency check passed", windows_skipped)
        self.assertIn("copied-file verification was skipped", windows_skipped)
        raw_skipped = success_message("raw", False)
        self.assertIn("Copied-data verification was skipped", raw_skipped)
        self.assertIn("Secure Boot acceptance", raw_skipped)
''',
)
replace_once(
    "gui/rufusarm64.py",
    '''            self.progress.set_text("USB created successfully")
            self.progress_detail.set_text("The operation completed successfully. A diagnostic report can be saved from Details.")
''',
    '''            self.progress.set_text("USB media creation completed")
            self.progress_detail.set_text("Software checks completed. Firmware boot still requires testing on the intended computer.")
''',
)
replace_once(
    "gui/rufusarm64_persistence.py",
    '''            self.progress.set_text("Persistent live USB created and verified")
            self.detail.set_text("Boot the USB, then qualify persistence across one reboot.")
''',
    '''            self.progress.set_text("Persistent live USB creation completed")
            self.detail.set_text("Internal checks passed. Boot the USB, then qualify persistence across one reboot.")
''',
)
