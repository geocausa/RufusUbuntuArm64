from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent.parent
I18N = ROOT / "gui" / "rufusarm64_i18n.py"
GUARDED_DIALOGS = (
    ROOT / "gui" / "rufusarm64_nonbootable_dialog.py",
    ROOT / "gui" / "rufusarm64_freedos_dialog.py",
)
CHECKSUM_DIALOG = ROOT / "gui" / "rufusarm64_checksums.py"
FFU_DIALOG = ROOT / "gui" / "rufusarm64_ffu_dialog.py"


class SecondaryDialogLocalizationContractTests(unittest.TestCase):
    def test_runtime_wraps_exact_loaded_dialog_classes_after_original_construction(self):
        text = I18N.read_text(encoding="utf-8")
        for marker in (
            '("rufusarm64_checksums", "ChecksumDialog")',
            '("rufusarm64_device_qualify_dialog", "DeviceQualificationDialog")',
            '("rufusarm64_device_qualify_dialog", "DriveImageBackupDialog")',
            '("rufusarm64_ffu_dialog", "FFUReviewDialog")',
            '("rufusarm64", "WindowsOptionsDialog")',
            '("rufusarm64", "AcquisitionDialog")',
            '("rufusarm64_persistence", "Window")',
            '("rufusarm64_nonbootable_dialog", "NonBootableFormatDialog")',
            '("rufusarm64_freedos_dialog", "FreeDOSFormatDialog")',
            "def install_secondary_dialog_localization():",
            "module = sys.modules.get(module_name)",
            'if dialog_class is None or getattr(dialog_class, "_localization_installed", False):',
            "_original_init(dialog, *args, **kwargs)",
            "GLib.idle_add(translate_widget_tree, dialog)",
            "dialog_class._localization_installed = True",
            "install_secondary_dialog_localization()",
        ):
            self.assertIn(marker, text)

    def test_widget_runtime_covers_secondary_shell_fields_without_broad_dynamic_translation(self):
        text = I18N.read_text(encoding="utf-8")
        for marker in (
            "def translate_widget_tree(widget, translation=None):",
            "isinstance(widget, Gtk.Window)",
            "isinstance(widget, Gtk.Entry)",
            "isinstance(widget, Gtk.ProgressBar)",
            "isinstance(widget, Gtk.TextView)",
            'N_("Image checksums")',
            'N_("Check USB drive")',
            'N_("Save drive image")',
            'N_("Review Full Flash Update")',
            'N_("Create non-bootable media")',
            'N_("FreeDOS 1.4 — x86 BIOS/Legacy media")',
            'N_("Type the exact FORMAT phrase")',
            'N_("Type the exact WRITE FREEDOS phrase")',
        ):
            self.assertIn(marker, text)
        for forbidden in (
            'N_("FORMAT /dev',
            'N_("WRITE FREEDOS /dev',
            'N_("RESTORE AUTHENTICATED FFU TO /dev',
            'N_("device_path")',
            'N_("identity")',
        ):
            self.assertNotIn(forbidden, text)

    def test_guarded_operation_sources_remain_localization_free_and_exactly_confirmed(self):
        for path in GUARDED_DIALOGS:
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertNotIn("rufusarm64_i18n", text)
                self.assertIn(
                    "self.confirmation.get_text().strip() == confirmation_phrase(self.plan)",
                    text,
                )
                self.assertIn("expected = confirmation_phrase(self.plan)", text)

    def test_checksum_operation_source_remains_localization_free_and_descriptor_bound(self):
        text = CHECKSUM_DIALOG.read_text(encoding="utf-8")
        self.assertNotIn("rufusarm64_i18n", text)
        for marker in (
            "command = build_checksum_command(self.helper, self.image_path)",
            "normalized = normalize_checksum_result(json.loads(completed.stdout))",
            "self.report = checksum_summary(payload)",
            "set_text(self.report, -1)",
        ):
            self.assertIn(marker, text)


def test_ffu_operation_source_remains_localization_free_and_evidence_bound(self):
    text = FFU_DIALOG.read_text(encoding="utf-8")
    self.assertNotIn("rufusarm64_i18n", text)
    for marker in (
        "command = build_ffu_review_command(",
        "command = build_ffu_restore_command(",
        'self.review.get("exact_confirmation_phrase")',
        "expected_review = copy.deepcopy(self.review_payload)",
        "normalized = normalize_ffu_restore_output(payload, expected_review)",
        "strict_json_loads(stdout)",
        "communicate_bounded(",
        "start_new_session=True",
        "os.killpg(process.pid, signal.SIGTERM)",
        "json.dumps(payload, indent=2, sort_keys=True)",
    ):
        self.assertIn(marker, text)


if __name__ == "__main__":
    unittest.main()
