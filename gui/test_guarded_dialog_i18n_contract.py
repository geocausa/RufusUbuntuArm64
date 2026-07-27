from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent.parent
I18N = ROOT / "gui" / "rufusarm64_i18n.py"
DIALOGS = (
    ROOT / "gui" / "rufusarm64_nonbootable_dialog.py",
    ROOT / "gui" / "rufusarm64_freedos_dialog.py",
)


class GuardedDialogLocalizationContractTests(unittest.TestCase):
    def test_runtime_wraps_exact_loaded_dialog_classes_after_original_construction(self):
        text = I18N.read_text(encoding="utf-8")
        for marker in (
            '("rufusarm64_nonbootable_dialog", "NonBootableFormatDialog")',
            '("rufusarm64_freedos_dialog", "FreeDOSFormatDialog")',
            "def install_guarded_dialog_localization():",
            "module = sys.modules.get(module_name)",
            'if dialog_class is None or getattr(dialog_class, "_localization_installed", False):',
            "_original_init(dialog, *args, **kwargs)",
            "GLib.idle_add(translate_widget_tree, dialog)",
            "dialog_class._localization_installed = True",
            "install_guarded_dialog_localization()",
        ):
            self.assertIn(marker, text)

    def test_widget_runtime_covers_dialog_shell_fields_without_broad_dynamic_translation(self):
        text = I18N.read_text(encoding="utf-8")
        for marker in (
            "def translate_widget_tree(widget, translation=None):",
            "isinstance(widget, Gtk.Window)",
            "isinstance(widget, Gtk.Entry)",
            "isinstance(widget, Gtk.ProgressBar)",
            "isinstance(widget, Gtk.TextView)",
            'N_("Create non-bootable media")',
            'N_("FreeDOS 1.4 — x86 BIOS/Legacy media")',
            'N_("Type the exact FORMAT phrase")',
            'N_("Type the exact WRITE FREEDOS phrase")',
        ):
            self.assertIn(marker, text)
        for forbidden in (
            'N_("FORMAT /dev',
            'N_("WRITE FREEDOS /dev',
            'N_("device_path")',
            'N_("identity")',
        ):
            self.assertNotIn(forbidden, text)

    def test_dialog_operation_sources_do_not_import_localization_or_change_exact_confirmation(self):
        for path in DIALOGS:
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertNotIn("rufusarm64_i18n", text)
                self.assertIn(
                    "self.confirmation.get_text().strip() == confirmation_phrase(self.plan)",
                    text,
                )
                self.assertIn("expected = confirmation_phrase(self.plan)", text)


if __name__ == "__main__":
    unittest.main()
