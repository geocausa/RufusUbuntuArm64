from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent.parent
I18N = ROOT / "gui" / "rufusarm64_i18n.py"
DIALOGS = (
    ROOT / "gui" / "rufusarm64_nonbootable_dialog.py",
    ROOT / "gui" / "rufusarm64_freedos_dialog.py",
)


class GuardedDialogLocalizationContractTests(unittest.TestCase):
    def test_each_dialog_defers_exact_widget_tree_translation_after_initial_plan_state(self):
        for path in DIALOGS:
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertIn("from rufusarm64_i18n import translate_widget_tree", text)
                shown = text.index("        self.show_all()")
                planned = text.index("        self.refresh_plan()", shown)
                translated = text.index("        GLib.idle_add(translate_widget_tree, self)", planned)
                self.assertLess(shown, planned)
                self.assertLess(planned, translated)

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

    def test_exact_generated_confirmation_comparisons_remain_unchanged(self):
        nonbootable = DIALOGS[0].read_text(encoding="utf-8")
        freedos = DIALOGS[1].read_text(encoding="utf-8")
        self.assertIn(
            "self.confirmation.get_text().strip() == confirmation_phrase(self.plan)",
            nonbootable,
        )
        self.assertIn(
            "self.confirmation.get_text().strip() == confirmation_phrase(self.plan)",
            freedos,
        )
        self.assertIn("expected = confirmation_phrase(self.plan)", nonbootable)
        self.assertIn("expected = confirmation_phrase(self.plan)", freedos)


if __name__ == "__main__":
    unittest.main()
