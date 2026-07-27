from pathlib import Path
import sys
import tempfile
import unittest


GUI_DIR = Path(__file__).resolve().parent
if str(GUI_DIR) not in sys.path:
    sys.path.insert(0, str(GUI_DIR))

from test_i18n import Button, Label, TextView, Window, load_i18n_module, write_mo


QUALIFICATION_DIALOG = GUI_DIR / "rufusarm64_device_qualify_dialog.py"


class DeviceQualificationLocalizationTests(unittest.TestCase):
    def test_static_shell_translates_with_real_catalog_and_preserves_profile_and_erase_contracts(self):
        module, _ = load_i18n_module()
        intro_source = (
            "This is a separate destructive USB qualification test. It overwrites every tested region and does not "
            "preserve files or partitions. The normal Create USB workflow is not changed."
        )
        warning_source = (
            "Running the test will erase data in every selected test region. A full test is intended for an empty USB drive."
        )
        translations = {
            "Check USB drive": "Vérifier le lecteur USB",
            intro_source: "Ce test USB destructif est séparé du flux normal.",
            "Test profile": "Profil de test",
            "Calculating a read-only plan…": "Calcul du plan en lecture seule…",
            warning_source: "Le test efface toutes les régions sélectionnées.",
            "Run USB check": "Exécuter la vérification USB",
            "Cancel test": "Annuler le test",
            "Save report…": "Enregistrer le rapport…",
            "Preparing…": "Préparation…",
            "No qualification report is available yet.": "Aucun rapport de qualification n'est encore disponible.",
        }
        with tempfile.TemporaryDirectory() as directory:
            locale_root = Path(directory)
            write_mo(locale_root / "zz" / "LC_MESSAGES" / "rufusarm64.mo", translations)
            translation = module.load_translation(str(locale_root), ["zz"])

            intro = Label(intro_source)
            profile_heading = Label("Test profile")
            quick_choice = Label("Quick capacity and alias check")
            full_choice = Label("Full-device multi-region verification")
            plan = Label("Calculating a read-only plan…")
            warning = Label(warning_source)
            erase_label = Label("Type ERASE /dev/sdz to enable the test")
            run_button = Button("Run USB check")
            cancel_button = Button("Cancel test")
            save_button = Button("Save report…")
            status = Label("Preparing…")
            report = TextView("No qualification report is available yet.")
            evidence = TextView('{"device_path":"/dev/sdz","profile":"quick","status":"passed"}')
            dialog = Window(
                title="Check USB drive",
                children=[
                    intro,
                    profile_heading,
                    quick_choice,
                    full_choice,
                    plan,
                    warning,
                    erase_label,
                    run_button,
                    cancel_button,
                    save_button,
                    status,
                    report,
                    evidence,
                ],
            )

            self.assertFalse(module.translate_widget_tree(dialog, translation))
            self.assertEqual(dialog.title, translations["Check USB drive"])
            self.assertEqual(intro.text, translations[intro_source])
            self.assertEqual(profile_heading.text, "Profil de test")
            self.assertEqual(plan.text, translations["Calculating a read-only plan…"])
            self.assertEqual(warning.text, translations[warning_source])
            self.assertEqual(run_button.label, "Exécuter la vérification USB")
            self.assertEqual(cancel_button.label, "Annuler le test")
            self.assertEqual(save_button.label, "Enregistrer le rapport…")
            self.assertEqual(status.text, "Préparation…")
            self.assertEqual(report.buffer.text, translations["No qualification report is available yet."])

            self.assertEqual(quick_choice.text, "Quick capacity and alias check")
            self.assertEqual(full_choice.text, "Full-device multi-region verification")
            self.assertEqual(erase_label.text, "Type ERASE /dev/sdz to enable the test")
            self.assertEqual(
                evidence.buffer.text,
                '{"device_path":"/dev/sdz","profile":"quick","status":"passed"}',
            )

    def test_exact_secondary_class_set_includes_qualification_once(self):
        module, _ = load_i18n_module()
        self.assertEqual(
            module.SECONDARY_DIALOG_CLASSES,
            (
                ("rufusarm64_checksums", "ChecksumDialog"),
                ("rufusarm64_device_qualify_dialog", "DeviceQualificationDialog"),
                ("rufusarm64_device_qualify_dialog", "DriveImageBackupDialog"),
                ("rufusarm64_ffu_dialog", "FFUReviewDialog"),
                ("rufusarm64_nonbootable_dialog", "NonBootableFormatDialog"),
                ("rufusarm64_freedos_dialog", "FreeDOSFormatDialog"),
            ),
        )

    def test_operation_source_remains_localization_free_identity_bound_and_exactly_confirmed(self):
        text = QUALIFICATION_DIALOG.read_text(encoding="utf-8")
        self.assertNotIn("rufusarm64_i18n", text)
        for marker in (
            'expected = f"ERASE {self.device}"',
            'self.confirmation.get_text().strip() == expected',
            'build_dry_run_command(self.binary, self.device, self.identity, profile)',
            'self.identity,',
            'payload = normalize_report(json.loads(stdout))',
            'rendered = json.dumps(payload, indent=2, sort_keys=True)',
            'if os.path.lexists(filename):',
            'save_new_qualification_report(',
        ):
            self.assertIn(marker, text)


if __name__ == "__main__":
    unittest.main()
