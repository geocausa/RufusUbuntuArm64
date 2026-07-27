from pathlib import Path
import sys
import tempfile
import unittest


GUI_DIR = Path(__file__).resolve().parent
if str(GUI_DIR) not in sys.path:
    sys.path.insert(0, str(GUI_DIR))

from test_i18n import Button, Label, TextView, Window, load_i18n_module, write_mo


class ChecksumDialogLocalizationTests(unittest.TestCase):
    def test_static_shell_translates_with_real_catalog_and_preserves_selected_path_and_digest_report(self):
        module, _ = load_i18n_module()
        translations = {
            "Image checksums": "Sommes de contrôle de l'image",
            "Calculate MD5, SHA-1, SHA-256, and SHA-512 for the selected image in one read-only pass. The image is not mounted or modified, no USB device is opened, and administrator authentication is not used.": "Calcule quatre sommes en une passe en lecture seule.",
            "MD5 and SHA-1 are included only for comparison with legacy published values. They are not used by RufusArm64 for trust, signatures, downloads, or write assurance.": "MD5 et SHA-1 sont fournis uniquement pour les comparaisons historiques.",
            "Calculate": "Calculer",
            "Copy report": "Copier le rapport",
            "Select Calculate to hash the exact image file.": "Sélectionnez Calculer pour hacher le fichier image exact.",
            "No checksums have been calculated.": "Aucune somme de contrôle n'a été calculée.",
        }
        with tempfile.TemporaryDirectory() as directory:
            locale_root = Path(directory)
            write_mo(locale_root / "zz" / "LC_MESSAGES" / "rufusarm64.mo", translations)
            translation = module.load_translation(str(locale_root), ["zz"])

            selected_path = Label("/tmp/selected-image.iso")
            intro = Label(next(message for message in translations if message.startswith("Calculate MD5")))
            warning = Label(next(message for message in translations if message.startswith("MD5 and SHA-1")))
            calculate = Button("Calculate")
            copy = Button("Copy report")
            status = Label("Select Calculate to hash the exact image file.")
            report = TextView("No checksums have been calculated.")
            digest_report = TextView("SHA-256  0123456789abcdef  /tmp/selected-image.iso")
            dialog = Window(
                title="Image checksums",
                children=[selected_path, intro, warning, calculate, copy, status, report, digest_report],
            )

            self.assertFalse(module.translate_widget_tree(dialog, translation))
            self.assertEqual(dialog.title, translations["Image checksums"])
            self.assertEqual(intro.text, translations[next(message for message in translations if message.startswith("Calculate MD5"))])
            self.assertEqual(warning.text, translations[next(message for message in translations if message.startswith("MD5 and SHA-1"))])
            self.assertEqual(calculate.label, "Calculer")
            self.assertEqual(copy.label, "Copier le rapport")
            self.assertEqual(status.text, translations["Select Calculate to hash the exact image file."])
            self.assertEqual(report.buffer.text, translations["No checksums have been calculated."])
            self.assertEqual(selected_path.text, "/tmp/selected-image.iso")
            self.assertEqual(digest_report.buffer.text, "SHA-256  0123456789abcdef  /tmp/selected-image.iso")

    def test_checksum_class_is_in_the_exact_secondary_dialog_set(self):
        module, _ = load_i18n_module()
        self.assertEqual(
            module.SECONDARY_DIALOG_CLASSES,
            (
                ("rufusarm64_checksums", "ChecksumDialog"),
                ("rufusarm64_device_qualify_dialog", "DeviceQualificationDialog"),
                ("rufusarm64_device_qualify_dialog", "DriveImageBackupDialog"),
                ("rufusarm64_nonbootable_dialog", "NonBootableFormatDialog"),
                ("rufusarm64_freedos_dialog", "FreeDOSFormatDialog"),
            ),
        )


if __name__ == "__main__":
    unittest.main()
