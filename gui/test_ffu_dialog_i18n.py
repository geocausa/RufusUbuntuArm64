from pathlib import Path
import sys
import tempfile
import unittest


GUI_DIR = Path(__file__).resolve().parent
if str(GUI_DIR) not in sys.path:
    sys.path.insert(0, str(GUI_DIR))

from test_i18n import Button, Entry, Label, TextView, Window, load_i18n_module, write_mo


FFU_DIALOG = GUI_DIR / "rufusarm64_ffu_dialog.py"


class FFUDialogLocalizationTests(unittest.TestCase):
    def test_static_shell_translates_with_real_catalog_and_preserves_trust_target_confirmation_and_evidence(self):
        module, _ = load_i18n_module()
        destructive_source = (
            "After a successful unmounted-target review, type the displayed phrase exactly. "
            "Administrator authentication then reruns every source, policy, trust-generation, "
            "target and geometry check before any write."
        )
        warning_source = (
            "Experimental FFU provider — authenticate and review first. Restoration is available only for an "
            "already-unmounted removable whole disk and destroys data on the exact reviewed target."
        )
        translations = {
            "Review Full Flash Update": "Examiner la mise à jour Flash complète",
            "Close": "Fermer",
            "Authenticated trust store": "Magasin de confiance authentifié",
            "Trust-metadata policy": "Politique de métadonnées de confiance",
            "Publisher policy": "Politique de l'éditeur",
            "Authenticate and review": "Authentifier et examiner",
            "Choose all three explicit trust inputs.": "Choisissez les trois entrées de confiance explicites.",
            "No review has been performed. The ordinary Create USB action remains disabled for FFU images.": "Aucun examen n'a été effectué et l'action USB ordinaire reste désactivée.",
            destructive_source: "Après un examen réussi, saisissez exactement la phrase affichée avant toute écriture.",
            "Restore authenticated FFU": "Restaurer le FFU authentifié",
            "Cancel restore": "Annuler la restauration",
        }
        with tempfile.TemporaryDirectory() as directory:
            locale_root = Path(directory)
            write_mo(locale_root / "zz" / "LC_MESSAGES" / "rufusarm64.mo", translations)
            translation = module.load_translation(str(locale_root), ["zz"])

            warning = Label(warning_source)
            image_target = Label("Image: /tmp/device.ffu\nTarget: /dev/sdz — Vendor Model")
            trust_label = Label("Authenticated trust store")
            metadata_label = Label("Trust-metadata policy")
            publisher_label = Label("Publisher policy")
            review = Button("Authenticate and review")
            status = Label("Choose all three explicit trust inputs.")
            result = TextView("No review has been performed. The ordinary Create USB action remains disabled for FFU images.")
            destructive = Label(destructive_source)
            confirmation = Entry("RESTORE AUTHENTICATED FFU TO /dev/DEVICE SIZE N BYTES")
            restore = Button("Restore authenticated FFU")
            cancel = Button("Cancel restore")
            close = Button("Close")

            trust_path = Label("/etc/rufusarm64/ffu-trust")
            metadata_path = Label("/etc/rufusarm64/metadata-policy.json")
            publisher_path = Label("/etc/rufusarm64/publisher-policy.json")
            exact_phrase = Label("RESTORE AUTHENTICATED FFU TO /dev/sdz SIZE 1048576 BYTES")
            evidence = TextView('{"target_identity":"serial:abc","outcome":"verified"}')
            dynamic_status = Label("Authenticated read-only review passed.")

            dialog = Window(
                title="Review Full Flash Update",
                children=[
                    warning,
                    image_target,
                    trust_label,
                    metadata_label,
                    publisher_label,
                    review,
                    status,
                    result,
                    destructive,
                    confirmation,
                    restore,
                    cancel,
                    close,
                    trust_path,
                    metadata_path,
                    publisher_path,
                    exact_phrase,
                    evidence,
                    dynamic_status,
                ],
            )

            self.assertFalse(module.translate_widget_tree(dialog, translation))
            self.assertEqual(dialog.title, translations["Review Full Flash Update"])
            self.assertEqual(trust_label.text, translations["Authenticated trust store"])
            self.assertEqual(metadata_label.text, translations["Trust-metadata policy"])
            self.assertEqual(publisher_label.text, translations["Publisher policy"])
            self.assertEqual(review.label, translations["Authenticate and review"])
            self.assertEqual(status.text, translations["Choose all three explicit trust inputs."])
            self.assertEqual(result.buffer.text, translations["No review has been performed. The ordinary Create USB action remains disabled for FFU images."])
            self.assertEqual(destructive.text, translations[destructive_source])
            self.assertEqual(restore.label, translations["Restore authenticated FFU"])
            self.assertEqual(cancel.label, translations["Cancel restore"])
            self.assertEqual(close.label, translations["Close"])

            self.assertEqual(warning.text, warning_source)
            self.assertEqual(image_target.text, "Image: /tmp/device.ffu\nTarget: /dev/sdz — Vendor Model")
            self.assertEqual(confirmation.placeholder, "RESTORE AUTHENTICATED FFU TO /dev/DEVICE SIZE N BYTES")
            self.assertEqual(trust_path.text, "/etc/rufusarm64/ffu-trust")
            self.assertEqual(metadata_path.text, "/etc/rufusarm64/metadata-policy.json")
            self.assertEqual(publisher_path.text, "/etc/rufusarm64/publisher-policy.json")
            self.assertEqual(exact_phrase.text, "RESTORE AUTHENTICATED FFU TO /dev/sdz SIZE 1048576 BYTES")
            self.assertEqual(evidence.buffer.text, '{"target_identity":"serial:abc","outcome":"verified"}')
            self.assertEqual(dynamic_status.text, "Authenticated read-only review passed.")

    def test_exact_secondary_class_set_includes_ffu_once(self):
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
                ("rufusarm64", "WindowsOptionsDialog"),
                ("rufusarm64", "AcquisitionDialog"),
            ),
        )

    def test_ffu_source_keeps_warning_chooser_confirmation_and_operation_contracts_outside_localization(self):
        text = FFU_DIALOG.read_text(encoding="utf-8")
        self.assertNotIn("rufusarm64_i18n", text)
        for marker in (
            "Experimental FFU provider",
            "Choose the authenticated FFU trust-store folder",
            "Choose the FFU trust-metadata public-key policy",
            "Choose the explicit FFU publisher policy",
            "RESTORE AUTHENTICATED FFU TO /dev/DEVICE SIZE N BYTES",
            'self.review.get("exact_confirmation_phrase")',
            "build_ffu_review_command(",
            "build_ffu_restore_command(",
            "normalize_ffu_restore_output(payload, expected_review)",
        ):
            self.assertIn(marker, text)


if __name__ == "__main__":
    unittest.main()
