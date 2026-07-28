import ast
from pathlib import Path
import sys
import tempfile
import unittest


GUI_DIR = Path(__file__).resolve().parent
if str(GUI_DIR) not in sys.path:
    sys.path.insert(0, str(GUI_DIR))

from test_i18n import Button, Expander, FileChooserButton, Frame, Label, Window, load_i18n_module, write_mo


SOURCE = GUI_DIR / "rufusarm64.py"


class AcquisitionDialogLocalizationTests(unittest.TestCase):
    def test_real_catalog_translates_static_shell_and_preserves_trust_and_image_evidence(self):
        module, _ = load_i18n_module()
        intro_source = (
            "The built-in channel verifies threshold-signed root and catalog metadata, rejects version rollback, "
            "and checksum-verifies every image. No unsigned bypass is offered."
        )
        recovery_source = (
            "Use this only with catalog, detached-signature, and public-key files obtained through a separately trusted path."
        )
        translations = {
            "Download a verified image": "Télécharger une image vérifiée",
            "Cancel": "Annuler",
            "Download": "Télécharger",
            intro_source: "Le canal intégré vérifie les métadonnées signées et chaque image.",
            "Built-in verified catalog": "Catalogue vérifié intégré",
            "Refresh catalog": "Actualiser le catalogue",
            "Checking the package-owned trust channel…": "Vérification du canal de confiance du paquet…",
            "Advanced recovery: local signed catalog": "Récupération avancée : catalogue local signé",
            recovery_source: "Utilisez uniquement des fichiers obtenus par un chemin de confiance séparé.",
            "Catalog": "Catalogue",
            "Signature": "Signature",
            "Public key": "Clé publique",
            "Download folder": "Dossier de téléchargement",
            "Choose catalog": "Choisir le catalogue",
            "Choose signature": "Choisir la signature",
            "Choose public key": "Choisir la clé publique",
            "Choose download folder": "Choisir le dossier de téléchargement",
            "Verify local catalog": "Vérifier le catalogue local",
            "Choose all three local trust files, then verify.": "Choisissez les trois fichiers de confiance locaux, puis vérifiez.",
            "No verified image selected.": "Aucune image vérifiée sélectionnée.",
        }
        with tempfile.TemporaryDirectory() as directory:
            locale_root = Path(directory)
            write_mo(locale_root / "zz" / "LC_MESSAGES" / "rufusarm64.mo", translations)
            translation = module.load_translation(str(locale_root), ["zz"])

            cancel = Button("Cancel")
            download = Button("Download")
            intro = Label(intro_source)
            refresh = Button("Refresh catalog")
            channel_status = Label("Checking the package-owned trust channel…")
            frame = Frame("Built-in verified catalog", [refresh, channel_status])
            recovery = Expander("Advanced recovery: local signed catalog")
            recovery_note = Label(recovery_source)
            catalog_label = Label("Catalog")
            signature_label = Label("Signature")
            key_label = Label("Public key")
            output_label = Label("Download folder")
            catalog = FileChooserButton("Choose catalog", "/etc/rufusarm64/catalog.json")
            signature = FileChooserButton("Choose signature", "/etc/rufusarm64/catalog.sig")
            public_key = FileChooserButton("Choose public key", "/etc/rufusarm64/catalog.pub")
            output = FileChooserButton("Choose download folder", "/home/geoca/Downloads")
            verify = Button("Verify local catalog")
            catalog_status = Label("Choose all three local trust files, then verify.")
            image_detail = Label("No verified image selected.")
            dynamic_channel = Label("Root v8 expires 2027-01-01; catalog v42 from verified cache; signing key(s) 0123456789ab…")
            dynamic_image = Label("File: ubuntu-arm64.iso\nSize: 5.2 GiB\nSHA-256: deadbeef")
            provider_error = Label("Built-in catalog unavailable: threshold signature 2 of 3 was not met")
            dialog = Window(
                title="Download a verified image",
                children=[
                    cancel,
                    download,
                    intro,
                    frame,
                    recovery,
                    recovery_note,
                    catalog_label,
                    signature_label,
                    key_label,
                    output_label,
                    catalog,
                    signature,
                    public_key,
                    output,
                    verify,
                    catalog_status,
                    image_detail,
                    dynamic_channel,
                    dynamic_image,
                    provider_error,
                ],
            )

            self.assertFalse(module.translate_widget_tree(dialog, translation))
            self.assertEqual(dialog.title, translations["Download a verified image"])
            self.assertEqual(cancel.label, translations["Cancel"])
            self.assertEqual(download.label, translations["Download"])
            self.assertEqual(intro.text, translations[intro_source])
            self.assertEqual(frame.label, translations["Built-in verified catalog"])
            self.assertEqual(refresh.label, translations["Refresh catalog"])
            self.assertEqual(channel_status.text, translations["Checking the package-owned trust channel…"])
            self.assertEqual(recovery.label, translations["Advanced recovery: local signed catalog"])
            self.assertEqual(recovery_note.text, translations[recovery_source])
            self.assertEqual(catalog_label.text, translations["Catalog"])
            self.assertEqual(signature_label.text, translations["Signature"])
            self.assertEqual(key_label.text, translations["Public key"])
            self.assertEqual(output_label.text, translations["Download folder"])
            self.assertEqual(catalog.title, translations["Choose catalog"])
            self.assertEqual(signature.title, translations["Choose signature"])
            self.assertEqual(public_key.title, translations["Choose public key"])
            self.assertEqual(output.title, translations["Choose download folder"])
            self.assertEqual(verify.label, translations["Verify local catalog"])
            self.assertEqual(catalog_status.text, translations["Choose all three local trust files, then verify."])
            self.assertEqual(image_detail.text, translations["No verified image selected."])

            self.assertEqual(catalog.filename, "/etc/rufusarm64/catalog.json")
            self.assertEqual(signature.filename, "/etc/rufusarm64/catalog.sig")
            self.assertEqual(public_key.filename, "/etc/rufusarm64/catalog.pub")
            self.assertEqual(output.filename, "/home/geoca/Downloads")
            self.assertEqual(dynamic_channel.text, "Root v8 expires 2027-01-01; catalog v42 from verified cache; signing key(s) 0123456789ab…")
            self.assertEqual(dynamic_image.text, "File: ubuntu-arm64.iso\nSize: 5.2 GiB\nSHA-256: deadbeef")
            self.assertEqual(provider_error.text, "Built-in catalog unavailable: threshold signature 2 of 3 was not met")

    def test_exact_dialog_set_includes_acquisition_once(self):
        module, _ = load_i18n_module()
        self.assertEqual(module.SECONDARY_DIALOG_CLASSES[-2], ("rufusarm64", "AcquisitionDialog"))
        self.assertEqual(module.SECONDARY_DIALOG_CLASSES[-1], ("rufusarm64_persistence", "Window"))
        self.assertEqual(module.SECONDARY_DIALOG_CLASSES.count(("rufusarm64", "AcquisitionDialog")), 1)

    def test_source_preserves_catalog_trust_selection_resume_and_returned_values(self):
        source = SOURCE.read_text(encoding="utf-8")
        self.assertNotIn("rufusarm64_i18n", source)
        tree = ast.parse(source, filename=str(SOURCE))
        dialog_class = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "AcquisitionDialog")
        dialog_source = ast.get_source_segment(source, dialog_class) or ""
        for marker in (
            'self.mode = ""',
            'self.channel_metadata = {}',
            'build_acquisition_channel_list_command(helper_path(), ACQUISITION_CHANNEL_CONFIG)',
            'normalize_acquisition_channel(json.loads(stdout))',
            'build_acquisition_list_command(helper_path(), *selection)',
            'normalize_acquisition_images(json.loads(result.stdout))',
            'schedule_process_group_termination(process, grace_seconds=5)',
            'communicate_bounded(',
            'run_bounded(',
            'self.image_combo.append(image["id"], acquisition_image_label(image))',
            'image_id = self.image_combo.get_active_id()',
            'image = next((item for item in self.images if item["id"] == image_id), None)',
            'SHA-256:',
            '"mode": self.mode',
            '"channel_config": ACQUISITION_CHANNEL_CONFIG',
            '"catalog": self.catalog.get_filename() or ""',
            '"signature": self.signature.get_filename() or ""',
            '"public_key": self.public_key.get_filename() or ""',
            '"output": self.output.get_filename() or ""',
            '"image": image',
        ):
            self.assertIn(marker, dialog_source)


if __name__ == "__main__":
    unittest.main()
