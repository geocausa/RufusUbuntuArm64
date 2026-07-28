from pathlib import Path
import sys
import tempfile
import unittest


GUI_DIR = Path(__file__).resolve().parent
if str(GUI_DIR) not in sys.path:
    sys.path.insert(0, str(GUI_DIR))

from test_i18n import Button, Entry, Label, ProgressBar, TextView, Window, load_i18n_module, write_mo


BACKUP_DIALOG = GUI_DIR / "rufusarm64_device_qualify_dialog.py"


class DriveBackupLocalizationTests(unittest.TestCase):
    def test_static_shell_translates_with_real_catalog_and_preserves_paths_confirmation_and_evidence(self):
        module, _ = load_i18n_module()
        intro_source = (
            "Save a byte-for-byte image of the selected removable drive. The source is opened read-only, but its mounted "
            "filesystems may be unmounted briefly to obtain a coherent image. Create USB and Check USB are separate workflows."
        )
        publication_source = (
            "The final image path is created only after every planned byte has been copied, synchronized, SHA-256 hashed, "
            "and revalidated. Existing files and symbolic links are never replaced."
        )
        translations = {
            "Save drive image": "Enregistrer l'image du lecteur",
            intro_source: "Enregistre une image cohérente du lecteur sélectionné en lecture seule.",
            "New image file": "Nouveau fichier image",
            "Choose a new .img path": "Choisissez un nouveau chemin .img",
            "Choose…": "Choisir…",
            "Choose a new destination path to calculate the read-only plan.": "Choisissez une destination pour calculer le plan.",
            publication_source: "Le fichier final n'est publié qu'après copie et vérification complètes.",
            "The exact confirmation phrase appears after planning.": "La phrase de confirmation exacte apparaît après la planification.",
            "Type the exact SAVE phrase": "Saisissez la phrase SAVE exacte",
            "Cancel backup": "Annuler la sauvegarde",
            "Choose a destination file.": "Choisissez un fichier de destination.",
            "Not started": "Non démarré",
            "No backup report is available yet.": "Aucun rapport de sauvegarde n'est encore disponible.",
        }
        with tempfile.TemporaryDirectory() as directory:
            locale_root = Path(directory)
            write_mo(locale_root / "zz" / "LC_MESSAGES" / "rufusarm64.mo", translations)
            translation = module.load_translation(str(locale_root), ["zz"])

            intro = Label(intro_source)
            heading = Label("New image file")
            destination = Entry("Choose a new .img path")
            choose = Button("Choose…")
            plan = Label("Choose a new destination path to calculate the read-only plan.")
            publication = Label(publication_source)
            confirm_guidance = Label("The exact confirmation phrase appears after planning.")
            confirmation = Entry("Type the exact SAVE phrase")
            save = Button("Save drive image")
            cancel = Button("Cancel backup")
            status = Label("Choose a destination file.")
            progress = ProgressBar("Not started")
            report = TextView("No backup report is available yet.")

            source_path = Label("/dev/sdz")
            destination_path = Label("/home/user/backup.img")
            exact_phrase = Label("SAVE /dev/sdz TO /home/user/backup.img")
            plan_evidence = TextView('{"identity":"serial:abc","required_bytes":1048576}')
            progress_evidence = ProgressBar("524288 / 1048576 bytes")
            report_evidence = TextView('{"status":"passed","sha256":"0123456789abcdef"}')

            dialog = Window(
                title="Save drive image",
                children=[
                    intro,
                    heading,
                    destination,
                    choose,
                    plan,
                    publication,
                    confirm_guidance,
                    confirmation,
                    save,
                    cancel,
                    status,
                    progress,
                    report,
                    source_path,
                    destination_path,
                    exact_phrase,
                    plan_evidence,
                    progress_evidence,
                    report_evidence,
                ],
            )

            self.assertFalse(module.translate_widget_tree(dialog, translation))
            self.assertEqual(dialog.title, translations["Save drive image"])
            self.assertEqual(intro.text, translations[intro_source])
            self.assertEqual(heading.text, translations["New image file"])
            self.assertEqual(destination.placeholder, translations["Choose a new .img path"])
            self.assertEqual(choose.label, translations["Choose…"])
            self.assertEqual(plan.text, translations["Choose a new destination path to calculate the read-only plan."])
            self.assertEqual(publication.text, translations[publication_source])
            self.assertEqual(confirm_guidance.text, translations["The exact confirmation phrase appears after planning."])
            self.assertEqual(confirmation.placeholder, translations["Type the exact SAVE phrase"])
            self.assertEqual(save.label, translations["Save drive image"])
            self.assertEqual(cancel.label, translations["Cancel backup"])
            self.assertEqual(status.text, translations["Choose a destination file."])
            self.assertEqual(progress.text, translations["Not started"])
            self.assertEqual(report.buffer.text, translations["No backup report is available yet."])

            self.assertEqual(source_path.text, "/dev/sdz")
            self.assertEqual(destination_path.text, "/home/user/backup.img")
            self.assertEqual(exact_phrase.text, "SAVE /dev/sdz TO /home/user/backup.img")
            self.assertEqual(plan_evidence.buffer.text, '{"identity":"serial:abc","required_bytes":1048576}')
            self.assertEqual(progress_evidence.text, "524288 / 1048576 bytes")
            self.assertEqual(report_evidence.buffer.text, '{"status":"passed","sha256":"0123456789abcdef"}')

    def test_operation_source_remains_localization_free_and_preserves_backup_contracts(self):
        text = BACKUP_DIALOG.read_text(encoding="utf-8")
        self.assertNotIn("rufusarm64_i18n", text)
        for marker in (
            "backup_build_dry_run_command(self.binary, self.device, self.identity, self.output_path)",
            "backup_confirmation_phrase(self.device, self.output_path)",
            "self.confirmation.get_text().strip() == expected",
            "backup_build_run_command(self.pkexec, self.binary, self.device, self.identity, self.output_path)",
            'progress["total"] != planned or progress["done"] < last_done',
            "payload = backup_normalize_report(json.loads(stdout))",
            "start_new_session=True",
            "info = os.lstat(self.output_path)",
            "not stat.S_ISREG(info.st_mode)",
            "info.st_uid != os.getuid()",
            "schedule_process_group_termination(process, grace_seconds=5)",
            "iter_bounded_process_utf8_lines(",
            "os.path.lexists(self.output_path)",
        ):
            self.assertIn(marker, text)


if __name__ == "__main__":
    unittest.main()
