import ast
import re
from pathlib import Path
import sys
import tempfile
import unittest


GUI_DIR = Path(__file__).resolve().parent
ROOT = GUI_DIR.parent
if str(GUI_DIR) not in sys.path:
    sys.path.insert(0, str(GUI_DIR))

from test_i18n import Button, CheckButton, Entry, Expander, FileChooserButton, FileFilter, Frame, HeaderBar, Label, ProgressBar, TextView, Window, load_i18n_module, write_mo


SOURCE = GUI_DIR / "rufusarm64_persistence.py"
WRAPPER = ROOT / "packaging" / "rufusarm64-persistence"


class PersistenceWizardLocalizationTests(unittest.TestCase):
    def test_real_catalog_translates_static_shell_and_preserves_values_and_evidence(self):
        module, _ = load_i18n_module()
        intro_source = (
            "Choose a supported Ubuntu or Debian ISO, select a removable USB drive, and choose how much space "
            "to keep for files and settings. RufusArm64 checks compatibility before it allows the USB to be erased."
        )
        support_source = (
            "This feature supports recognized Ubuntu 20.04 or newer and Debian live images. Some images or computers "
            "may not be compatible; RufusArm64 checks the ISO before writing anything to the USB."
        )
        check_source = (
            "This check reads the ISO without changing the USB. It confirms that the selected image supports "
            "persistence and that the USB has enough space."
        )
        translations = {
            "RufusArm64 Persistent Live USB": "USB live persistant RufusArm64",
            "Ubuntu casper and Debian live-boot": "Ubuntu casper et Debian live-boot",
            "Create a persistent live Linux USB": "Créer une clé USB Linux live persistante",
            intro_source: "Choisissez une image prise en charge, une clé USB et l'espace persistant.",
            support_source: "Cette fonction prend en charge les images Ubuntu et Debian reconnues.",
            "Linux ISO": "ISO Linux",
            "Choose a plain Linux ISOHybrid image": "Choisir une image ISOHybrid Linux simple",
            "Linux ISO images": "Images ISO Linux",
            "USB drive": "Clé USB",
            "Space for saved changes": "Espace pour les modifications enregistrées",
            "GiB — leave at 0 to use the recommended available space": "Gio — laisser 0 pour l'espace recommandé",
            "Advanced options": "Options avancées",
            "USB name": "Nom USB",
            "The short name shown for the writable boot partition.": "Nom court de la partition de démarrage inscriptible.",
            "Development validation": "Validation de développement",
            "Validate media at UEFI boot (development only)": "Valider le support au démarrage UEFI (développement uniquement)",
            "Unsigned development loader — Secure Boot compatibility is not established. Development testing only.": "Chargeur de développement non signé — compatibilité Secure Boot non établie.",
            "Check compatibility": "Vérifier la compatibilité",
            check_source: "Cette vérification lit l'ISO sans modifier la clé USB.",
            "Check ISO and USB": "Vérifier l'ISO et la clé USB",
            "Choose an ISO and USB drive, then check compatibility.": "Choisissez une ISO et une clé USB, puis vérifiez la compatibilité.",
            "Ready": "Prêt",
            "The USB cannot be erased until the compatibility check succeeds.": "La clé USB ne peut pas être effacée avant une vérification réussie.",
            "Details and diagnostics": "Détails et diagnostics",
            "Cancel": "Annuler",
            "Create persistent USB": "Créer la clé USB persistante",
        }
        with tempfile.TemporaryDirectory() as directory:
            locale_root = Path(directory)
            write_mo(locale_root / "zz" / "LC_MESSAGES" / "rufusarm64.mo", translations)
            translation = module.load_translation(str(locale_root), ["zz"])

            header = HeaderBar("RufusArm64 Persistent Live USB", "Ubuntu casper and Debian live-boot")
            heading = Label("Create a persistent live Linux USB", use_markup=True)
            intro = Label(intro_source)
            support = Label(support_source)
            iso_label = Label("Linux ISO")
            image_filter = FileFilter("Linux ISO images")
            image = FileChooserButton("Choose a plain Linux ISOHybrid image", "/tmp/ubuntu.iso", [image_filter])
            usb_label = Label("USB drive")
            target_value = Label("/dev/sdz — Vendor Model — 32.0 GiB")
            space_label = Label("Space for saved changes")
            size_value = Label("10")
            size_help = Label("GiB — leave at 0 to use the recommended available space")
            advanced = Expander("Advanced options")
            usb_name = Label("USB name")
            volume = Entry(None)
            volume_value = Label("RUFUS-LIVE")
            volume.tooltip = "The short name shown for the writable boot partition."
            validation_label = Label("Development validation")
            runtime = CheckButton("Validate media at UEFI boot (development only)")
            runtime_warning = Label("Unsigned development loader — Secure Boot compatibility is not established. Development testing only.")
            frame = Frame("Check compatibility")
            check_note = Label(check_source)
            analyze = Button("Check ISO and USB")
            summary = Label("Choose an ISO and USB drive, then check compatibility.")
            progress = ProgressBar("Ready")
            detail = Label("The USB cannot be erased until the compatibility check succeeds.")
            diagnostics = Expander("Details and diagnostics")
            log = TextView("[12:00:00] Image: /tmp/ubuntu.iso\nTarget identity: serial:abc")
            cancel = Button("Cancel")
            create = Button("Create persistent USB")
            window = Window(
                title="RufusArm64 Persistent Live USB",
                children=[header, heading, intro, support, iso_label, image, usb_label, target_value, space_label, size_value, size_help, advanced, usb_name, volume, volume_value, validation_label, runtime, runtime_warning, frame, check_note, analyze, summary, progress, detail, diagnostics, log, cancel, create],
            )

            self.assertFalse(module.translate_widget_tree(window, translation))
            self.assertEqual(window.title, translations["RufusArm64 Persistent Live USB"])
            self.assertEqual(header.title, translations["RufusArm64 Persistent Live USB"])
            self.assertEqual(header.subtitle, translations["Ubuntu casper and Debian live-boot"])
            self.assertEqual(heading.text, translations["Create a persistent live Linux USB"])
            self.assertEqual(heading.markup, "<span size='large' weight='bold'>Créer une clé USB Linux live persistante</span>")
            self.assertEqual(intro.text, translations[intro_source])
            self.assertEqual(support.text, translations[support_source])
            self.assertEqual(iso_label.text, translations["Linux ISO"])
            self.assertEqual(image.title, translations["Choose a plain Linux ISOHybrid image"])
            self.assertEqual(image_filter.name, translations["Linux ISO images"])
            self.assertEqual(usb_label.text, translations["USB drive"])
            self.assertEqual(space_label.text, translations["Space for saved changes"])
            self.assertEqual(size_help.text, translations["GiB — leave at 0 to use the recommended available space"])
            self.assertEqual(advanced.label, translations["Advanced options"])
            self.assertEqual(usb_name.text, translations["USB name"])
            self.assertEqual(volume.tooltip, translations["The short name shown for the writable boot partition."])
            self.assertEqual(validation_label.text, translations["Development validation"])
            self.assertEqual(runtime.label, translations["Validate media at UEFI boot (development only)"])
            self.assertEqual(runtime_warning.text, translations["Unsigned development loader — Secure Boot compatibility is not established. Development testing only."])
            self.assertEqual(frame.label, translations["Check compatibility"])
            self.assertEqual(check_note.text, translations[check_source])
            self.assertEqual(analyze.label, translations["Check ISO and USB"])
            self.assertEqual(summary.text, translations["Choose an ISO and USB drive, then check compatibility."])
            self.assertEqual(progress.text, translations["Ready"])
            self.assertEqual(detail.text, translations["The USB cannot be erased until the compatibility check succeeds."])
            self.assertEqual(diagnostics.label, translations["Details and diagnostics"])
            self.assertEqual(cancel.label, translations["Cancel"])
            self.assertEqual(create.label, translations["Create persistent USB"])

            self.assertEqual(image.filename, "/tmp/ubuntu.iso")
            self.assertEqual(target_value.text, "/dev/sdz — Vendor Model — 32.0 GiB")
            self.assertEqual(size_value.text, "10")
            self.assertEqual(volume_value.text, "RUFUS-LIVE")
            self.assertIsNone(volume.placeholder)
            self.assertEqual(log.buffer.text, "[12:00:00] Image: /tmp/ubuntu.iso\nTarget identity: serial:abc")

    def test_wrapper_installs_localization_after_importing_persistence_module(self):
        text = WRAPPER.read_text(encoding="utf-8")
        match = re.search(r"<<'PYRUFUSARM64PERSISTENCE'\n(.*)\nPYRUFUSARM64PERSISTENCE\n\Z", text, re.DOTALL)
        self.assertIsNotNone(match)
        payload = match.group(1)
        compile(payload, str(WRAPPER), "exec")
        pin = payload.index('gi.require_version("Gtk", "3.0")')
        i18n_import = payload.index("from rufusarm64_i18n import install_secondary_dialog_localization")
        persistence_import = payload.index("import rufusarm64_persistence as persistence")
        install = payload.index("install_secondary_dialog_localization()")
        run = payload.index("persistence.App().run(None)")
        self.assertLess(pin, i18n_import)
        self.assertLess(i18n_import, persistence_import)
        self.assertLess(persistence_import, install)
        self.assertLess(install, run)

    def test_source_preserves_selection_plan_confirmation_process_and_evidence_contracts(self):
        source = SOURCE.read_text(encoding="utf-8")
        self.assertNotIn("rufusarm64_i18n", source)
        tree = ast.parse(source, filename=str(SOURCE))
        window_class = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Window")
        window_source = ast.get_source_segment(source, window_class) or ""
        for marker in (
            "inspect_source_identity(image)",
                          'target_identity = str(device.get("identity") or "").strip()',
            "normalize_persistence_gib(self.size.get_value_as_int())",
            "normalize_boot_label(self.volume_label.get_text())",
            "key = (image, source_identity, target_identity, target_size, size_gib, label, runtime_validation)",
            "build_analyze_command(",
            "build_create_command(",
                          'if key != self.plan_key:',
                          'cancel_path = self.new_cancel_path()',
            "start_new_session=True",
            "schedule_process_group_termination(self.process, grace_seconds=5)",
            "json.loads(line)",
            "completion_checklist()",
        ):
            self.assertIn(marker, window_source)


if __name__ == "__main__":
    unittest.main()
