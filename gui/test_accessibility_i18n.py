from pathlib import Path
import sys
import tempfile
import unittest


GUI_DIR = Path(__file__).resolve().parent
if str(GUI_DIR) not in sys.path:
    sys.path.insert(0, str(GUI_DIR))

from test_i18n import Accessible, Button, Label, Window, load_i18n_module, write_mo


class TranslationAwareAccessibilityTests(unittest.TestCase):
    def test_reviewed_mnemonics_names_and_descriptions_translate_together(self):
        module, _ = load_i18n_module()
        translations = {
            "_Boot image": "_Image de démarrage",
            "_USB drive": "Clé _USB",
            "_Download…": "_Télécharger…",
            "_Create USB": "_Créer la clé USB",
            "C_ancel": "A_nnuler",
            "USB target drive": "Clé USB cible",
            "Choose the removable whole drive that will be erased only after confirmation.": "Choisissez le disque amovible entier qui ne sera effacé qu'après confirmation.",
            "Calculate image checksums": "Calculer les sommes de contrôle",
            "Calculate comparison hashes. Shortcut Ctrl+K.": "Calculer les empreintes de comparaison. Raccourci Ctrl+K.",
        }
        with tempfile.TemporaryDirectory() as directory:
            locale_root = Path(directory)
            write_mo(locale_root / "zz" / "LC_MESSAGES" / "rufusarm64.mo", translations)
            translation = module.load_translation(str(locale_root), ["zz"])
            boot = Label("_Boot image")
            usb = Label(
                "_USB drive",
                accessible=Accessible(
                    "USB target drive",
                    "Choose the removable whole drive that will be erased only after confirmation.",
                ),
            )
            download = Button("_Download…")
            create = Button("_Create USB")
            cancel = Button("C_ancel")
            checksum = Button(
                "Calculate image checksums",
                accessible=Accessible(
                    "Calculate image checksums",
                    "Calculate comparison hashes. Shortcut Ctrl+K.",
                ),
            )
            dynamic = Button(
                "serial:abc",
                accessible=Accessible("/dev/sdz", '{"outcome":"verified"}'),
            )
            window = Window(children=[boot, usb, download, create, cancel, checksum, dynamic])

            self.assertFalse(module.translate_widget_tree(window, translation))
            self.assertEqual(boot.text, translations["_Boot image"])
            self.assertEqual(usb.text, translations["_USB drive"])
            self.assertEqual(download.label, translations["_Download…"])
            self.assertEqual(create.label, translations["_Create USB"])
            self.assertEqual(cancel.label, translations["C_ancel"])
            self.assertEqual(usb.accessible.name, translations["USB target drive"])
            self.assertEqual(usb.accessible.description, translations["Choose the removable whole drive that will be erased only after confirmation."])
            self.assertEqual(checksum.label, translations["Calculate image checksums"])
            self.assertEqual(checksum.accessible.name, translations["Calculate image checksums"])
            self.assertEqual(checksum.accessible.description, translations["Calculate comparison hashes. Shortcut Ctrl+K."])
            self.assertEqual(dynamic.label, "serial:abc")
            self.assertEqual(dynamic.accessible.name, "/dev/sdz")
            self.assertEqual(dynamic.accessible.description, '{"outcome":"verified"}')

    def test_every_primary_accessibility_string_is_admitted_to_catalog(self):
        module, _ = load_i18n_module()
        import ast
        source = (GUI_DIR / "rufusarm64_integrated.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        values = []
        for node in tree.body:
            if not isinstance(node, ast.Assign) or len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
                continue
            name = node.targets[0].id
            if name not in {
                "PRIMARY_LABEL_MNEMONICS",
                "PRIMARY_BUTTON_MNEMONICS",
                "PRIMARY_ACCESSIBILITY",
                "ABOUT_ACCESSIBILITY",
            }:
                continue
            value = ast.literal_eval(node.value)
            if isinstance(value, dict):
                for key, item in value.items():
                    if name == "PRIMARY_LABEL_MNEMONICS":
                        values.extend((key, item[0]))
                    elif name == "PRIMARY_BUTTON_MNEMONICS":
                        values.append(item)
                    else:
                        values.extend(part for part in item if part)
            else:
                values.extend(part for part in value if part)
        missing = sorted({value for value in values if value not in module.CATALOG_MESSAGE_SET})
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
