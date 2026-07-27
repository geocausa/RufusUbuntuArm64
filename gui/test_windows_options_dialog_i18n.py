import ast
from pathlib import Path
import sys
import tempfile
import unittest


GUI_DIR = Path(__file__).resolve().parent
if str(GUI_DIR) not in sys.path:
    sys.path.insert(0, str(GUI_DIR))

from test_i18n import Button, CheckButton, Entry, Label, Window, load_i18n_module, write_mo


SOURCE = GUI_DIR / "rufusarm64.py"


class WindowsOptionsDialogLocalizationTests(unittest.TestCase):
    def test_real_catalog_translates_static_shell_and_preserves_machine_derived_values(self):
        module, _ = load_i18n_module()
        intro_source = (
            "Every option below is optional. RufusArm64 creates an autounattend.xml file on the USB; "
            "the Windows ISO itself is not changed. Leave everything unchecked for standard Microsoft setup."
        )
        warning_source = (
            "Microsoft can change unattended-setup behavior between Windows releases. RufusArm64 validates "
            "the answer file, but Windows may ignore an option that a future build no longer supports."
        )
        translations = {
            "Windows installation options": "Options d'installation de Windows",
            "Cancel": "Annuler",
            "Continue": "Continuer",
            "Customize Windows Setup": "Personnaliser l'installation de Windows",
            intro_source: "Chaque option est facultative et l'image ISO Windows reste inchangée.",
            "Remove TPM 2.0, Secure Boot and minimum-RAM checks": "Supprimer les contrôles TPM, Secure Boot et mémoire minimale",
            "Useful for unsupported PCs. This normally is not needed on a Surface Pro 11 X1E.": "Utile pour les PC non pris en charge.",
            "Remove the Microsoft online-account requirement": "Supprimer l'obligation de compte Microsoft en ligne",
            "Allows Windows setup to continue with a local account when supported by that Windows build.": "Autoriser un compte local lorsque cette version de Windows le prend en charge.",
            "Create a local administrator account": "Créer un compte administrateur local",
            "Account name": "Nom du compte",
            "Skip privacy prompts and reduce initial data collection/recommendations": "Ignorer les invites de confidentialité et réduire la collecte initiale",
            "Sets Windows Setup privacy choices and disables advertising/consumer-content policies where supported.": "Configure les choix de confidentialité de Windows.",
            "Apply Rufus Quality of Life changes": "Appliquer les améliorations de confort Rufus",
            "Removes bundled OneDrive setup, Outlook and Teams, and disables Copilot, web search, consumer-content suggestions and related Microsoft promotions.": "Supprime les applications et promotions Microsoft facultatives.",
            "Use this Ubuntu user's regional settings": "Utiliser les paramètres régionaux de cet utilisateur Ubuntu",
            "Disable automatic BitLocker device-encryption provisioning": "Désactiver l'activation automatique du chiffrement BitLocker",
            "Does not decrypt an existing installation. It prevents automatic encryption during this new setup where supported.": "Ne déchiffre pas une installation existante.",
            warning_source: "Le comportement de l'installation automatisée peut changer selon la version de Windows.",
        }
        with tempfile.TemporaryDirectory() as directory:
            locale_root = Path(directory)
            write_mo(locale_root / "zz" / "LC_MESSAGES" / "rufusarm64.mo", translations)
            translation = module.load_translation(str(locale_root), ["zz"])

            cancel = Button("Cancel")
            proceed = Button("Continue")
            heading = Label("Customize Windows Setup", use_markup=True)
            intro = Label(intro_source)
            hardware = CheckButton("Remove TPM 2.0, Secure Boot and minimum-RAM checks")
            hardware_detail = Label("Useful for unsupported PCs. This normally is not needed on a Surface Pro 11 X1E.")
            online = CheckButton("Remove the Microsoft online-account requirement")
            online_detail = Label("Allows Windows setup to continue with a local account when supported by that Windows build.")
            local = CheckButton("Create a local administrator account")
            account = Label("Account name")
            username = Entry("geoca")
            privacy = CheckButton("Skip privacy prompts and reduce initial data collection/recommendations")
            privacy_detail = Label("Sets Windows Setup privacy choices and disables advertising/consumer-content policies where supported.")
            qol = CheckButton("Apply Rufus Quality of Life changes")
            qol_detail = Label("Removes bundled OneDrive setup, Outlook and Teams, and disables Copilot, web search, consumer-content suggestions and related Microsoft promotions.")
            region = CheckButton("Use this Ubuntu user's regional settings")
            region_detail = Label("Applies locale en-US and time zone Pacific Standard Time during Windows Setup.")
            bitlocker = CheckButton("Disable automatic BitLocker device-encryption provisioning")
            bitlocker_detail = Label("Does not decrypt an existing installation. It prevents automatic encryption during this new setup where supported.")
            warning = Label(warning_source)
            capability = Label("Detected Windows 11 Professional media (arm64; 2 editions; WIM payload). Unsupported options are disabled below.")
            unsupported = CheckButton("Dynamic option", tooltip="This option is not supported by the selected Windows media.")
            dialog = Window(
                title="Windows installation options",
                children=[
                    cancel,
                    proceed,
                    heading,
                    intro,
                    hardware,
                    hardware_detail,
                    online,
                    online_detail,
                    local,
                    account,
                    username,
                    privacy,
                    privacy_detail,
                    qol,
                    qol_detail,
                    region,
                    region_detail,
                    bitlocker,
                    bitlocker_detail,
                    warning,
                    capability,
                    unsupported,
                ],
            )

            self.assertFalse(module.translate_widget_tree(dialog, translation))
            self.assertEqual(dialog.title, translations["Windows installation options"])
            self.assertEqual(cancel.label, translations["Cancel"])
            self.assertEqual(proceed.label, translations["Continue"])
            self.assertEqual(heading.text, translations["Customize Windows Setup"])
            self.assertEqual(
                heading.markup,
                "<span size='large' weight='bold'>Personnaliser l&#x27;installation de Windows</span>",
            )
            self.assertEqual(intro.text, translations[intro_source])
            self.assertEqual(hardware.label, translations["Remove TPM 2.0, Secure Boot and minimum-RAM checks"])
            self.assertEqual(hardware_detail.text, translations["Useful for unsupported PCs. This normally is not needed on a Surface Pro 11 X1E."])
            self.assertEqual(online.label, translations["Remove the Microsoft online-account requirement"])
            self.assertEqual(online_detail.text, translations["Allows Windows setup to continue with a local account when supported by that Windows build."])
            self.assertEqual(local.label, translations["Create a local administrator account"])
            self.assertEqual(account.text, translations["Account name"])
            self.assertEqual(privacy.label, translations["Skip privacy prompts and reduce initial data collection/recommendations"])
            self.assertEqual(privacy_detail.text, translations["Sets Windows Setup privacy choices and disables advertising/consumer-content policies where supported."])
            self.assertEqual(qol.label, translations["Apply Rufus Quality of Life changes"])
            self.assertEqual(qol_detail.text, translations["Removes bundled OneDrive setup, Outlook and Teams, and disables Copilot, web search, consumer-content suggestions and related Microsoft promotions."])
            self.assertEqual(region.label, translations["Use this Ubuntu user's regional settings"])
            self.assertEqual(bitlocker.label, translations["Disable automatic BitLocker device-encryption provisioning"])
            self.assertEqual(bitlocker_detail.text, translations["Does not decrypt an existing installation. It prevents automatic encryption during this new setup where supported."])
            self.assertEqual(warning.text, translations[warning_source])

            self.assertEqual(username.placeholder, "geoca")
            self.assertEqual(region_detail.text, "Applies locale en-US and time zone Pacific Standard Time during Windows Setup.")
            self.assertEqual(capability.text, "Detected Windows 11 Professional media (arm64; 2 editions; WIM payload). Unsupported options are disabled below.")
            self.assertEqual(unsupported.label, "Dynamic option")
            self.assertEqual(unsupported.tooltip, "This option is not supported by the selected Windows media.")

    def test_exact_dialog_set_includes_windows_options_once(self):
        module, _ = load_i18n_module()
        self.assertEqual(module.SECONDARY_DIALOG_CLASSES[-3], ("rufusarm64", "WindowsOptionsDialog"))
        self.assertEqual(module.SECONDARY_DIALOG_CLASSES[-2], ("rufusarm64", "AcquisitionDialog"))
        self.assertEqual(module.SECONDARY_DIALOG_CLASSES[-1], ("rufusarm64_persistence", "Window"))
        self.assertEqual(module.SECONDARY_DIALOG_CLASSES.count(("rufusarm64", "WindowsOptionsDialog")), 1)

    def test_source_preserves_capability_previous_value_and_answer_file_contracts(self):
        source = SOURCE.read_text(encoding="utf-8")
        self.assertNotIn("rufusarm64_i18n", source)
        tree = ast.parse(source, filename=str(SOURCE))
        dialog_class = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "WindowsOptionsDialog")
        dialog_source = ast.get_source_segment(source, dialog_class) or ""
        for marker in (
            'previous.get("bypass_hardware", False)',
            'previous.get("bypass_online_account", False)',
            'previous.get("local_user")',
            'self.local_user.set_text(previous.get("local_user", ""))',
            'previous.get("quality_of_life", False)',
            'previous.get("use_regional_settings", False)',
            'self.apply_option_capability',
            'self.use_region.set_sensitive(regional_allowed)',
            'validate_local_username(self.local_user.get_text())',
            '"bypass_hardware": self.bypass_hardware.get_active()',
            '"quality_of_life": self.quality_of_life.get_active()',
            '"locale": self.region_locale if self.use_region.get_active() else ""',
            '"timezone": self.region_timezone if self.use_region.get_active() else ""',
            'capability_summary = Gtk.Label(label=self.capability_summary())',
        ):
            self.assertIn(marker, dialog_source)


if __name__ == "__main__":
    unittest.main()
