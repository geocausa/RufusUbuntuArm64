import importlib.util
from pathlib import Path
import sys
import tempfile
import types
import unittest


GUI_DIR = Path(__file__).resolve().parent
if str(GUI_DIR) not in sys.path:
    sys.path.insert(0, str(GUI_DIR))

from test_i18n import load_i18n_module, write_mo


FORMAT_SOURCE = GUI_DIR / "rufusarm64_drive_backup_formats.py"
ISO_SOURCE = GUI_DIR / "rufusarm64_drive_backup_iso.py"
BACKUP_CONTRACT_SOURCE = GUI_DIR / "rufusarm64_device_qualify.py"
ISO_CONTRACT_SOURCE = GUI_DIR / "rufusarm64_iso_capture.py"


def load_format_module(i18n):
    names = (
        "gi",
        "gi.repository",
        "rufusarm64_i18n",
        "rufusarm64_device_qualify_dialog",
        "rufusarm64_device_qualify",
    )
    saved = {name: sys.modules.get(name) for name in names}
    fake_gi = types.ModuleType("gi")
    repository = types.ModuleType("gi.repository")
    repository.GLib = types.SimpleNamespace()
    repository.Gtk = types.SimpleNamespace()
    backup_dialog = types.ModuleType("rufusarm64_device_qualify_dialog")
    backup_dialog.DriveImageBackupDialog = type("DriveImageBackupDialog", (), {})
    qualify = types.ModuleType("rufusarm64_device_qualify")
    for name in (
        "backup_build_dry_run_command",
        "backup_build_run_command",
        "backup_confirmation_phrase",
        "backup_decode_progress_line",
        "backup_normalize_plan",
        "backup_normalize_report",
        "backup_progress_summary",
    ):
        setattr(qualify, name, lambda *args, **kwargs: None)
    sys.modules["gi"] = fake_gi
    sys.modules["gi.repository"] = repository
    sys.modules["rufusarm64_i18n"] = i18n
    sys.modules["rufusarm64_device_qualify_dialog"] = backup_dialog
    sys.modules["rufusarm64_device_qualify"] = qualify
    try:
        spec = importlib.util.spec_from_file_location("rufusarm64_backup_format_i18n_test", FORMAT_SOURCE)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        for name, previous in saved.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous


class BackupFormatLocalizationTests(unittest.TestCase):
    def test_real_catalog_translates_only_presentation_and_preserves_canonical_ids(self):
        i18n, _ = load_i18n_module()
        translations = {
            "Image format": "Format d'image",
            "Raw image (.img)": "Image brute (.img)",
            "Dynamic VHD (.vhd)": "VHD dynamique (.vhd)",
            "Dynamic VHDX (.vhdx)": "VHDX dynamique (.vhdx)",
            "Filesystem ISO/UDF (.iso)": "Système de fichiers ISO/UDF (.iso)",
            "Choose a new Raw image (.img) file": "Choisir un nouveau fichier d'image brute (.img)",
            "Choose a new Dynamic VHD (.vhd) file": "Choisir un nouveau fichier VHD dynamique (.vhd)",
            "Choose a new Dynamic VHDX (.vhdx) file": "Choisir un nouveau fichier VHDX dynamique (.vhdx)",
            "Choose a new Filesystem ISO/UDF (.iso) file": "Choisir un nouveau fichier ISO/UDF (.iso)",
        }
        with tempfile.TemporaryDirectory() as directory:
            locale_root = Path(directory)
            write_mo(locale_root / "zz" / "LC_MESSAGES" / "rufusarm64.mo", translations)
            i18n.configure_translation(str(locale_root), ["zz"])
            module = load_format_module(i18n)
            module._FORMAT_LABELS["iso"] = "Filesystem ISO/UDF (.iso)"
            module._FORMAT_EXTENSIONS["iso"] = ".iso"

            self.assertEqual(tuple(module._FORMAT_LABELS), ("raw", "vhd", "vhdx", "iso"))
            self.assertEqual(
                module._FORMAT_EXTENSIONS,
                {"raw": ".img", "vhd": ".vhd", "vhdx": ".vhdx", "iso": ".iso"},
            )
            self.assertEqual(module._format_presentation_label("raw"), translations["Raw image (.img)"])
            self.assertEqual(module._format_presentation_label("vhd"), translations["Dynamic VHD (.vhd)"])
            self.assertEqual(module._format_presentation_label("vhdx"), translations["Dynamic VHDX (.vhdx)"])
            self.assertEqual(
                module._format_presentation_label("iso"),
                translations["Filesystem ISO/UDF (.iso)"],
            )
            for format_name in ("raw", "vhd", "vhdx", "iso"):
                source_title = module._FORMAT_CHOOSER_TITLES[format_name]
                self.assertEqual(module._format_chooser_title(format_name), translations[source_title])
            self.assertEqual(module._format_presentation_label("unknown"), "")
            self.assertEqual(module._format_chooser_title("unknown"), "")

            i18n.configure_translation(str(locale_root), ["missing"])
            self.assertEqual(module._format_presentation_label("raw"), "Raw image (.img)")
            self.assertEqual(
                module._format_chooser_title("iso"),
                "Choose a new Filesystem ISO/UDF (.iso) file",
            )
            self.assertEqual(tuple(module._FORMAT_LABELS), ("raw", "vhd", "vhdx", "iso"))
            self.assertEqual(module._FORMAT_EXTENSIONS["iso"], ".iso")

    def test_source_uses_ids_for_behavior_and_translations_only_for_presentation(self):
        text = FORMAT_SOURCE.read_text(encoding="utf-8")
        iso = ISO_SOURCE.read_text(encoding="utf-8")
        for marker in (
            'value = str(dialog.format_selector.get_active_id() or "raw")',
            "dialog.format_selector.append(format_name, _format_presentation_label(format_name))",
            "title=_format_chooser_title(format_name)",
            "image_filter.set_name(_format_presentation_label(format_name))",
            "extension = _FORMAT_EXTENSIONS[format_name]",
            "if not filename.lower().endswith(extension)",
            "filename += extension",
            'payload["destination"]["format"] != format_name',
            'dialog.plan["destination"]["format"] != format_name',
        ):
            self.assertIn(marker, text)
        self.assertIn('formats._FORMAT_LABELS["iso"] = "Filesystem ISO/UDF (.iso)"', iso)
        self.assertIn('formats._FORMAT_EXTENSIONS["iso"] = ".iso"', iso)
        self.assertNotIn("append(_format_presentation_label(format_name),", text)
        self.assertNotIn("get_active_text()", text)

    def test_planners_reports_and_confirmation_contracts_remain_localization_free(self):
        backup_contract = BACKUP_CONTRACT_SOURCE.read_text(encoding="utf-8")
        iso_contract = ISO_CONTRACT_SOURCE.read_text(encoding="utf-8")
        self.assertNotIn("rufusarm64_i18n", backup_contract)
        self.assertNotIn("rufusarm64_i18n", iso_contract)
        for marker in (
            "backup_confirmation_phrase",
            '"--format"',
            '"--expected-identity"',
            "backup_normalize_plan",
            "backup_normalize_report",
        ):
            self.assertIn(marker, backup_contract)
        for marker in (
            "confirmation_phrase",
            '"--expected-source-node"',
            '"--expected-source-mount"',
            "normalize_plan",
            "normalize_report",
        ):
            self.assertIn(marker, iso_contract)


if __name__ == "__main__":
    unittest.main()
