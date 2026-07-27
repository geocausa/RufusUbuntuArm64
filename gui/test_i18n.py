import html
import importlib.util
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import types
import unittest


ROOT = Path(__file__).resolve().parent.parent
I18N_SOURCE = ROOT / "gui" / "rufusarm64_i18n.py"
POT = ROOT / "po" / "rufusarm64.pot"
PACKAGE_SCRIPT = ROOT / "scripts" / "build-deb.sh"
LAUNCHER = ROOT / "packaging" / "rufusarm64"


class Accessible:
    def __init__(self, name=None, description=None):
        self.name = name
        self.description = description

    def get_name(self):
        return self.name

    def set_name(self, value):
        self.name = value

    def get_description(self):
        return self.description

    def set_description(self, value):
        self.description = value


class Widget:
    def __init__(self, tooltip=None, accessible=None):
        self.tooltip = tooltip
        self.accessible = accessible

    def get_tooltip_text(self):
        return self.tooltip

    def set_tooltip_text(self, value):
        self.tooltip = value

    def get_accessible(self):
        return self.accessible


class Container(Widget):
    def __init__(self, children=None, **kwargs):
        super().__init__(**kwargs)
        self.children = list(children or [])

    def get_children(self):
        return list(self.children)


class HeaderBar(Container):
    def __init__(self, title=None, subtitle=None, **kwargs):
        super().__init__(**kwargs)
        self.title = title
        self.subtitle = subtitle

    def get_title(self):
        return self.title

    def set_title(self, value):
        self.title = value

    def get_subtitle(self):
        return self.subtitle

    def set_subtitle(self, value):
        self.subtitle = value


class Label(Widget):
    def __init__(self, text, use_markup=False, **kwargs):
        super().__init__(**kwargs)
        self.text = text
        self.use_markup = use_markup
        self.markup = None

    def get_text(self):
        return self.text

    def set_text(self, value):
        self.text = value
        self.markup = None

    def get_use_markup(self):
        return self.use_markup

    def set_markup(self, value):
        self.markup = value
        self.text = _strip_test_markup(value)


class Button(Widget):
    def __init__(self, label=None, **kwargs):
        super().__init__(**kwargs)
        self.label = label

    def get_label(self):
        return self.label

    def set_label(self, value):
        self.label = value


class CheckButton(Button):
    pass


class Expander(Button):
    pass


def _strip_test_markup(value):
    start = value.find(">")
    end = value.rfind("<")
    return html.unescape(value[start + 1 : end]) if 0 <= start < end else value


def load_i18n_module():
    saved = {name: sys.modules.get(name) for name in ("gi", "gi.repository")}
    deferred = []
    fake_gi = types.ModuleType("gi")
    repository = types.ModuleType("gi.repository")
    repository.GLib = types.SimpleNamespace(
        idle_add=lambda callback, *args: deferred.append((callback, args)) or 1,
        markup_escape_text=lambda value: html.escape(value, quote=True),
    )
    repository.Gtk = types.SimpleNamespace(
        Container=Container,
        HeaderBar=HeaderBar,
        Label=Label,
        Button=Button,
        CheckButton=CheckButton,
        Expander=Expander,
    )
    sys.modules["gi"] = fake_gi
    sys.modules["gi.repository"] = repository
    try:
        module_name = f"rufusarm64_i18n_test_{id(deferred)}"
        spec = importlib.util.spec_from_file_location(module_name, I18N_SOURCE)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module, deferred
    finally:
        for name, previous in saved.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous


def write_mo(path, messages):
    catalog = dict(messages)
    catalog.setdefault("", "Content-Type: text/plain; charset=UTF-8\nLanguage: zz\n")
    keys = sorted(catalog)
    original_strings = [key.encode("utf-8") for key in keys]
    translated_strings = [catalog[key].encode("utf-8") for key in keys]
    count = len(keys)
    original_table_offset = 28
    translated_table_offset = original_table_offset + count * 8
    original_data_offset = translated_table_offset + count * 8

    original_blob = bytearray()
    original_entries = []
    for value in original_strings:
        original_entries.append((len(value), original_data_offset + len(original_blob)))
        original_blob.extend(value + b"\0")

    translated_data_offset = original_data_offset + len(original_blob)
    translated_blob = bytearray()
    translated_entries = []
    for value in translated_strings:
        translated_entries.append((len(value), translated_data_offset + len(translated_blob)))
        translated_blob.extend(value + b"\0")

    payload = bytearray(struct.pack("<7I", 0x950412DE, 0, count, original_table_offset, translated_table_offset, 0, 0))
    for length, offset in original_entries:
        payload.extend(struct.pack("<2I", length, offset))
    for length, offset in translated_entries:
        payload.extend(struct.pack("<2I", length, offset))
    payload.extend(original_blob)
    payload.extend(translated_blob)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


class PrimaryLocalizationTests(unittest.TestCase):
    def test_real_gnu_catalog_loads_from_standard_layout_and_falls_back_safely(self):
        module, _ = load_i18n_module()
        with tempfile.TemporaryDirectory() as directory:
            locale_root = Path(directory)
            catalog_path = locale_root / "zz" / "LC_MESSAGES" / "rufusarm64.mo"
            write_mo(catalog_path, {"Create USB": "Créer USB"})
            translation = module.load_translation(str(locale_root), ["zz"])
            self.assertEqual(module._translated("Create USB", translation), "Créer USB")
            self.assertEqual(module._translated("dynamic /dev/sda", translation), "dynamic /dev/sda")

            missing = module.load_translation(str(locale_root), ["missing"])
            self.assertEqual(module._translated("Create USB", missing), "Create USB")

            catalog_path.write_bytes(b"not a message catalog")
            corrupted = module.load_translation(str(locale_root), ["zz"])
            self.assertEqual(module._translated("Create USB", corrupted), "Create USB")

    def test_primary_widget_pass_translates_exact_static_text_and_preserves_contract_data(self):
        module, _ = load_i18n_module()
        translations = {
            "Bootable USB creator for Linux ARM64": "Créateur USB amorçable pour Linux ARM64",
            "Create a bootable USB drive": "Créer <USB> & continuer",
            "Create USB": "Créer USB",
            "Calculate image checksums": "Calculer les sommes de contrôle",
            "Choose the removable whole drive that will be erased only after confirmation.": "Choisissez le disque USB amovible confirmé.",
            "Keyboard: {shortcut}": "Clavier : {shortcut}",
        }
        with tempfile.TemporaryDirectory() as directory:
            locale_root = Path(directory)
            write_mo(locale_root / "zz" / "LC_MESSAGES" / "rufusarm64.mo", translations)
            translation = module.load_translation(str(locale_root), ["zz"])

            header = HeaderBar(title="RufusArm64", subtitle="Bootable USB creator for Linux ARM64")
            heading = Label("Create a bootable USB drive", use_markup=True)
            action = Button(
                "Create USB",
                tooltip="Calculate image checksums\nKeyboard: Ctrl+K",
                accessible=Accessible(
                    "Calculate image checksums",
                    "Choose the removable whole drive that will be erased only after confirmation.",
                ),
            )
            dynamic = Label("/dev/sda — USB identity 012345")
            absent = Button(None, tooltip=None, accessible=Accessible(None, None))
            window = Container([header, heading, action, dynamic, absent])

            self.assertFalse(module.apply_primary_ui_translation(window, translation))
            self.assertEqual(header.title, "RufusArm64")
            self.assertEqual(header.subtitle, translations["Bootable USB creator for Linux ARM64"])
            self.assertEqual(heading.text, translations["Create a bootable USB drive"])
            self.assertEqual(
                heading.markup,
                "<span size='large' weight='bold'>Créer &lt;USB&gt; &amp; continuer</span>",
            )
            self.assertEqual(action.label, "Créer USB")
            self.assertEqual(action.tooltip, "Calculer les sommes de contrôle\nClavier : Ctrl+K")
            self.assertEqual(action.accessible.name, "Calculer les sommes de contrôle")
            self.assertEqual(action.accessible.description, "Choisissez le disque USB amovible confirmé.")
            self.assertEqual(dynamic.text, "/dev/sda — USB identity 012345")
            self.assertIsNone(absent.label)
            self.assertIsNone(absent.tooltip)
            self.assertIsNone(absent.accessible.name)
            self.assertIsNone(absent.accessible.description)
            self.assertIs(window._rufusarm64_translation, translation)
            self.assertGreaterEqual(window._rufusarm64_translated_fields, 6)

    def test_installer_is_idempotent_and_defers_until_composed_construction(self):
        module, deferred = load_i18n_module()

        class Window(Container):
            def __init__(self, app):
                super().__init__()
                self.app = app

        module.install_localization(Window)
        module.install_localization(Window)
        window = Window("application")
        self.assertEqual(window.app, "application")
        self.assertTrue(Window._localization_installed)
        self.assertEqual(deferred, [(module.apply_primary_ui_translation, (window,))])

    def test_template_is_deterministic_and_excludes_machine_contracts(self):
        completed = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "update-pot.py"), "--check"],
            cwd=ROOT,
            check=False,
            text=True,
            capture_output=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)
        text = POT.read_text(encoding="utf-8")
        self.assertIn('msgid "Create USB"', text)
        self.assertIn('msgid "Keyboard: {shortcut}"', text)
        self.assertIn('#: gui/rufusarm64_i18n.py', text)
        self.assertNotIn("POT-Creation-Date", text)
        for forbidden in ("--expected-identity", "FORMAT /dev", 'msgid "device_path"', 'msgid "filesystem"'):
            self.assertNotIn(forbidden, text)

    def test_package_and_launcher_bind_the_runtime_template_and_safe_ordering(self):
        package = PACKAGE_SCRIPT.read_text(encoding="utf-8")
        launcher = LAUNCHER.read_text(encoding="utf-8")
        for marker in (
            'python3 "${ROOT_DIR}/scripts/update-pot.py" --check',
            '"${ROOT_DIR}/gui/rufusarm64_i18n.py"',
            '"${PACKAGE_DIR}/usr/lib/rufusarm64/rufusarm64_i18n.py"',
            '"${ROOT_DIR}/po/rufusarm64.pot"',
            '"${PACKAGE_DIR}/usr/share/doc/rufusarm64/rufusarm64.pot"',
        ):
            self.assertIn(marker, package)
        pin = launcher.index('gi.require_version("Gtk", "3.0")')
        i18n_import = launcher.index("from rufusarm64_i18n import gettext as _, install_localization")
        appearance = launcher.index("install_appearance(RufusWindow)")
        tooltips = launcher.index("install_main_control_tooltips(RufusWindow)")
        localization = launcher.index("install_localization(RufusWindow)")
        run = launcher.index('return run_rufusarm64(["rufusarm64", *arguments])')
        self.assertLess(pin, i18n_import)
        self.assertLess(appearance, tooltips)
        self.assertLess(tooltips, localization)
        self.assertLess(localization, run)


if __name__ == "__main__":
    unittest.main()
