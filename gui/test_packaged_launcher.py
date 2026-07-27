import re
from pathlib import Path
import sys
import tempfile
import types
import unittest


ROOT = Path(__file__).resolve().parent.parent
LAUNCHER = ROOT / "packaging" / "rufusarm64"


def launcher_payload():
    text = LAUNCHER.read_text(encoding="utf-8")
    match = re.search(r"<<'PYRUFUSARM64'\n(.*)\nPYRUFUSARM64\n\Z", text, re.DOTALL)
    if match is None:
        raise AssertionError("launcher Python payload is missing")
    return text, match.group(1)


class LauncherModuleContext:
    def __init__(self):
        self.saved = {}
        self.names = (
            "gi",
            "gi.repository",
            "rufusarm64_drive_backup_formats",
            "rufusarm64_drive_backup_iso",
            "rufusarm64",
            "rufusarm64_integrated",
        )

    def __enter__(self):
        for name in self.names:
            self.saved[name] = sys.modules.get(name)
        self.pin_calls = []
        fake_gi = types.ModuleType("gi")
        fake_gi.require_version = lambda namespace, version: self.pin_calls.append((namespace, version))
        repository = types.ModuleType("gi.repository")
        repository.GLib = types.SimpleNamespace()
        repository.Gtk = types.SimpleNamespace()
        sys.modules["gi"] = fake_gi
        sys.modules["gi.repository"] = repository
        return self

    def __exit__(self, *_):
        for name, module in self.saved.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


class PackagedLauncherTests(unittest.TestCase):
    def test_launcher_remains_valid_isolated_shell_entrypoint(self):
        text, payload = launcher_payload()
        self.assertTrue(text.startswith("#!/bin/sh\n"))
        self.assertIn('exec /usr/bin/python3 -I - "$@"', text)
        self.assertIn('if [ "${1:-}" = "--persistence" ]; then', text)
        self.assertLess(payload.index('gi.require_version("Gtk", "3.0")'), payload.index("from gi.repository import GLib, Gtk"))
        self.assertLess(payload.index('gi.require_version("Gtk", "3.0")'), payload.index("from rufusarm64_drive_backup_formats import"))
        self.assertIn('sys.path.insert(0, "/usr/lib/rufusarm64")', payload)
        compile(payload, str(LAUNCHER), "exec")

    def test_pure_appearance_contract_normalizes_and_resolves_preferences(self):
        _, payload = launcher_payload()
        with LauncherModuleContext() as context:
            namespace = {"__name__": "rufusarm64_launcher_contract"}
            exec(compile(payload, str(LAUNCHER), "exec"), namespace)
            self.assertEqual(context.pin_calls, [("Gtk", "3.0")])

        normalize = namespace["normalize_appearance"]
        prefers_dark = namespace["appearance_prefers_dark"]
        self.assertEqual(normalize(" SYSTEM "), "system")
        self.assertEqual(normalize("Light"), "light")
        self.assertEqual(normalize("DARK"), "dark")
        self.assertEqual(normalize("contrast"), "system")
        self.assertFalse(prefers_dark("light", True))
        self.assertTrue(prefers_dark("dark", False))
        self.assertTrue(prefers_dark("system", True))
        self.assertFalse(prefers_dark("invalid", False))

    def test_persisted_appearance_reader_fails_closed_to_system(self):
        _, payload = launcher_payload()
        with LauncherModuleContext():
            namespace = {"__name__": "rufusarm64_launcher_contract"}
            exec(compile(payload, str(LAUNCHER), "exec"), namespace)
        reader = namespace["read_persisted_appearance"]

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            self.assertEqual(reader(path), "system")
            path.write_text('{"appearance":"dark"}', encoding="utf-8")
            self.assertEqual(reader(path), "dark")
            path.write_text('{"appearance":"unsupported"}', encoding="utf-8")
            self.assertEqual(reader(path), "system")
            path.write_text("[]", encoding="utf-8")
            self.assertEqual(reader(path), "system")
            path.write_text("{", encoding="utf-8")
            self.assertEqual(reader(path), "system")

    def test_entrypoint_installs_appearance_before_running_composed_application(self):
        _, payload = launcher_payload()
        calls = []
        run_arguments = []

        with LauncherModuleContext() as context:
            formats = types.ModuleType("rufusarm64_drive_backup_formats")
            formats.install_drive_backup_formats = lambda: calls.append("formats")
            iso = types.ModuleType("rufusarm64_drive_backup_iso")
            iso.install_drive_backup_iso = lambda: calls.append("iso")
            base = types.ModuleType("rufusarm64")

            class RufusWindow:
                def __init__(self, _app):
                    pass

            base.RufusWindow = RufusWindow
            integrated = types.ModuleType("rufusarm64_integrated")

            def run_rufusarm64(argv):
                calls.append("run")
                run_arguments.append(argv)
                return 0

            integrated.run_rufusarm64 = run_rufusarm64
            sys.modules["rufusarm64_drive_backup_formats"] = formats
            sys.modules["rufusarm64_drive_backup_iso"] = iso
            sys.modules["rufusarm64"] = base
            sys.modules["rufusarm64_integrated"] = integrated

            original_argv = sys.argv
            try:
                sys.argv = ["-", "image.iso"]
                namespace = {"__name__": "__main__"}
                with self.assertRaises(SystemExit) as stopped:
                    exec(compile(payload, str(LAUNCHER), "exec"), namespace)
            finally:
                sys.argv = original_argv

            self.assertEqual(stopped.exception.code, 0)
            self.assertEqual(context.pin_calls, [("Gtk", "3.0")])
            self.assertEqual(calls, ["formats", "iso", "run"])
            self.assertEqual(run_arguments, [["rufusarm64", "image.iso"]])
            self.assertTrue(RufusWindow._appearance_installed)
            self.assertTrue(callable(RufusWindow.apply_appearance))
            self.assertTrue(callable(RufusWindow.open_appearance_dialog))

    def test_source_exposes_accessible_system_light_dark_dialog(self):
        _, payload = launcher_payload()
        for marker in (
            'APPEARANCE_MODES = (APPEARANCE_SYSTEM, APPEARANCE_LIGHT, APPEARANCE_DARK)',
            'GTK_DARK_PROPERTY = "gtk-application-prefer-dark-theme"',
            '"preferences-desktop-theme-symbolic"',
            '"Change appearance"',
            '"Choose System, Light, or Dark appearance for RufusArm64 and its dialogs."',
            'window.settings["appearance"] = normalized',
            "window.save_settings()",
            "Follow the desktop appearance observed when RufusArm64 started.",
        ):
            self.assertIn(marker, payload)


if __name__ == "__main__":
    unittest.main()
