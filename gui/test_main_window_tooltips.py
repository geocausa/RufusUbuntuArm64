import re
from pathlib import Path
import sys
import types
import unittest


ROOT = Path(__file__).resolve().parent.parent
LAUNCHER = ROOT / "packaging" / "rufusarm64"
EXPECTED_CONTROLS = {
    "image_chooser",
    "download_button",
    "checksum_button",
    "ffu_review_button",
    "target_combo",
    "refresh_button",
    "qualify_button",
    "backup_button",
    "mode_value",
    "verify",
    "persistence_enabled",
    "persistence_size",
    "persistence_button",
    "partition_combo",
    "target_system_combo",
    "filesystem_combo",
    "cluster_combo",
    "volume_label",
    "driver_chooser",
    "dbx_chooser",
    "dbx_update_button",
    "quick_format",
    "bad_block_check",
    "copy_log_button",
    "save_log_button",
    "clear_log_button",
    "cancel_button",
    "start_button",
    "nonbootable_button",
    "freedos_button",
    "uefi_validation_button",
    "appearance_button",
}


def launcher_namespace():
    text = LAUNCHER.read_text(encoding="utf-8")
    match = re.search(r"<<'PYRUFUSARM64'\n(.*)\nPYRUFUSARM64\n\Z", text, re.DOTALL)
    if match is None:
        raise AssertionError("launcher Python payload is missing")

    names = ("gi", "gi.repository", "rufusarm64_i18n")
    saved = {name: sys.modules.get(name) for name in names}
    fake_gi = types.ModuleType("gi")
    fake_gi.require_version = lambda *_: None
    repository = types.ModuleType("gi.repository")
    repository.GLib = types.SimpleNamespace()
    repository.Gtk = types.SimpleNamespace()
    i18n = types.ModuleType("rufusarm64_i18n")
    i18n.gettext = lambda message: message
    i18n.install_localization = lambda window_class: setattr(window_class, "_localization_installed", True)
    sys.modules["gi"] = fake_gi
    sys.modules["gi.repository"] = repository
    sys.modules["rufusarm64_i18n"] = i18n
    try:
        namespace = {"__name__": "rufusarm64_tooltip_contract"}
        exec(compile(match.group(1), str(LAUNCHER), "exec"), namespace)
        return text, namespace
    finally:
        for name, module in saved.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


class FakeWidget:
    def __init__(self, tooltip=""):
        self.tooltip = tooltip

    def get_tooltip_text(self):
        return self.tooltip

    def set_tooltip_text(self, value):
        self.tooltip = value


class MainWindowTooltipTests(unittest.TestCase):
    def test_complete_explicit_control_map_is_present(self):
        _, namespace = launcher_namespace()
        tooltips = namespace["MAIN_CONTROL_TOOLTIPS"]
        self.assertEqual(set(tooltips), EXPECTED_CONTROLS)
        for attribute, description in tooltips.items():
            self.assertIsInstance(attribute, str)
            self.assertGreaterEqual(len(description.strip()), 24)
            self.assertTrue(description.endswith("."), description)

    def test_completion_fills_only_missing_tooltips(self):
        _, namespace = launcher_namespace()
        apply_tooltips = namespace["apply_main_control_tooltips"]

        class Window:
            image_chooser = FakeWidget()
            download_button = FakeWidget("Existing signed-catalog disclosure.")
            target_combo = FakeWidget("   ")

        window = Window()
        self.assertFalse(apply_tooltips(window))
        self.assertEqual(window.image_chooser.tooltip, namespace["MAIN_CONTROL_TOOLTIPS"]["image_chooser"])
        self.assertEqual(window.download_button.tooltip, "Existing signed-catalog disclosure.")
        self.assertEqual(window.target_combo.tooltip, namespace["MAIN_CONTROL_TOOLTIPS"]["target_combo"])
        self.assertEqual(window._main_control_tooltips, ("image_chooser", "download_button", "target_combo"))

    def test_installer_defers_until_composed_window_construction_finishes(self):
        _, namespace = launcher_namespace()
        deferred = []
        namespace["GLib"].idle_add = lambda callback, *args: deferred.append((callback, args)) or 1

        class Window:
            def __init__(self, app):
                self.base_app = app

        installer = namespace["install_main_control_tooltips"]
        installer(Window)
        installer(Window)
        window = Window("application")
        self.assertEqual(window.base_app, "application")
        self.assertTrue(Window._main_control_tooltips_installed)
        self.assertEqual(len(deferred), 1)
        callback, args = deferred[0]
        self.assertIs(callback, namespace["apply_main_control_tooltips"])
        self.assertEqual(args, (window,))

    def test_launcher_orders_tooltips_after_appearance_and_localization_after_tooltips(self):
        text, _ = launcher_namespace()
        appearance = text.index("install_appearance(RufusWindow)")
        tooltips = text.index("install_main_control_tooltips(RufusWindow)")
        localization = text.index("install_localization(RufusWindow)")
        run = text.index('return run_rufusarm64(["rufusarm64", *arguments])')
        self.assertLess(appearance, tooltips)
        self.assertLess(tooltips, localization)
        self.assertLess(localization, run)
        self.assertIn("GLib.idle_add(apply_main_control_tooltips, window)", text)


if __name__ == "__main__":
    unittest.main()
