import builtins
from pathlib import Path
import re
import sys
import types
import unittest


ROOT = Path(__file__).resolve().parent.parent
LAUNCHER = ROOT / "packaging" / "rufusarm64"


class PackagedLauncherTests(unittest.TestCase):
    def test_launcher_pins_gtk3_before_integrated_dialog_import(self):
        text = LAUNCHER.read_text(encoding="utf-8")
        self.assertIn("/usr/bin/python3 -I", text)
        match = re.search(r"-c '([^']+)'", text)
        self.assertIsNotNone(match, "launcher Python payload is missing")
        payload = match.group(1)

        pin_calls = []
        fake_gi = types.ModuleType("gi")
        fake_gi.require_version = lambda namespace, version: pin_calls.append((namespace, version))

        original_import = builtins.__import__
        original_argv = sys.argv
        original_gi = sys.modules.get("gi")

        def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "rufusarm64_device_qualify_dialog":
                self.assertEqual(pin_calls, [("Gtk", "3.0")])
                module = types.ModuleType(name)
                module.run_rufusarm64 = lambda argv: 0
                return module
            return original_import(name, globals, locals, fromlist, level)

        try:
            sys.modules["gi"] = fake_gi
            sys.argv = ["-c"]
            builtins.__import__ = guarded_import
            with self.assertRaises(SystemExit) as stopped:
                exec(compile(payload, str(LAUNCHER), "exec"), {})
            self.assertEqual(stopped.exception.code, 0)
            self.assertEqual(pin_calls, [("Gtk", "3.0")])
        finally:
            builtins.__import__ = original_import
            sys.argv = original_argv
            if original_gi is None:
                sys.modules.pop("gi", None)
            else:
                sys.modules["gi"] = original_gi


if __name__ == "__main__":
    unittest.main()
