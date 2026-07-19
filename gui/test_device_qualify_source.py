import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class DeviceQualificationSourceTests(unittest.TestCase):
    def read(self, relative):
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_main_window_exposes_separate_target_action(self):
        source = self.read("gui/rufusarm64.py")
        self.assertIn(
            "from rufusarm64_device_qualify_dialog import DeviceQualificationDialog",
            source,
        )
        self.assertIn(
            'DEVICE_QUALIFICATION_HELPER = "/usr/lib/rufusarm64/rufusarm64-device-qualify"',
            source,
        )
        self.assertIn('Gtk.Button(label="Test USB drive…")', source)
        self.assertIn('self.target_combo.connect("changed", self.target_selection_changed)', source)
        self.assertIn("def open_device_qualification", source)
        self.assertIn("DeviceQualificationDialog(", source)
        self.assertNotIn("device-qualify", self._writer_command_slice(source))

    def test_dialog_keeps_destructive_workflow_guarded(self):
        source = self.read("gui/rufusarm64_device_qualify_dialog.py")
        for required in (
            'modal=True',
            'f"ERASE {self.device_path}"',
            'start_new_session=True',
            'os.killpg(process.pid, signal.SIGTERM)',
            'self.parent_window.active_job = "qualification"',
            'self.parent_window.set_busy(True)',
            'normalize_qualification_event(json.loads(line))',
            'json.dumps(report, indent=2, sort_keys=True)',
        ):
            self.assertIn(required, source)
        self.assertNotIn("shell=True", source)

    def test_helper_accepts_only_guarded_graphical_stream(self):
        source = self.read("cmd/rufus-device-qualify/main.go")
        self.assertIn('jsonProgress := flags.Bool("json-progress"', source)
        self.assertIn('graphical device qualification requires --json-progress', source)
        self.assertIn('Event: "progress"', source)
        self.assertIn('Event: "result"', source)
        self.assertIn('non-dry-run machine output requires --yes and --expected-identity', source)

    def test_package_contains_both_python_modules(self):
        build = self.read("scripts/build-deb.sh")
        tests = self.read("scripts/test.sh")
        for filename in (
            "rufusarm64_device_qualify.py",
            "rufusarm64_device_qualify_dialog.py",
        ):
            self.assertIn(filename, build)
            self.assertGreaterEqual(tests.count(filename), 2)

    @staticmethod
    def _writer_command_slice(source):
        start = source.index("def build_writer_command") if "def build_writer_command" in source else 0
        end = source.find("\n    def ", start + 1)
        return source[start:] if end < 0 else source[start:end]


if __name__ == "__main__":
    unittest.main()
