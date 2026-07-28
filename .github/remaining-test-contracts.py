#!/usr/bin/env python3
"""Refresh exact source-contract tests for the shared bounded process migration."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path, old, new, label):
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise SystemExit(f"{label} changed: found {text.count(old)}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_once(
    "gui/test_acquisition_dialog_i18n.py",
    "            'os.killpg(process.pid, signal.SIGTERM)',\n",
    "            'schedule_process_group_termination(process, grace_seconds=5)',\n            'communicate_bounded(',\n            'run_bounded(',\n",
    "acquisition localization process markers",
)
replace_once(
    "gui/test_verified_acquisition_ui.py",
    '        self.assertIn("os.killpg(process.pid, signal.SIGTERM)", self.main_source)\n',
    '        self.assertIn("schedule_process_group_termination(process, grace_seconds=5)", self.main_source)\n        self.assertIn("iter_bounded_utf8_lines(", self.main_source)\n',
    "verified acquisition cancellation marker",
)

old_backup = '''    def test_cancel_and_close_target_only_the_owned_process_group(self):
        self.assertIn("os.killpg(process.pid, signal.SIGTERM)", self.backup_class_source)
        self.assertIn("GLib.timeout_add_seconds(5, self._force_kill, process)", self.backup_class_source)
        self.assertIn("os.killpg(process.pid, signal.SIGKILL)", self.backup_class_source)
        self.assertIn("if self.process is process and process.poll() is None", self.backup_class_source)
        self.assertIn("def _terminate_and_reap(process):", self.backup_class_source)
        self.assertIn("process.communicate(timeout=5)", self.backup_class_source)
        self.assertIn("Closing requested. Cancelling", self.backup_class_source)
        self.assertIn("dialog._terminate_and_reap(process)", self.format_source)
        self.assertIn("dialog._terminate_and_reap(process)", self.iso_source)
'''
new_backup = '''    def test_cancel_and_close_target_only_the_owned_process_group(self):
        self.assertIn("schedule_process_group_termination(process, grace_seconds=5)", self.backup_class_source)
        self.assertIn("iter_bounded_process_utf8_lines(", self.backup_class_source)
        self.assertIn("terminate_and_reap(process)", self.backup_class_source)
        self.assertNotIn("os.killpg(", self.backup_class_source)
        self.assertIn("Closing requested. Cancelling", self.backup_class_source)
        self.assertIn("terminate_and_reap(process)", self.format_source)
        self.assertIn("terminate_and_reap(process)", self.iso_source)
'''
replace_once("gui/test_device_backup_dialog.py", old_backup, new_backup, "backup cancellation source contract")

old_qualification = '''    def test_cancellation_does_not_kill_arbitrary_processes(self):
        self.assertIn("process = self.process", self.qualification_source)
        self.assertIn("process.poll() is not None", self.qualification_source)
        self.assertIn("process.terminate()", self.qualification_source)
        self.assertNotIn("os.killpg", self.qualification_source)
'''
new_qualification = '''    def test_cancellation_targets_only_the_owned_process_group(self):
        self.assertIn("process = self.process", self.qualification_source)
        self.assertIn("process.poll() is not None", self.qualification_source)
        self.assertIn("schedule_process_group_termination(process, grace_seconds=5)", self.qualification_source)
        self.assertIn("start_new_session=True", self.qualification_source)
        self.assertNotIn("process.terminate()", self.qualification_source)
        self.assertNotIn("os.killpg", self.qualification_source)
'''
replace_once("gui/test_device_qualify_dialog.py", old_qualification, new_qualification, "qualification cancellation source contract")

replace_once(
    "gui/test_drive_backup_i18n.py",
    '            "os.killpg(process.pid, signal.SIGTERM)",\n',
    '            "schedule_process_group_termination(process, grace_seconds=5)",\n            "iter_bounded_process_utf8_lines(",\n',
    "drive backup localization process markers",
)

replace_once(
    "gui/test_freedos_dialog.py",
    '        self.assertIn("subprocess.run(command", self.dialog_class_source)\n',
    '        self.assertIn("run_bounded(", self.dialog_class_source)\n',
    "FreeDOS bounded plan marker",
)
replace_once(
    "gui/test_freedos_dialog.py",
    '''        self.assertIn("os.killpg(process.pid, signal.SIGTERM)", self.dialog_class_source)
        self.assertIn("os.killpg(process.pid, signal.SIGKILL)", self.dialog_class_source)
''',
    '''        self.assertIn("iter_bounded_process_utf8_lines(", self.dialog_class_source)
        self.assertIn("terminate_and_reap(process)", self.dialog_class_source)
        self.assertNotIn("os.killpg(", self.dialog_class_source)
''',
    "FreeDOS bounded group markers",
)
replace_once(
    "gui/test_freedos_dialog.py",
    '        self.assertIn("for line in process.stderr", self.dialog_class_source)\n',
    '        self.assertIn("for channel, line in iter_bounded_process_utf8_lines(", self.dialog_class_source)\n',
    "FreeDOS concurrent progress marker",
)

replace_once(
    "gui/test_nonbootable_dialog.py",
    '        self.assertIn("subprocess.run(command", self.dialog_class_source)\n',
    '        self.assertIn("run_bounded(", self.dialog_class_source)\n',
    "nonbootable bounded plan marker",
)
replace_once(
    "gui/test_nonbootable_dialog.py",
    '''        self.assertIn("os.killpg(process.pid, signal.SIGTERM)", self.dialog_class_source)
        self.assertIn("os.killpg(process.pid, signal.SIGKILL)", self.dialog_class_source)
''',
    '''        self.assertIn("communicate_bounded(", self.dialog_class_source)
        self.assertIn("terminate_and_reap(process)", self.dialog_class_source)
        self.assertNotIn("os.killpg(", self.dialog_class_source)
''',
    "nonbootable bounded group markers",
)

replace_once(
    "gui/test_source_structure.py",
    '                    "_run_catalog_verify": ("subprocess.run(",),\n',
    '                    "_run_catalog_verify": ("run_bounded(",),\n',
    "source structure acquisition marker",
)
replace_once(
    "gui/test_source_structure.py",
    '                    "cancel_restore": ("os.killpg(", "signal.SIGTERM", "target state is not yet known"),\n',
    '                    "cancel_restore": ("schedule_process_group_termination(", "grace_seconds=5", "target state is not yet known"),\n',
    "source structure FFU cancellation marker",
)
