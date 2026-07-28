from pathlib import Path
import unittest


GUI = Path(__file__).resolve().parent


class RemainingProcessWorkerContractTests(unittest.TestCase):
    def test_remaining_gui_workers_use_shared_bounded_process_contract(self):
        required = {
            "rufusarm64.py": ("communicate_bounded(", "iter_bounded_utf8_lines(", "schedule_process_group_termination("),
            "rufusarm64_checksums.py": ("run_bounded(",),
            "rufusarm64_ffu_dialog.py": ("communicate_bounded(", "schedule_process_group_termination("),
            "rufusarm64_freedos_dialog.py": ("iter_bounded_process_utf8_lines(", "run_bounded("),
            "rufusarm64_nonbootable_dialog.py": ("communicate_bounded(", "run_bounded("),
            "rufusarm64_device_qualify_dialog.py": ("communicate_bounded(", "iter_bounded_process_utf8_lines(", "schedule_process_group_termination("),
            "rufusarm64_drive_backup_formats.py": ("iter_bounded_process_utf8_lines(", "run_bounded("),
            "rufusarm64_drive_backup_iso.py": ("iter_bounded_process_utf8_lines(", "run_bounded("),
        }
        forbidden = ("os.killpg(", "process.terminate()", "for line in process.stderr", "process.stdout.read()")
        for name, markers in required.items():
            with self.subTest(file=name):
                source = (GUI / name).read_text(encoding="utf-8")
                for marker in markers:
                    self.assertIn(marker, source)
                for marker in forbidden:
                    self.assertNotIn(marker, source)


if __name__ == "__main__":
    unittest.main()
