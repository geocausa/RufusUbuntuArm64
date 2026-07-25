#!/usr/bin/env python3
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label} anchor count is {count}, expected 1")
    return text.replace(old, new, 1)


main = Path("gui/rufusarm64.py")
text = main.read_text()
text = replace_once(
    text,
    "dialog = FFUReviewDialog(self, helper_path(), image, device)",
    "dialog = FFUReviewDialog(self, PKEXEC, helper_path(), image, device)",
    "FFU dialog privilege path",
)
main.write_text(text)


test = Path("gui/test_source_structure.py")
text = test.read_text()
text = replace_once(
    text,
    '''        workers = {
            "rufusarm64.py": ("run_download", "run_persistence_plan", "run_writer"),
            "rufusarm64_persistence.py": ("run_analysis", "run_create"),
        }
''',
    '''        workers = {
            "rufusarm64.py": ("run_download", "run_persistence_plan", "run_writer"),
            "rufusarm64_ffu_dialog.py": ("_run_restore",),
            "rufusarm64_persistence.py": ("run_analysis", "run_create"),
        }
''',
    "FFU process ownership contract",
)
text = replace_once(
    text,
    '''                "FFUReviewDialog": {
                    "start_review": ("threading.Thread(",),
                    "_run_review": ("subprocess.run(", "timeout=300"),
                    "_finish_review": ("generation != self.generation", "self.closed"),
                },
''',
    '''                "FFUReviewDialog": {
                    "start_review": ("threading.Thread(",),
                    "_run_review": ("subprocess.run(", "timeout=300"),
                    "_finish_review": ("generation != self.generation", "self.closed"),
                    "start_restore": ("threading.Thread(", "build_ffu_restore_command"),
                    "_run_restore": ("subprocess.Popen(", "start_new_session=True", "normalize_ffu_restore_output"),
                    "cancel_restore": ("os.killpg(", "signal.SIGTERM", "target state is not yet known"),
                    "_finish_restore": ("generation != self.generation", "self.closed", "possibly modified"),
                },
''',
    "FFU restore worker contracts",
)
text = replace_once(
    text,
    '''                    if method_name in {"verify_catalog", "image_changed", "refresh_devices", "start_review"} and "subprocess.run(" in body:
''',
    '''                    if method_name in {"verify_catalog", "image_changed", "refresh_devices", "start_review", "start_restore"} and ("subprocess.run(" in body or "subprocess.Popen(" in body):
''',
    "FFU GTK blocking contract",
)
test.write_text(text)
