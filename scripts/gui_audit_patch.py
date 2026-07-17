#!/usr/bin/env python3
"""Apply reviewed GUI settings and DBX task hardening exactly once."""

from pathlib import Path

root = Path(__file__).resolve().parents[1]


def replace(path: str, old: str, new: str) -> None:
    file = root / path
    text = file.read_text(encoding="utf-8")
    if old not in text:
        if new in text:
            return
        raise SystemExit(f"{path}: expected source block not found: {old[:100]!r}")
    file.write_text(text.replace(old, new, 1), encoding="utf-8")


replace(
    "gui/rufusarm64_logic.py",
    'import os\nimport re\nimport stat\n',
    'import json\nimport os\nimport re\nimport stat\nimport tempfile\n',
)
replace(
    "gui/rufusarm64_logic.py",
    'SUPPORTED_IMAGE_SUFFIXES = (\n',
    '''def atomic_write_json(path, payload):
    """Durably replace an owner-only JSON file without following directory links."""
    absolute = os.path.abspath(path)
    directory = os.path.dirname(absolute)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    directory_info = os.lstat(directory)
    if stat.S_ISLNK(directory_info.st_mode) or not stat.S_ISDIR(directory_info.st_mode):
        raise OSError("settings directory is not a real directory")
    os.chmod(directory, 0o700)

    descriptor = -1
    temporary = ""
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=".settings-", suffix=".tmp", dir=directory)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, absolute)
        temporary = ""
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        directory_fd = os.open(directory, flags)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


SUPPORTED_IMAGE_SUFFIXES = (
''',
)

replace(
    "gui/rufusarm64.py",
    '    acquisition_image_label,\n',
    '    acquisition_image_label,\n    atomic_write_json,\n',
)
replace(
    "gui/rufusarm64.py",
    '''        try:
            os.makedirs(directory, mode=0o700, exist_ok=True)
            temporary = path + ".tmp"
            with open(temporary, "w", encoding="utf-8") as handle:
                json.dump(self.settings, handle, indent=2, sort_keys=True)
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
        except OSError:
            pass
''',
    '''        try:
            atomic_write_json(path, self.settings)
        except (OSError, TypeError, ValueError):
            pass
''',
)
replace(
    "gui/rufusarm64.py",
    '''        self.dbx_update_button.set_sensitive(False)
        self.progress.set_text("Downloading Microsoft Secure Boot DBX…")

        def worker():
''',
    '''        self.active_job = "dbx-update"
        self.cancel_requested = False
        self.operation_started_at = datetime.now(timezone.utc)
        self.set_busy(True)
        self.progress.pulse()
        self.progress.set_text("Downloading Microsoft Secure Boot DBX…")
        self.progress_detail.set_text("The DBX update is read-only, but other operations remain disabled until it finishes.")

        def worker():
''',
)
replace(
    "gui/rufusarm64.py",
    '''    def finish_dbx_update(self, path, digest, error):
        self.dbx_update_button.set_sensitive(not self.busy and self.inspection.get("mode") == "windows")
        if error:
''',
    '''    def finish_dbx_update(self, path, digest, error):
        if self.active_job != "dbx-update":
            return False
        self.active_job = ""
        self.set_busy(False)
        if error:
''',
)

replace(
    "gui/test_logic.py",
    '    acquisition_image_label,\n',
    '    acquisition_image_label,\n    atomic_write_json,\n',
)
replace(
    "gui/test_logic.py",
    '''    def test_human_bytes(self):
        self.assertEqual(human_bytes(1024), "1.0 KiB")
''',
    '''    def test_atomic_write_json_is_owner_only_and_replaces(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "settings.json")
            atomic_write_json(path, {"value": 1})
            atomic_write_json(path, {"value": 2})
            with open(path, "r", encoding="utf-8") as handle:
                self.assertEqual(handle.read(), '{\\n  "value": 2\\n}')
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            self.assertEqual(sorted(os.listdir(directory)), ["settings.json"])

    def test_atomic_write_json_rejects_symlink_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            real = os.path.join(directory, "real")
            linked = os.path.join(directory, "linked")
            os.mkdir(real)
            os.symlink(real, linked)
            with self.assertRaises(OSError):
                atomic_write_json(os.path.join(linked, "settings.json"), {"unsafe": True})

    def test_human_bytes(self):
        self.assertEqual(human_bytes(1024), "1.0 KiB")
''',
)
