#!/usr/bin/env python3
"""Apply the reviewed pre-0.11 cross-file hardening edits exactly once.

This temporary branch-maintenance script exists because the audited changes
span large source files. Every replacement is exact and fail-closed so drift
cannot produce a partial semantic edit.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_exact(path: str, old: str, new: str, *, expected: int = 1) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count == 0 and new in text:
        return
    if count != expected:
        raise SystemExit(f"{path}: expected {expected} occurrence(s), found {count}: {old!r}")
    target.write_text(text.replace(old, new, expected), encoding="utf-8")


def main() -> None:
    replace_exact("cmd/rufus-linux/main.go", 'var version = "0.9.0"', 'var version = "development"')
    replace_exact(
        "cmd/rufus-linux/main.go",
        'postWriteTargetCheck := func(source *os.File) error {\n\t\treturn targetCheck(source, "")\n\t}',
        'postWriteTargetCheck := func(source *os.File) error {\n\t\treturn targetCheck(source, selectedIdentity)\n\t}',
    )

    replace_exact("gui/rufusarm64.py", 'VERSION = "0.9.0"', 'VERSION = "development"')
    replace_exact(
        "gui/rufusarm64.py",
        'INSTALLED_HELPER = os.environ.get("RUFUSARM64_HELPER", "/usr/lib/rufusarm64/rufusarm64-helper")\n'
        'BUNDLED_WIMLIB = os.environ.get("RUFUSARM64_WIMLIB", "/usr/lib/rufusarm64/wimlib-imagex")',
        'INSTALLED_HELPER = "/usr/lib/rufusarm64/rufusarm64-helper"\n'
        'BUNDLED_WIMLIB = "/usr/lib/rufusarm64/wimlib-imagex"\n'
        'PERSISTENCE_LAUNCHER = "/usr/bin/rufusarm64-persistence"',
    )
    replace_exact(
        "gui/rufusarm64.py",
        'def helper_path():\n    return INSTALLED_HELPER\n\n\n',
        'def helper_path():\n    return INSTALLED_HELPER\n\n\n'
        'def persistence_launcher_path():\n'
        '    if os.path.isfile(PERSISTENCE_LAUNCHER) and os.access(PERSISTENCE_LAUNCHER, os.X_OK):\n'
        '        return PERSISTENCE_LAUNCHER\n'
        '    development = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rufusarm64_persistence.py")\n'
        '    if os.path.isfile(development) and os.access(development, os.X_OK):\n'
        '        return development\n'
        '    raise FileNotFoundError("The guarded persistence creator is not installed.")\n\n\n',
    )
    replace_exact(
        "gui/rufusarm64.py",
        '            "Only the image is mounted, with read-only, no-suid, no-device and no-exec restrictions. "\n'
        '            "Persistent USB creation remains experimental and command-line only."',
        '            "Only the image is mounted, with read-only, no-suid, no-device and no-exec restrictions. "\n'
        '            "After analysis, return to the main window and open the guarded persistent USB creator."',
    )
    replace_exact(
        "gui/rufusarm64.py",
        '        persistence = Gtk.Expander(label="Linux persistence compatibility (experimental)")\n'
        '        persistence_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)\n'
        '        persistence_box.set_margin_top(8)\n'
        '        persistence_intro = Gtk.Label(label=(\n'
        '            "Analyze supported Ubuntu casper or Debian live-boot media before using the experimental command-line creator. "\n'
        '            "This analysis is read-only."\n'
        '        ))\n'
        '        persistence_intro.set_xalign(0)\n'
        '        persistence_intro.set_line_wrap(True)\n'
        '        persistence_box.pack_start(persistence_intro, False, False, 0)\n'
        '        self.persistence_button = Gtk.Button(label="Analyze selected image…")\n'
        '        self.persistence_button.set_halign(Gtk.Align.START)\n'
        '        self.persistence_button.connect("clicked", self.analyze_persistence)\n'
        '        persistence_box.pack_start(self.persistence_button, False, False, 0)',
        '        persistence = Gtk.Expander(label="Persistent Linux media (guarded creator)")\n'
        '        persistence_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)\n'
        '        persistence_box.set_margin_top(8)\n'
        '        persistence_intro = Gtk.Label(label=(\n'
        '            "The ordinary Create USB button preserves Linux images byte-for-byte and does not add persistence. "\n'
        '            "Check compatibility here, then open the guarded creator to build a writable FAT32 plus ext4 persistent USB."\n'
        '        ))\n'
        '        persistence_intro.set_xalign(0)\n'
        '        persistence_intro.set_line_wrap(True)\n'
        '        persistence_box.pack_start(persistence_intro, False, False, 0)\n'
        '        persistence_actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)\n'
        '        self.persistence_button = Gtk.Button(label="Check persistence compatibility…")\n'
        '        self.persistence_button.connect("clicked", self.analyze_persistence)\n'
        '        persistence_actions.pack_start(self.persistence_button, False, False, 0)\n'
        '        self.open_persistence_button = Gtk.Button(label="Open Persistent USB Creator…")\n'
        '        self.open_persistence_button.connect("clicked", self.open_persistence_creator)\n'
        '        persistence_actions.pack_start(self.open_persistence_button, False, False, 0)\n'
        '        persistence_box.pack_start(persistence_actions, False, False, 0)',
    )
    replace_exact(
        "gui/rufusarm64.py",
        '        for widget in (self.image_chooser, self.download_button, self.target_combo, self.refresh_button, self.verify):\n'
        '            widget.set_sensitive(not busy)',
        '        for widget in (self.image_chooser, self.download_button, self.target_combo, self.refresh_button, self.verify, self.open_persistence_button):\n'
        '            widget.set_sensitive(not busy)',
    )
    replace_exact(
        "gui/rufusarm64.py",
        '    def analyze_persistence(self, *_):\n',
        '    def open_persistence_creator(self, *_):\n'
        '        if self.busy:\n'
        '            return\n'
        '        try:\n'
        '            subprocess.Popen([persistence_launcher_path()], start_new_session=True)\n'
        '        except OSError as exc:\n'
        '            self.message(f"Could not open the persistent USB creator: {exc}", Gtk.MessageType.ERROR)\n\n'
        '    def analyze_persistence(self, *_):\n',
    )
    replace_exact(
        "gui/rufusarm64.py",
        '                self.progress_detail.set_text("The private read-only ISO mount was removed. Creation remains experimental and command-line only.")',
        '                self.progress_detail.set_text("The private read-only ISO mount was removed. Open the guarded persistent USB creator to continue.")',
    )

    replace_exact(
        "gui/rufusarm64_logic.py",
        '    lines.append("Planning is read-only. Persistent USB creation remains experimental and command-line only.")',
        '    lines.append("Planning is read-only. Use the guarded persistent USB creator for the destructive creation step.")',
    )

    replace_exact(
        "gui/rufusarm64_persistence.py",
        'HELPER = os.environ.get("RUFUSARM64_HELPER", "/usr/lib/rufusarm64/rufusarm64-helper")\n'
        'PERSISTENCE_HELPER = os.environ.get(\n'
        '    "RUFUSARM64_PERSISTENCE_HELPER", "/usr/lib/rufusarm64/rufusarm64-persistence-helper"\n'
        ')',
        'HELPER = "/usr/lib/rufusarm64/rufusarm64-helper"\n'
        'PERSISTENCE_HELPER = "/usr/lib/rufusarm64/rufusarm64-persistence-helper"',
    )

    replace_exact(
        "internal/windowsmedia/windowsmedia.go",
        '\tcandidates := make([]string, 0, 4)\n'
        '\tif envPath := strings.TrimSpace(os.Getenv("RUFUSARM64_WIMLIB")); envPath != "" {\n'
        '\t\tcandidates = append(candidates, envPath)\n'
        '\t}\n',
        '\tcandidates := make([]string, 0, 3)\n',
    )

    build = ROOT / "scripts/build-deb.sh"
    text = build.read_text(encoding="utf-8")
    start = text.find("replacements = (\n")
    end_marker = 'grep -Fxq "VERSION = \\"${VERSION}\\"" "${GUI_TARGET}"\n'
    end = text.find(end_marker)
    if start >= 0:
        if end < 0:
            raise SystemExit("scripts/build-deb.sh: could not find the post-rewrite version check")
        text = text[:start] + text[end:]
    elif "replacements = (" in text:
        raise SystemExit("scripts/build-deb.sh: unexpected semantic-rewrite block")
    text = text.replace(
        '# repository version into the installed GUI. Also make the boundary between the\n'
        '# ordinary writer and the dedicated persistence creator explicit in the shipped\n'
        '# interface so a successful analysis cannot be mistaken for a changed write mode.\n'
        '# Fail closed if any expected source string has drifted.\n',
        '# repository version into the installed GUI. All interface semantics live in the\n'
        '# tested source file; packaging must not rewrite application behavior or wording.\n',
    )
    text = text.replace(
        'grep -Fq "Persistent Linux media (separate creator)" "${GUI_TARGET}"\n'
        'grep -Fq "the main Create USB button remains an ordinary image write" "${GUI_TARGET}"\n',
        'grep -Fq "Persistent Linux media (guarded creator)" "${GUI_TARGET}"\n'
        'grep -Fq "Open Persistent USB Creator" "${GUI_TARGET}"\n',
    )
    build.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
