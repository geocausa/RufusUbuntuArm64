#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one replacement target, found {count}")
    file_path.write_text(text.replace(old, new, 1), encoding="utf-8")


checksum_logic = r'''CHECKSUM_ALGORITHMS = ("md5", "sha1", "sha256", "sha512")
CHECKSUM_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}
CHECKSUM_LABELS = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "sha512": "SHA-512"}


def build_checksum_command(helper, image):
    helper = str(helper or "").strip()
    image = str(image or "").strip()
    if not helper:
        raise ValueError("The RufusArm64 checksum helper is not installed correctly.")
    if not image:
        raise ValueError("Choose an image before calculating checksums.")
    return [helper, "hash", "--all", "--json", image]


def normalize_checksum_result(payload):
    if not isinstance(payload, dict):
        raise ValueError("The checksum helper returned an invalid response.")
    path = str(payload.get("path") or "").strip()
    try:
        size = int(payload.get("size") or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError("The checksum helper returned an invalid image size.") from exc
    digests = payload.get("digests")
    if not path or not os.path.isabs(path) or size <= 0 or not isinstance(digests, list):
        raise ValueError("The checksum helper response is incomplete.")
    if len(digests) != len(CHECKSUM_ALGORITHMS):
        raise ValueError("The checksum helper did not return the complete algorithm set.")
    normalized = []
    for index, algorithm in enumerate(CHECKSUM_ALGORITHMS):
        item = digests[index]
        if not isinstance(item, dict) or item.get("algorithm") != algorithm:
            raise ValueError("The checksum helper returned algorithms in an unexpected order.")
        value = str(item.get("hex") or "").strip()
        if not re.fullmatch(rf"[0-9a-f]{{{CHECKSUM_LENGTHS[algorithm]}}}", value):
            raise ValueError(f"The checksum helper returned an invalid {CHECKSUM_LABELS[algorithm]} value.")
        normalized.append({"algorithm": algorithm, "hex": value})
    return {"path": path, "size": size, "digests": normalized}


def checksum_summary(payload):
    result = normalize_checksum_result(payload)
    lines = [f"File: {result['path']}", f"Size: {human_bytes(result['size'])}", ""]
    for item in result["digests"]:
        lines.append(f"{CHECKSUM_LABELS[item['algorithm']]}: {item['hex']}")
    lines.extend([
        "",
        "MD5 and SHA-1 are shown only for comparison with legacy published checksums.",
        "Use a trusted signature or authenticated catalog for authenticity decisions.",
    ])
    return "\n".join(lines)


'''
replace_once(
    "gui/rufusarm64_logic.py",
    "def build_acquisition_channel_list_command(helper, config):\n",
    checksum_logic + "def build_acquisition_channel_list_command(helper, config):\n",
)

replace_once(
    "gui/test_logic.py",
    "    build_acquisition_channel_download_command,\n",
    "    build_acquisition_channel_download_command,\n    build_checksum_command,\n",
)
replace_once(
    "gui/test_logic.py",
    "    device_label,\n",
    "    checksum_summary,\n    device_label,\n",
)
replace_once(
    "gui/test_logic.py",
    "    normalize_acquisition_images,\n",
    "    normalize_acquisition_images,\n    normalize_checksum_result,\n",
)
checksum_tests = r'''    def test_checksum_command_and_normalization_are_read_only(self):
        command = build_checksum_command("/helper", "/images/ubuntu.iso")
        self.assertEqual(command, ["/helper", "hash", "--all", "--json", "/images/ubuntu.iso"])
        self.assertNotIn("pkexec", command)
        self.assertNotIn("write", command)
        payload = normalize_checksum_result({
            "path": "/images/ubuntu.iso",
            "size": 4096,
            "digests": [
                {"algorithm": "md5", "hex": "a" * 32},
                {"algorithm": "sha1", "hex": "b" * 40},
                {"algorithm": "sha256", "hex": "c" * 64},
                {"algorithm": "sha512", "hex": "d" * 128},
            ],
        })
        self.assertEqual([item["algorithm"] for item in payload["digests"]], ["md5", "sha1", "sha256", "sha512"])
        summary = checksum_summary(payload)
        self.assertIn("MD5: " + "a" * 32, summary)
        self.assertIn("SHA-512: " + "d" * 128, summary)
        self.assertIn("legacy published checksums", summary)

    def test_checksum_normalization_rejects_incomplete_or_ambiguous_results(self):
        valid = {
            "path": "/images/ubuntu.iso",
            "size": 1,
            "digests": [
                {"algorithm": "md5", "hex": "a" * 32},
                {"algorithm": "sha1", "hex": "b" * 40},
                {"algorithm": "sha256", "hex": "c" * 64},
                {"algorithm": "sha512", "hex": "d" * 128},
            ],
        }
        for payload in (
            None,
            {**valid, "path": "relative.iso"},
            {**valid, "size": 0},
            {**valid, "digests": valid["digests"][:-1]},
            {**valid, "digests": [valid["digests"][1], valid["digests"][0], *valid["digests"][2:]]},
            {**valid, "digests": [{**valid["digests"][0], "hex": "A" * 32}, *valid["digests"][1:]]},
        ):
            with self.assertRaises(ValueError):
                normalize_checksum_result(payload)
        with self.assertRaises(ValueError):
            build_checksum_command("", "/images/ubuntu.iso")
        with self.assertRaises(ValueError):
            build_checksum_command("/helper", "")

'''
replace_once(
    "gui/test_logic.py",
    "    def test_acquisition_commands_and_catalog_normalization(self):\n",
    checksum_tests + "    def test_acquisition_commands_and_catalog_normalization(self):\n",
)

Path("gui/rufusarm64_checksums.py").write_text(r'''#!/usr/bin/env python3
"""Unprivileged GTK dialog for descriptor-bound selected-image checksums."""

import json
import subprocess
import threading

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import GLib, Gtk

from rufusarm64_logic import build_checksum_command, checksum_summary, normalize_checksum_result


class ChecksumDialog(Gtk.Dialog):
    """Calculate all Rufus-compatible checksums without entering a write path."""

    def __init__(self, parent, helper, image_path):
        super().__init__(title="Image checksums", transient_for=parent, modal=True)
        self.parent_window = parent
        self.helper = helper
        self.image_path = image_path
        self.running = False
        self.closed = False
        self.generation = 0
        self.report = ""
        self.set_default_size(760, 520)
        self.add_button("Close", Gtk.ResponseType.CLOSE)
        self.close_button = self.get_widget_for_response(Gtk.ResponseType.CLOSE)
        self.connect("delete-event", self.on_delete_event)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_border_width(18)
        self.get_content_area().pack_start(box, True, True, 0)

        intro = Gtk.Label(label=(
            "Calculate MD5, SHA-1, SHA-256, and SHA-512 for the selected image in one read-only pass. "
            "The image is not mounted or modified, no USB device is opened, and administrator authentication is not used."
        ))
        intro.set_xalign(0)
        intro.set_line_wrap(True)
        box.pack_start(intro, False, False, 0)

        path_label = Gtk.Label(label=image_path)
        path_label.set_xalign(0)
        path_label.set_line_wrap(True)
        path_label.set_selectable(True)
        path_label.get_style_context().add_class("dim-label")
        box.pack_start(path_label, False, False, 0)

        warning = Gtk.InfoBar()
        warning.set_message_type(Gtk.MessageType.INFO)
        warning_label = Gtk.Label(label=(
            "MD5 and SHA-1 are included only for comparison with legacy published values. "
            "They are not used by RufusArm64 for trust, signatures, downloads, or write assurance."
        ))
        warning_label.set_xalign(0)
        warning_label.set_line_wrap(True)
        warning.get_content_area().add(warning_label)
        box.pack_start(warning, False, False, 0)

        action_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.calculate_button = Gtk.Button(label="Calculate")
        self.calculate_button.get_style_context().add_class("suggested-action")
        self.calculate_button.connect("clicked", self.start)
        action_row.pack_start(self.calculate_button, False, False, 0)
        self.copy_button = Gtk.Button(label="Copy report")
        self.copy_button.set_sensitive(False)
        self.copy_button.connect("clicked", self.copy_report)
        action_row.pack_start(self.copy_button, False, False, 0)
        self.spinner = Gtk.Spinner()
        action_row.pack_start(self.spinner, False, False, 0)
        self.status = Gtk.Label(label="Select Calculate to hash the exact image file.")
        self.status.set_xalign(0)
        self.status.set_line_wrap(True)
        action_row.pack_start(self.status, True, True, 0)
        box.pack_start(action_row, False, False, 0)

        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scroll.set_hexpand(True)
        scroll.set_vexpand(True)
        self.result_view = Gtk.TextView(
            editable=False,
            cursor_visible=False,
            monospace=True,
            wrap_mode=Gtk.WrapMode.WORD_CHAR,
        )
        self.result_view.get_buffer().set_text("No checksums have been calculated.")
        scroll.add(self.result_view)
        box.pack_start(scroll, True, True, 0)
        self.show_all()

    def on_delete_event(self, *_):
        if self.running:
            self.status.set_text("Checksum calculation is still running. Wait for it to finish before closing this dialog.")
            return True
        self.closed = True
        self.generation += 1
        return False

    def set_running(self, running):
        self.running = bool(running)
        self.calculate_button.set_sensitive(not self.running)
        self.close_button.set_sensitive(not self.running)
        self.copy_button.set_sensitive(not self.running and bool(self.report))
        if self.running:
            self.spinner.start()
        else:
            self.spinner.stop()

    def start(self, *_):
        if self.running:
            return
        try:
            command = build_checksum_command(self.helper, self.image_path)
        except ValueError as exc:
            self.status.set_text(str(exc))
            return
        self.generation += 1
        generation = self.generation
        self.report = ""
        self.set_running(True)
        self.status.set_text("Reading the selected image and calculating four checksums…")
        self.result_view.get_buffer().set_text("Checksum calculation in progress…")
        threading.Thread(target=self._run, args=(command, generation), daemon=True).start()

    def _run(self, command, generation):
        payload = None
        failure = ""
        try:
            completed = subprocess.run(
                command,
                check=False,
                text=True,
                capture_output=True,
                timeout=900,
            )
            if completed.returncode != 0:
                failure = completed.stderr.strip() or "The checksum helper failed."
            elif not completed.stdout.strip():
                failure = "The checksum helper returned no result."
            else:
                payload = normalize_checksum_result(json.loads(completed.stdout))
        except subprocess.TimeoutExpired:
            failure = "Checksum calculation exceeded the fifteen-minute safety limit."
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            failure = str(exc)
        GLib.idle_add(self._finish, generation, payload, failure)

    def _finish(self, generation, payload, failure):
        if self.closed or generation != self.generation:
            return False
        self.set_running(False)
        if failure:
            self.status.set_text("Checksums could not be calculated.")
            self.result_view.get_buffer().set_text(failure)
            self.parent_window.append_log(f"Image checksum calculation failed: {failure}")
            return False
        self.report = checksum_summary(payload)
        self.result_view.get_buffer().set_text(self.report)
        self.status.set_text("Checksums calculated successfully.")
        self.copy_button.set_sensitive(True)
        self.parent_window.append_log("Selected-image checksums:\n" + json.dumps(payload, indent=2, sort_keys=True))
        return False

    def copy_report(self, *_):
        if not self.report:
            return
        Gtk.Clipboard.get_default(self.get_display()).set_text(self.report, -1)
        self.status.set_text("Checksum report copied to the clipboard.")
''', encoding="utf-8")

replace_once(
    "gui/rufusarm64.py",
    "from rufusarm64_logic import (\n",
    "from rufusarm64_checksums import ChecksumDialog\n\nfrom rufusarm64_logic import (\n",
)
replace_once(
    "gui/rufusarm64.py",
    '''        self.download_button.connect("clicked", self.open_acquisition)
        image_row.pack_start(self.download_button, False, False, 0)
        grid.attach(image_row, 1, 0, 2, 1)
''',
    '''        self.download_button.connect("clicked", self.open_acquisition)
        image_row.pack_start(self.download_button, False, False, 0)
        self.checksum_button = Gtk.Button(label="Checksums…")
        self.checksum_button.set_sensitive(False)
        self.checksum_button.set_tooltip_text("Calculate MD5, SHA-1, SHA-256, and SHA-512 for the selected image")
        self.checksum_button.connect("clicked", self.open_checksum_dialog)
        image_row.pack_start(self.checksum_button, False, False, 0)
        grid.attach(image_row, 1, 0, 2, 1)
''',
)
replace_once(
    "gui/rufusarm64.py",
    '''        for widget in (
            self.image_chooser,
            self.download_button,
            self.target_combo,
            self.verify,
            self.open_persistence_button,
            self.uefi_validation_button,
        ):
            widget.set_sensitive(not busy)
        self.refresh_button.set_sensitive(not busy and not self.device_refreshing)
''',
    '''        for widget in (
            self.image_chooser,
            self.download_button,
            self.target_combo,
            self.verify,
            self.open_persistence_button,
            self.uefi_validation_button,
        ):
            widget.set_sensitive(not busy)
        selected_image = self.image_chooser.get_filename() or ""
        self.checksum_button.set_sensitive(
            not busy and background_idle and bool(selected_image) and os.path.isfile(selected_image)
        )
        self.refresh_button.set_sensitive(not busy and not self.device_refreshing)
''',
)
replace_once(
    "gui/rufusarm64.py",
    '''    def open_uefi_validator(self, *_):
''',
    '''    def open_checksum_dialog(self, *_):
        if self.busy:
            return
        image_path = self.image_chooser.get_filename() or ""
        if not image_path or not os.path.isfile(image_path):
            self.progress_detail.set_text("Choose an image before calculating checksums.")
            return
        dialog = ChecksumDialog(self, helper_path(), image_path)
        dialog.run()
        dialog.closed = True
        dialog.generation += 1
        dialog.destroy()

    def open_uefi_validator(self, *_):
''',
)

replace_once(
    "scripts/build-deb.sh",
    '''install -Dm644 "${ROOT_DIR}/gui/rufusarm64_logic.py" \\
  "${PACKAGE_DIR}/usr/lib/rufusarm64/rufusarm64_logic.py"
''',
    '''install -Dm644 "${ROOT_DIR}/gui/rufusarm64_logic.py" \\
  "${PACKAGE_DIR}/usr/lib/rufusarm64/rufusarm64_logic.py"
install -Dm644 "${ROOT_DIR}/gui/rufusarm64_checksums.py" \\
  "${PACKAGE_DIR}/usr/lib/rufusarm64/rufusarm64_checksums.py"
''',
)
replace_once(
    "scripts/build-deb.sh",
    '''grep -Fq "Open Persistent USB Creator" "${GUI_TARGET}"
''',
    '''grep -Fq "Open Persistent USB Creator" "${GUI_TARGET}"
grep -Fq "Checksums…" "${GUI_TARGET}"
''',
)
replace_once(
    "scripts/test.sh",
    '''  gui/rufusarm64.py gui/rufusarm64_logic.py \\
  gui/rufusarm64_persistence.py gui/rufusarm64_persistence_logic.py
''',
    '''  gui/rufusarm64.py gui/rufusarm64_logic.py gui/rufusarm64_checksums.py \\
  gui/rufusarm64_persistence.py gui/rufusarm64_persistence_logic.py
''',
)
replace_once(
    "README.md",
    '''The single visible graphical application entry supplies the ordinary writer and the persistent-live action while retaining separate guarded helpers internally. The main window also provides a read-only **Validate UEFI Media…** dialog for mounted or extracted media; it reports fallback-loader, PE/EFI, DBX, and SBAT results, and can compare against either a trusted local SbatLevel CSV or the running shim firmware SBAT level without changing the write path.
''',
    '''The single visible graphical application entry supplies the ordinary writer and the persistent-live action while retaining separate guarded helpers internally. The selected-image **Checksums…** action calculates MD5, SHA-1, SHA-256, and SHA-512 through the unprivileged descriptor-bound helper without changing writer state; MD5 and SHA-1 are legacy comparison values only. The main window also provides a read-only **Validate UEFI Media…** dialog for mounted or extracted media; it reports fallback-loader, PE/EFI, DBX, and SBAT results, and can compare against either a trusted local SbatLevel CSV or the running shim firmware SBAT level without changing the write path.
''',
)
