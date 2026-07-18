import json
from pathlib import Path


def replace_once(path, old, new):
    file_path = Path(path)
    source = file_path.read_text()
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one replacement target, found {count}")
    file_path.write_text(source.replace(old, new, 1))


logic_functions = r'''

UEFI_ARCHITECTURES = {
    "native",
    "386",
    "amd64",
    "arm",
    "arm64",
    "riscv64",
    "loongarch64",
}


def normalize_uefi_architecture(value):
    value = str(value or "native").strip().lower()
    aliases = {
        "": "native",
        "aarch64": "arm64",
        "x86_64": "amd64",
        "x64": "amd64",
        "i386": "386",
        "i686": "386",
        "loong64": "loongarch64",
    }
    value = aliases.get(value, value)
    if value not in UEFI_ARCHITECTURES:
        raise ValueError("Choose Native, x86, x86-64, ARM, ARM64, RISC-V 64, or LoongArch 64.")
    return value


def build_uefi_validate_command(
    helper,
    directory,
    architecture="native",
    max_files=512,
    require_fallback=True,
    dbx_file="",
    firmware=False,
):
    helper = str(helper or "").strip()
    directory = str(directory or "").strip()
    dbx_file = str(dbx_file or "").strip()
    if not helper:
        raise ValueError("The RufusArm64 validation helper is not installed correctly.")
    if not directory:
        raise ValueError("Choose a mounted or extracted UEFI media folder.")
    try:
        max_files = int(max_files)
    except (TypeError, ValueError) as exc:
        raise ValueError("The EFI file limit must be a whole number.") from exc
    if max_files <= 0 or max_files > 4096:
        raise ValueError("The EFI file limit must be between 1 and 4096.")
    if dbx_file and firmware:
        raise ValueError("Choose either a local DBX file or the running firmware DBX, not both.")
    command = [
        helper,
        "uefi",
        "validate",
        "--directory",
        directory,
        "--arch",
        normalize_uefi_architecture(architecture),
        "--max-files",
        str(max_files),
        f"--require-fallback={'true' if require_fallback else 'false'}",
    ]
    if dbx_file:
        command.extend(["--dbx", dbx_file])
    elif firmware:
        command.append("--firmware")
    command.append("--json")
    return command


def normalize_uefi_validation(payload):
    if not isinstance(payload, dict):
        raise ValueError("The UEFI validator returned an invalid response.")
    root = str(payload.get("root") or "").strip()
    architecture = str(payload.get("architecture") or "").strip()
    fallback_path = str(payload.get("fallback_path") or "").strip()
    files = payload.get("files")
    warnings = payload.get("warnings") or []
    errors = payload.get("errors") or []
    if not root or not architecture or not fallback_path or not isinstance(files, list):
        raise ValueError("The UEFI validator response is incomplete.")
    if not isinstance(warnings, list) or not isinstance(errors, list):
        raise ValueError("The UEFI validator returned invalid warning or error lists.")
    normalized_files = []
    for item in files:
        if not isinstance(item, dict):
            raise ValueError("The UEFI validator returned an invalid file result.")
        path = str(item.get("path") or "").strip()
        if not path:
            raise ValueError("The UEFI validator returned a file result without a path.")
        file_warnings = item.get("warnings") or []
        if not isinstance(file_warnings, list):
            raise ValueError("The UEFI validator returned invalid per-file warnings.")
        try:
            sbat_count = len(item.get("sbat") or [])
            certificates = int(item.get("embedded_certificates") or 0)
        except (TypeError, ValueError) as exc:
            raise ValueError("The UEFI validator returned invalid per-file metadata.") from exc
        normalized_files.append({
            "path": path,
            "machine_name": str(item.get("machine_name") or "unknown"),
            "subsystem_name": str(item.get("subsystem_name") or "unknown subsystem"),
            "fallback": bool(item.get("fallback")),
            "direct_hash_revoked": bool(item.get("direct_hash_revoked")),
            "x509_certificate_revoked": bool(item.get("x509_certificate_revoked")),
            "embedded_certificates": max(0, certificates),
            "sbat_records": sbat_count,
            "warnings": [str(value) for value in file_warnings],
            "error": str(item.get("error") or "").strip(),
        })
    return {
        "root": root,
        "architecture": architecture,
        "fallback_path": fallback_path,
        "fallback_found": bool(payload.get("fallback_found")),
        "dbx_checked": bool(payload.get("dbx_checked")),
        "valid": bool(payload.get("valid")),
        "revoked": bool(payload.get("revoked")),
        "files": normalized_files,
        "warnings": [str(value) for value in warnings],
        "errors": [str(value) for value in errors],
        "raw": payload,
    }


def uefi_validation_summary(payload):
    result = normalize_uefi_validation(payload)
    state = "Validation passed" if result["valid"] else "Validation found problems"
    lines = [
        f"{state}: {result['architecture']} UEFI media",
        f"Media root: {result['root']}",
        f"Fallback loader: {result['fallback_path']} ({'found' if result['fallback_found'] else 'missing'})",
        f"DBX revocations checked: {'yes' if result['dbx_checked'] else 'no'}",
        f"EFI executables checked: {len(result['files'])}",
    ]
    for item in result["files"]:
        status = "OK"
        if item["direct_hash_revoked"] or item["x509_certificate_revoked"]:
            status = "REVOKED"
        elif item["error"]:
            status = "ERROR"
        elif item["warnings"]:
            status = "WARNING"
        fallback = " fallback" if item["fallback"] else ""
        lines.append(
            f"{status}: {item['path']}{fallback} — {item['machine_name']}; "
            f"{item['subsystem_name']}; SBAT records {item['sbat_records']}"
        )
        for warning in item["warnings"]:
            lines.append(f"  Warning: {warning}")
        if item["error"]:
            lines.append(f"  Error: {item['error']}")
    for warning in result["warnings"]:
        lines.append(f"Warning: {warning}")
    for error in result["errors"]:
        lines.append(f"Error: {error}")
    lines.append("This read-only check does not prove that the intended computer will boot the media.")
    return "\n".join(lines)
'''

replace_once(
    "gui/rufusarm64_logic.py",
    "\ndef build_writer_command(\n",
    logic_functions + "\ndef build_writer_command(\n",
)

replace_once(
    "gui/test_logic.py",
    '''    build_persistence_plan_command,
    build_writer_command,
''',
    '''    build_persistence_plan_command,
    build_uefi_validate_command,
    build_writer_command,
''',
)
replace_once(
    "gui/test_logic.py",
    '''    normalize_target_system,
    normalize_volume_label,
''',
    '''    normalize_target_system,
    normalize_uefi_validation,
    normalize_volume_label,
''',
)
replace_once(
    "gui/test_logic.py",
    '''    success_message,
    normalize_windows_locale,
''',
    '''    success_message,
    uefi_validation_summary,
    normalize_windows_locale,
''',
)

logic_tests = r'''

    def test_uefi_validation_command_is_read_only(self):
        command = build_uefi_validate_command(
            "/helper", "/mnt/usb", "aarch64", 1024, True, "/cache/dbx.bin", False
        )
        self.assertEqual(command[:3], ["/helper", "uefi", "validate"])
        self.assertEqual(command[command.index("--arch") + 1], "arm64")
        self.assertEqual(command[command.index("--max-files") + 1], "1024")
        self.assertIn("--require-fallback=true", command)
        self.assertIn("--dbx", command)
        self.assertEqual(command[-1], "--json")
        self.assertNotIn("pkexec", command)
        self.assertNotIn("write", command)
        with self.assertRaises(ValueError):
            build_uefi_validate_command("/helper", "/mnt/usb", dbx_file="dbx.bin", firmware=True)
        with self.assertRaises(ValueError):
            build_uefi_validate_command("/helper", "/mnt/usb", max_files=4097)

    def test_uefi_validation_normalization_and_summary(self):
        payload = {
            "root": "/mnt/usb",
            "architecture": "arm64",
            "fallback_path": "EFI/BOOT/BOOTAA64.EFI",
            "fallback_found": True,
            "dbx_checked": True,
            "valid": True,
            "revoked": False,
            "files": [{
                "path": "EFI/BOOT/BOOTAA64.EFI",
                "machine_name": "ARM64",
                "subsystem_name": "EFI application",
                "fallback": True,
                "embedded_certificates": 2,
                "sbat": [{"component": "shim"}],
            }],
        }
        normalized = normalize_uefi_validation(payload)
        self.assertTrue(normalized["valid"])
        self.assertEqual(normalized["files"][0]["sbat_records"], 1)
        summary = uefi_validation_summary(payload)
        self.assertIn("Validation passed", summary)
        self.assertIn("BOOTAA64.EFI", summary)
        self.assertIn("does not prove", summary)
        with self.assertRaises(ValueError):
            normalize_uefi_validation({"root": "/mnt/usb", "files": []})
'''
replace_once(
    "gui/test_logic.py",
    "\n\nif __name__ == \"__main__\":\n",
    logic_tests + "\n\nif __name__ == \"__main__\":\n",
)

replace_once(
    "gui/rufusarm64.py",
    '''    build_persistence_analyze_command,
    build_writer_command,
''',
    '''    build_persistence_analyze_command,
    build_uefi_validate_command,
    build_writer_command,
''',
)
replace_once(
    "gui/rufusarm64.py",
    '''    normalize_target_system,
    normalize_volume_label,
''',
    '''    normalize_target_system,
    normalize_uefi_validation,
    normalize_volume_label,
''',
)
replace_once(
    "gui/rufusarm64.py",
    '''    success_message,
    normalize_windows_locale,
''',
    '''    success_message,
    uefi_validation_summary,
    normalize_windows_locale,
''',
)

dialog_class = r'''

class UEFIValidationDialog(Gtk.Dialog):
    """Run the descriptor-safe UEFI validator without entering a write path."""

    def __init__(self, parent, settings):
        super().__init__(title="Validate UEFI media", transient_for=parent, modal=True)
        self.parent_window = parent
        self.settings = settings
        self.running = False
        self.closed = False
        self.generation = 0
        self.set_default_size(760, 620)
        self.add_button("Close", Gtk.ResponseType.CLOSE)
        self.close_button = self.get_widget_for_response(Gtk.ResponseType.CLOSE)
        self.connect("delete-event", self.on_delete_event)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_border_width(18)
        self.get_content_area().pack_start(box, True, True, 0)

        intro = Gtk.Label(label=(
            "Check a mounted or extracted UEFI media folder. Validation is read-only and unprivileged; "
            "it does not mount images, open a USB device, or change whether Create USB is available."
        ))
        intro.set_xalign(0)
        intro.set_line_wrap(True)
        box.pack_start(intro, False, False, 0)

        grid = Gtk.Grid(column_spacing=12, row_spacing=10)
        box.pack_start(grid, False, False, 0)
        self._attach_label(grid, "Media folder", 0)
        self.directory = Gtk.FileChooserButton(
            title="Choose mounted or extracted UEFI media",
            action=Gtk.FileChooserAction.SELECT_FOLDER,
        )
        saved_directory = settings.get("uefi_validation_directory", "")
        if saved_directory and os.path.isdir(saved_directory):
            self.directory.set_filename(saved_directory)
        grid.attach(self.directory, 1, 0, 1, 1)

        self._attach_label(grid, "Architecture", 1)
        self.architecture = Gtk.ComboBoxText()
        for identifier, label in (
            ("native", "Native architecture"),
            ("arm64", "ARM64"),
            ("amd64", "x86-64"),
            ("386", "x86"),
            ("arm", "ARM"),
            ("riscv64", "RISC-V 64"),
            ("loongarch64", "LoongArch 64"),
        ):
            self.architecture.append(identifier, label)
        saved_arch = settings.get("uefi_validation_architecture", "native")
        self.architecture.set_active_id(saved_arch if saved_arch else "native")
        grid.attach(self.architecture, 1, 1, 1, 1)

        self.require_fallback = Gtk.CheckButton(label="Require the removable-media fallback loader")
        self.require_fallback.set_active(bool(settings.get("uefi_validation_require_fallback", True)))
        grid.attach(self.require_fallback, 1, 2, 1, 1)

        self._attach_label(grid, "Local DBX", 3)
        self.dbx = Gtk.FileChooserButton(
            title="Choose an optional DBXUpdate.bin file",
            action=Gtk.FileChooserAction.OPEN,
        )
        dbx_filter = Gtk.FileFilter()
        dbx_filter.set_name("UEFI DBX files")
        dbx_filter.add_pattern("*.bin")
        self.dbx.add_filter(dbx_filter)
        saved_dbx = settings.get("uefi_validation_dbx", "")
        if saved_dbx and os.path.isfile(saved_dbx):
            self.dbx.set_filename(saved_dbx)
        grid.attach(self.dbx, 1, 3, 1, 1)

        self.firmware = Gtk.CheckButton(label="Use the running firmware DBX instead")
        self.firmware.set_active(bool(settings.get("uefi_validation_firmware", False)))
        self.firmware.connect("toggled", self.firmware_toggled)
        grid.attach(self.firmware, 1, 4, 1, 1)
        self.firmware_toggled()

        action_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.validate_button = Gtk.Button(label="Validate")
        self.validate_button.get_style_context().add_class("suggested-action")
        self.validate_button.connect("clicked", self.start_validation)
        action_row.pack_start(self.validate_button, False, False, 0)
        self.spinner = Gtk.Spinner()
        action_row.pack_start(self.spinner, False, False, 0)
        self.status = Gtk.Label(label="Choose a media folder, then validate.")
        self.status.set_xalign(0)
        self.status.set_line_wrap(True)
        action_row.pack_start(self.status, True, True, 0)
        box.pack_start(action_row, False, False, 0)

        result_scroll = Gtk.ScrolledWindow()
        result_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        result_scroll.set_hexpand(True)
        result_scroll.set_vexpand(True)
        self.result_view = Gtk.TextView(
            editable=False,
            cursor_visible=False,
            monospace=True,
            wrap_mode=Gtk.WrapMode.WORD_CHAR,
        )
        self.result_view.get_buffer().set_text(
            "No validation has been run.\n\nThis check does not prove that the intended computer will boot the media."
        )
        result_scroll.add(self.result_view)
        box.pack_start(result_scroll, True, True, 0)
        self.show_all()

    @staticmethod
    def _attach_label(grid, text, row):
        label = Gtk.Label(label=text)
        label.set_xalign(0)
        label.set_valign(Gtk.Align.CENTER)
        grid.attach(label, 0, row, 1, 1)

    def firmware_toggled(self, *_):
        self.dbx.set_sensitive(not self.running and not self.firmware.get_active())

    def on_delete_event(self, *_):
        if self.running:
            self.status.set_text("Validation is still running. Wait for it to finish before closing this dialog.")
            return True
        self.closed = True
        self.generation += 1
        return False

    def set_running(self, running):
        self.running = bool(running)
        self.validate_button.set_sensitive(not self.running)
        self.close_button.set_sensitive(not self.running)
        self.directory.set_sensitive(not self.running)
        self.architecture.set_sensitive(not self.running)
        self.require_fallback.set_sensitive(not self.running)
        self.firmware.set_sensitive(not self.running)
        self.firmware_toggled()
        if self.running:
            self.spinner.start()
        else:
            self.spinner.stop()

    def start_validation(self, *_):
        if self.running:
            return
        try:
            command = build_uefi_validate_command(
                helper_path(),
                self.directory.get_filename(),
                self.architecture.get_active_id() or "native",
                512,
                self.require_fallback.get_active(),
                self.dbx.get_filename() or "",
                self.firmware.get_active(),
            )
        except ValueError as exc:
            self.status.set_text(str(exc))
            return
        self.settings["uefi_validation_directory"] = self.directory.get_filename() or ""
        self.settings["uefi_validation_architecture"] = self.architecture.get_active_id() or "native"
        self.settings["uefi_validation_require_fallback"] = self.require_fallback.get_active()
        self.settings["uefi_validation_dbx"] = self.dbx.get_filename() or ""
        self.settings["uefi_validation_firmware"] = self.firmware.get_active()
        self.generation += 1
        generation = self.generation
        self.set_running(True)
        self.status.set_text("Validating EFI executables, fallback loader, SBAT metadata, and optional DBX revocations…")
        self.result_view.get_buffer().set_text("Validation in progress…")
        threading.Thread(target=self._run_validation, args=(command, generation), daemon=True).start()

    def _run_validation(self, command, generation):
        payload = None
        failure = ""
        try:
            completed = subprocess.run(
                command,
                check=False,
                text=True,
                capture_output=True,
                timeout=120,
            )
            if completed.stdout.strip():
                payload = json.loads(completed.stdout)
                normalize_uefi_validation(payload)
            if payload is None:
                failure = completed.stderr.strip() or "The UEFI validator returned no result."
        except subprocess.TimeoutExpired:
            failure = "UEFI validation exceeded the two-minute safety limit."
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            failure = str(exc)
        GLib.idle_add(self._finish_validation, generation, payload, failure)

    def _finish_validation(self, generation, payload, failure):
        if self.closed or generation != self.generation:
            return False
        self.set_running(False)
        if failure:
            self.status.set_text("Validation could not be completed.")
            self.result_view.get_buffer().set_text(failure)
            self.parent_window.append_log(f"UEFI validation failed to run: {failure}")
            return False
        normalized = normalize_uefi_validation(payload)
        summary = uefi_validation_summary(payload)
        self.result_view.get_buffer().set_text(summary)
        self.status.set_text("Validation passed." if normalized["valid"] else "Validation found problems.")
        self.parent_window.append_log(
            "UEFI media validation result:\n" + json.dumps(payload, indent=2, sort_keys=True)
        )
        return False
'''
replace_once(
    "gui/rufusarm64.py",
    "\n\nclass RufusWindow(Gtk.ApplicationWindow):\n",
    dialog_class + "\n\nclass RufusWindow(Gtk.ApplicationWindow):\n",
)

replace_once(
    "gui/rufusarm64.py",
    '''        about_button.connect("clicked", self.show_about)
        header.pack_end(about_button)
''',
    '''        about_button.connect("clicked", self.show_about)
        header.pack_end(about_button)
        self.uefi_validation_button = Gtk.Button(label="Validate UEFI Media…")
        self.uefi_validation_button.set_tooltip_text(
            "Run a read-only validation of a mounted or extracted UEFI media folder"
        )
        self.uefi_validation_button.connect("clicked", self.open_uefi_validator)
        header.pack_start(self.uefi_validation_button)
''',
)
replace_once(
    "gui/rufusarm64.py",
    '''        for widget in (self.image_chooser, self.download_button, self.target_combo, self.verify, self.open_persistence_button):
            widget.set_sensitive(not busy)
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
''',
)

open_method = r'''

    def open_uefi_validator(self, *_):
        if self.busy:
            return
        dialog = UEFIValidationDialog(self, self.settings)
        dialog.run()
        dialog.closed = True
        dialog.generation += 1
        dialog.destroy()
        self.save_settings()
'''
replace_once(
    "gui/rufusarm64.py",
    "\n    def image_changed(self, *_):\n",
    open_method + "\n    def image_changed(self, *_):\n",
)

replace_once(
    "README.md",
    "The single visible graphical application entry supplies the ordinary writer and the persistent-live action while retaining separate guarded helpers internally.\n",
    "The single visible graphical application entry supplies the ordinary writer and the persistent-live action while retaining separate guarded helpers internally. The main window also provides a read-only **Validate UEFI Media…** dialog for mounted or extracted media; it reports fallback-loader, PE/EFI, SBAT, and optional DBX results without changing the write path.\n",
)

parity_path = Path("docs/upstream-rufus-parity.json")
parity = json.loads(parity_path.read_text())
for feature in parity["features"]:
    if feature["id"] == "uefi-runtime-validation":
        feature["notes"] = (
            "The 0.11 development line exposes descriptor-rooted CLI and GTK validation of fallback loaders, "
            "PE architecture and EFI subsystem fields, bounded SBAT metadata, and optional DBX hash/certificate "
            "revocations. Boot-chain reference resolution and trusted SBAT-level comparison remain planned."
        )
        break
else:
    raise SystemExit("UEFI runtime validation parity entry was not found")
parity_path.write_text(json.dumps(parity, indent=2) + "\n")
