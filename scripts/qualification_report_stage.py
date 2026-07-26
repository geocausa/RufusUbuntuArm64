#!/usr/bin/env python3
"""Apply the exact GTK and package integration for qualification report export."""

from pathlib import Path


def replace_once(path, old, new, label):
    source = path.read_text(encoding="utf-8")
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one source anchor, found {count}")
    path.write_text(source.replace(old, new), encoding="utf-8")


dialog = Path("gui/rufusarm64_device_qualify_dialog.py")
replace_once(
    dialog,
    ''')

DEVICE_BACKUP = "/usr/bin/rufusarm64-device-backup"
''',
    ''')
from rufusarm64_qualification_report import save_new_qualification_report

DEVICE_BACKUP = "/usr/bin/rufusarm64-device-backup"
''',
    "qualification report import",
)
replace_once(
    dialog,
    '''        self.process = None
        self.plan = None
        self.set_default_size(700, 560)
''',
    '''        self.process = None
        self.plan = None
        self.report_payload = None
        self.set_default_size(700, 560)
''',
    "qualification report state",
)
replace_once(
    dialog,
    '''        self.cancel_button.connect("clicked", self.cancel_run)
        actions.pack_start(self.cancel_button, False, False, 0)
        self.spinner = Gtk.Spinner()
''',
    '''        self.cancel_button.connect("clicked", self.cancel_run)
        actions.pack_start(self.cancel_button, False, False, 0)
        self.save_report_button = Gtk.Button(label="Save report…")
        self.save_report_button.set_sensitive(False)
        self.save_report_button.connect("clicked", self.save_report)
        actions.pack_start(self.save_report_button, False, False, 0)
        self.spinner = Gtk.Spinner()
''',
    "qualification report button",
)
replace_once(
    dialog,
    '''        self.run_button.set_sensitive(False if self.running else bool(self.plan) and self.confirmation.get_text().strip() == f"ERASE {self.device}")
        self.cancel_button.set_sensitive(self.running)
        self.close_button.set_sensitive(not self.running)
''',
    '''        self.run_button.set_sensitive(False if self.running else bool(self.plan) and self.confirmation.get_text().strip() == f"ERASE {self.device}")
        self.cancel_button.set_sensitive(self.running)
        self.save_report_button.set_sensitive(not self.running and self.report_payload is not None)
        self.close_button.set_sensitive(not self.running)
''',
    "qualification report running state",
)
replace_once(
    dialog,
    '''        except ValueError as exc:
            self.status.set_text(str(exc))
            return
        self.set_running(True)
''',
    '''        except ValueError as exc:
            self.status.set_text(str(exc))
            return
        self.report_payload = None
        self.save_report_button.set_sensitive(False)
        self.set_running(True)
''',
    "qualification report reset",
)
replace_once(
    dialog,
    '''        if payload is None:
            self.status.set_text("USB qualification could not complete.")
            self.result.get_buffer().set_text(error)
            return False
        summary = report_summary(payload)
''',
    '''        if payload is None:
            self.report_payload = None
            self.save_report_button.set_sensitive(False)
            self.status.set_text("USB qualification could not complete.")
            self.result.get_buffer().set_text(error)
            return False
        self.report_payload = payload
        self.save_report_button.set_sensitive(True)
        summary = report_summary(payload)
''',
    "qualification report result binding",
)
replace_once(
    dialog,
    '''    def cancel_run(self, *_):
        process = self.process
''',
    '''    def save_report(self, *_):
        if self.running or self.report_payload is None:
            return
        chooser = Gtk.FileChooserDialog(
            title="Save a new USB qualification report",
            transient_for=self,
            action=Gtk.FileChooserAction.SAVE,
        )
        chooser.add_buttons("Cancel", Gtk.ResponseType.CANCEL, "Save", Gtk.ResponseType.OK)
        chooser.set_current_name(f"rufusarm64-{os.path.basename(self.device)}-qualification.json")
        report_filter = Gtk.FileFilter()
        report_filter.set_name("JSON qualification reports")
        report_filter.add_pattern("*.json")
        chooser.add_filter(report_filter)
        response = chooser.run()
        filename = chooser.get_filename() if response == Gtk.ResponseType.OK else ""
        chooser.destroy()
        if not filename:
            return
        filename = os.path.abspath(filename)
        if os.path.lexists(filename):
            self.status.set_text("Choose a new report path; existing files and symbolic links are never replaced.")
            return
        try:
            save_new_qualification_report(
                filename,
                self.device,
                self.identity,
                self.report_payload,
            )
        except (OSError, ValueError) as exc:
            self.status.set_text(f"Could not save the qualification report: {exc}")
            return
        self.status.set_text(f"Qualification report saved to {filename}.")

    def cancel_run(self, *_):
        process = self.process
''',
    "qualification report save action",
)

package = Path("scripts/build-deb.sh")
replace_once(
    package,
    '''install -Dm644 "${ROOT_DIR}/gui/rufusarm64_device_qualify.py" \\
  "${PACKAGE_DIR}/usr/lib/rufusarm64/rufusarm64_device_qualify.py"
install -Dm644 "${ROOT_DIR}/gui/rufusarm64_device_qualify_dialog.py" \\
''',
    '''install -Dm644 "${ROOT_DIR}/gui/rufusarm64_device_qualify.py" \\
  "${PACKAGE_DIR}/usr/lib/rufusarm64/rufusarm64_device_qualify.py"
install -Dm644 "${ROOT_DIR}/gui/rufusarm64_qualification_report.py" \\
  "${PACKAGE_DIR}/usr/lib/rufusarm64/rufusarm64_qualification_report.py"
install -Dm644 "${ROOT_DIR}/gui/rufusarm64_device_qualify_dialog.py" \\
''',
    "qualification report package install",
)
