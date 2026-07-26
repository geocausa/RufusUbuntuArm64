#!/usr/bin/env python3
"""Fail closed when helper exit status contradicts a passed qualification payload."""

from pathlib import Path

path = Path("gui/rufusarm64_device_qualify_dialog.py")
source = path.read_text(encoding="utf-8")
old = '''        self.report_payload = payload
        self.save_report_button.set_sensitive(True)
        summary = report_summary(payload)
        self.status.set_text(summary)
        rendered = json.dumps(payload, indent=2, sort_keys=True)
        if error:
            rendered += "\\n\\nDiagnostics:\\n" + error
        self.result.get_buffer().set_text(rendered)
        if returncode != 0 and payload.get("status") == "passed":
            self.status.set_text("The report says passed, but the helper returned an error status. Treat this result as failed.")
'''
new = '''        transport_mismatch = returncode != 0 and payload.get("status") == "passed"
        self.report_payload = None if transport_mismatch else payload
        self.save_report_button.set_sensitive(not transport_mismatch)
        summary = report_summary(payload)
        self.status.set_text(summary)
        rendered = json.dumps(payload, indent=2, sort_keys=True)
        if error:
            rendered += "\\n\\nDiagnostics:\\n" + error
        self.result.get_buffer().set_text(rendered)
        if transport_mismatch:
            self.status.set_text("The report says passed, but the helper returned an error status. Treat this result as failed.")
'''
count = source.count(old)
if count != 1:
    raise SystemExit(f"qualification transport mismatch anchor: expected one source anchor, found {count}")
path.write_text(source.replace(old, new), encoding="utf-8")
