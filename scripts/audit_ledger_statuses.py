#!/usr/bin/env python3
from pathlib import Path
import re

path = Path("docs/pre-0.11-code-audit.md")
text = path.read_text(encoding="utf-8")
baseline = "Baseline: `7b10e134b83fca3c82f5dc354f844cee4ed2c557` (`0.10.4`)\n"
summary = baseline + '''
Audit disposition at the current branch head:

- **22 fixed findings** with code, regression coverage, or permanent CI/package gates;
- **3 cleared findings** where the original concern did not represent a defect;
- **4 explicit architectural or trust deferrals** that do not weaken the current documented release contract;
- **2 planned parity items** that remain outside this corrective branch.

The branch is not considered release-ready merely because software CI passes. Persistent-live support still requires physical boot and reboot qualification for each claimed image/hardware combination.
'''
if text.count(baseline) != 1:
    raise SystemExit("audit baseline marker changed")
text = text.replace(baseline, summary, 1)
text = text.replace(
    "- **confirmed** — demonstrated directly from the current call chain or by a focused regression case;\n",
    "- **confirmed** — demonstrated directly from the current call chain or by a focused regression case;\n- **fixed** — corrected with regression coverage or a permanent validation gate;\n",
    1,
)

statuses = {
    "fixed": ("A-001", "A-002", "A-003", "A-004", "A-005", "A-006", "A-008", "A-010", "A-011", "A-012", "A-013", "A-014", "A-017", "A-022", "A-023", "A-024", "A-025", "A-026", "A-028"),
    "cleared": ("A-015", "A-020", "A-021"),
    "deferred": ("A-007", "A-009", "A-018", "A-019"),
    "planned": ("A-016", "A-027"),
}
for status, identifiers in statuses.items():
    for identifier in identifiers:
        pattern = rf"(?ms)(^### {re.escape(identifier)} .*?^\*\*Status:\*\*)[^\n]+"
        text, count = re.subn(pattern, rf"\1 {status}", text, count=1)
        if count != 1:
            raise SystemExit(f"status marker missing for {identifier}")

for identifier in statuses["fixed"]:
    match = re.search(rf"(?ms)^### {re.escape(identifier)} .*?(?=^### |^## |\Z)", text)
    if not match:
        raise SystemExit(f"section missing for {identifier}")
    block = match.group(0).replace("Required correction:", "Implemented correction:")
    text = text[:match.start()] + block + text[match.end():]


def replace_section(identifier, replacement):
    global text
    pattern = rf"(?ms)^### {re.escape(identifier)} .*?(?=^### |^## |\Z)"
    text, count = re.subn(pattern, replacement.rstrip() + "\n\n", text, count=1)
    if count != 1:
        raise SystemExit(f"section replacement missing for {identifier}")


replace_section("A-008", '''### A-008 — Windows GPT metadata receives durable exact readback verification

**Severity:** medium  
**Status:** fixed

The Windows GPT creator now validates signed-offset bounds, rejects short writes, writes and syncs backup metadata before primary metadata, and reads the protective MBR, both headers, and both entry arrays back byte-for-byte before success. Focused tests cover durability order, corrupted readback, short writes, and oversized offsets.''')
replace_section("A-012", '''### A-012 — slow GUI probes no longer block the GTK thread

**Severity:** medium performance and responsiveness  
**Status:** fixed

Image inspection, removable-device enumeration in both windows, and manual signed-catalog verification now run in worker threads. Monotonic generation tokens, selected-path snapshots, and close guards prevent stale callbacks from replacing newer selections or touching a destroyed window. A permanent AST-based test rejects regression to synchronous GTK callbacks.''')
replace_section("A-022", '''### A-022 — reused downloads are bound to the opened regular inode

**Severity:** low to medium same-user hardening  
**Status:** fixed

Existing downloads are opened with `O_NOFOLLOW`, compared with the original `Lstat` identity before hashing, checked for mutation after hashing, and compared again with the final pathname. Replacement and symlink-swap regression tests fail closed. Atomic no-replace installation remains the separate boundary for newly downloaded files.''')
replace_section("A-028", '''### A-028 — documentation and completion messages distinguish verification layers

**Severity:** medium semantics  
**Status:** fixed

User-facing documentation and completion messages distinguish source identity, copied bytes/files, filesystem consistency, bootloader/DBX structure, physical firmware boot, and persistence across reboot. A successful software write never claims universal firmware boot or Secure Boot acceptance.''')
path.write_text(text, encoding="utf-8")
