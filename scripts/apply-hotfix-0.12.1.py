#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OLD = "0.12.0"
NEW = "0.12.1"
DATE = "2026-07-20"


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def write(path, text):
    (ROOT / path).write_text(text, encoding="utf-8")


def replace_once(path, old, new):
    text = read(path)
    if text.count(old) != 1:
        raise SystemExit(f"{path}: expected exactly one marker {old!r}")
    write(path, text.replace(old, new, 1))


write("VERSION", NEW + "\n")

changelog = read("CHANGELOG.md")
marker = "# Changelog\n\n"
entry = f"""## {NEW} — {DATE}\n\n- Fixed the packaged graphical launcher so GTK 3 is selected before any integrated dialog imports `Gtk`, preventing silent startup failure on systems that also provide GTK 4 introspection.\n- Added a regression that executes the exact isolated launcher payload and requires the GTK 3 version pin to occur before the integrated dialog import.\n- Kept the Stage 1 feature set unchanged; this is a focused field-reported startup patch over 0.12.0.\n\n"""
if marker not in changelog or f"## {NEW} —" in changelog:
    raise SystemExit("CHANGELOG.md: release insertion marker is missing or duplicate")
write("CHANGELOG.md", changelog.replace(marker, marker + entry, 1))

readme = read("README.md")
if OLD not in readme:
    raise SystemExit("README.md: current release marker is missing")
write("README.md", readme.replace(OLD, NEW))

for name in (
    "rufusarm64.1",
    "rufusarm64-cli.1",
    "rufusarm64-persistence.1",
    "rufusarm64-device-qualify.1",
    "rufusarm64-device-backup.1",
):
    replace_once(f"docs/{name}", f"RufusArm64 {OLD}", f"RufusArm64 {NEW}")

meta = read("packaging/io.github.geocausa.RufusArm64.metainfo.xml")
meta_marker = "  <releases>\n"
meta_entry = f"""    <release version=\"{NEW}\" date=\"{DATE}\">\n      <description>\n        <p>Fixes packaged GTK startup on desktops that provide both GTK 3 and GTK 4 introspection by pinning GTK 3 before integrated dialog imports.</p>\n      </description>\n    </release>\n"""
if meta_marker not in meta or f'release version="{NEW}"' in meta:
    raise SystemExit("AppStream release insertion marker is missing or duplicate")
write("packaging/io.github.geocausa.RufusArm64.metainfo.xml", meta.replace(meta_marker, meta_marker + meta_entry, 1))

notes = f"""# RufusArm64 {NEW}\n\nRufusArm64 {NEW} is a focused Stage 1 patch release for a field-reported graphical startup failure in 0.12.0.\n\n## Highlights\n\n- Pins GTK 3 in the installed isolated launcher before importing the integrated qualification and drive-image dialogs.\n- Prevents systems that also expose GTK 4 introspection from selecting the wrong namespace before the main application requests GTK 3.\n- Adds an executable launcher-order regression for the exact packaged Python payload.\n- Retains all 0.12.0 writer, persistence, qualification, UEFI-analysis, and drive-image backup behavior unchanged.\n\n## Safety and support boundaries\n\nThis patch changes only graphical startup ordering. It does not alter privileged commands, source or target identity checks, destructive confirmation, filesystem operations, image-writing behavior, or drive-image publication.\n\nThe optional package-owned ARM64 UEFI runtime-integrity loader remains unsigned. Secure Boot compatibility is not established. Physical hardware testing remains separate from software, loop-device, native ARM64 runner, reproducibility, and QEMU evidence.\n\n## Install and rollback\n\nInstall or upgrade on Ubuntu ARM64 with:\n\n```bash\nsudo apt install ./rufusarm64_{NEW}_arm64.deb\n```\n\nVerify the package first with the published SHA-256 sidecar. Remove it with `sudo apt remove rufusarm64`. Rollback by reinstalling a retained 0.12.0 package; user-created USB media and drive images are not removed by package upgrade, rollback, or removal.\n\n## Supply-chain and release assets\n\nThe canonical `v{NEW}` workflow publishes `rufusarm64_{NEW}_arm64.deb`, its checksum sidecar, deterministic project source, pinned WIM corresponding source, and deterministic `uefi-md5sum` corresponding source from the exact synchronized release commit.\n"""
write(f"docs/release-{NEW}.md", notes)

print(f"Prepared RufusArm64 {NEW} release metadata.")
