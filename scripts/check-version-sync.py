#!/usr/bin/env python3
"""Require every canonical release surface to agree with VERSION."""
from pathlib import Path
import re
import xml.etree.ElementTree as ET

root = Path(__file__).resolve().parent.parent
version = (root / "VERSION").read_text(encoding="utf-8").strip()
if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
    raise SystemExit(f"VERSION is not canonical semantic version text: {version!r}")

changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
match = re.search(r"^## ([0-9]+\.[0-9]+\.[0-9]+) — ([0-9]{4}-[0-9]{2}-[0-9]{2})$", changelog, re.MULTILINE)
if match is None or match.group(1) != version:
    raise SystemExit("top changelog release does not match VERSION")
release_date = match.group(2)

meta_path = root / "packaging/io.github.geocausa.RufusArm64.metainfo.xml"
component = ET.parse(meta_path).getroot()
releases = component.find("releases")
first = releases.find("release") if releases is not None else None
if first is None or first.get("version") != version or first.get("date") != release_date:
    raise SystemExit("first AppStream release does not match VERSION and changelog date")

for name in ("rufusarm64.1", "rufusarm64-cli.1", "rufusarm64-persistence.1"):
    first_line = (root / "docs" / name).read_text(encoding="utf-8").splitlines()[0]
    if f'"RufusArm64 {version}"' not in first_line:
        raise SystemExit(f"{name} does not match VERSION")

readme = (root / "README.md").read_text(encoding="utf-8")
for marker in (
    f"rufusarm64_{version}_arm64.deb",
    f"Version {version}",
    "Validate media at UEFI boot",
    "The current runtime loader is **unsigned**" if False else "The canonical loader is built twice",
):
    if marker not in readme:
        raise SystemExit(f"README is missing release marker: {marker}")

roadmap = (root / "ROADMAP.md").read_text(encoding="utf-8")
if "## 0.11 — UEFI analysis and runtime media integrity (completed)" not in roadmap:
    raise SystemExit("ROADMAP does not mark the 0.11 tranche complete")

notes = root / "docs" / f"release-{version}.md"
if not notes.is_file():
    raise SystemExit(f"missing release notes: {notes.relative_to(root)}")
notes_text = notes.read_text(encoding="utf-8")
required_notes = (
    f"# RufusArm64 {version}",
    "limited to the guarded ARM64 persistent writable-copy workflow",
    "unsigned",
    "Secure Boot compatibility is not established",
    "intentionally corrupted GPT/FAT32 media",
    "original-loader chainload",
    "Physical Surface Pro 11",
)
for marker in required_notes:
    if marker not in notes_text:
        raise SystemExit(f"release notes are missing required boundary: {marker}")

release_workflow = (root / ".github/workflows/release.yml").read_text(encoding="utf-8")
if "tag_version=\"${GITHUB_REF_NAME#v}\"" not in release_workflow:
    raise SystemExit("release workflow no longer verifies the tag against VERSION")
if "body_path: docs/release-${{ steps.version.outputs.version }}.md" not in release_workflow:
    raise SystemExit("release workflow body path no longer follows VERSION")

print(f"Release metadata is synchronized for {version} ({release_date}).")
