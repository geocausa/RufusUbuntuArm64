#!/usr/bin/env python3
from pathlib import Path

VERSION = "0.11.0"
DATE_ISO = "2026-07-18"
DATE_LONG = "18 July 2026"


def read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def write(path: str, text: str) -> None:
    Path(path).write_text(text, encoding="utf-8")


def replace_once(path: str, old: str, new: str) -> None:
    text = read(path)
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one occurrence, found {count}: {old!r}")
    write(path, text.replace(old, new, 1))


write("VERSION", VERSION + "\n")

changelog_entry = """## 0.11.0 — 2026-07-18

- Added a descriptor-rooted, bounded UEFI media analyzer for fallback-loader architecture, PE/COFF structure, DBX revocations, SBAT metadata, trusted local or firmware SBAT levels, and structured CLI/GTK reporting.
- Added Rufus-compatible `md5sum.txt` generation and verification plus an opt-in boot-time ARM64 media-integrity option for the guarded Ubuntu/Debian persistent writable-copy path.
- Reproducibly built the package-private `uefi-md5sum` v1.2 ARM64 loader from exact upstream and EDK2 commits, retained corresponding source and provenance, and kept the loader explicitly unsigned.
- Added transactional fallback-loader wrapping and rollback, exact post-install manifest verification, qualification-record hashes, guarded GUI disclosure, and refusal in raw-image, Windows, NTFS, compressed-stream, and virtual-disk writers.
- Qualified unchanged and intentionally corrupted GPT/FAT32 media under pinned AArch64 QEMU firmware, including original-loader chainload and complete serial, image, firmware, provenance, and checksum evidence.
- Kept Secure Boot compatibility and universal hardware compatibility explicitly unclaimed; physical Surface Pro 11 boot and persistence start/reboot/verify evidence remains a separate per-hardware qualification gate.
- Hardened tagged releases so the ARM64 package, deterministic project source, pinned WIM source, and deterministic `uefi-md5sum` corresponding source are produced from one synchronized version contract.

"""
replace_once("CHANGELOG.md", "# Changelog\n\n", "# Changelog\n\n" + changelog_entry)

replace_once(
    "packaging/io.github.geocausa.RufusArm64.metainfo.xml",
    "    <p>It writes raw and ISOHybrid media, prepares compressed and common virtual-disk inputs, creates Windows installation media, verifies signed acquisition catalogs, and provides a guarded graphical persistent-live USB workflow for supported Ubuntu casper and Debian live-boot media.</p>",
    "    <p>It writes raw and ISOHybrid media, prepares compressed and common virtual-disk inputs, creates Windows installation media, verifies signed acquisition catalogs, analyzes UEFI and Secure Boot metadata, and provides guarded persistent-live creation with optional ARM64 boot-time media-integrity validation.</p>",
)
release_xml = """    <release version="0.11.0" date="2026-07-18">
      <description>
        <p>Adds descriptor-safe UEFI, DBX, and SBAT analysis plus an opt-in, reproducibly built ARM64 boot-time media-integrity validator for supported persistent Ubuntu/Debian writable-copy media, qualified under pinned AArch64 QEMU firmware and explicitly unsigned.</p>
      </description>
    </release>
"""
replace_once(
    "packaging/io.github.geocausa.RufusArm64.metainfo.xml",
    "  <releases>\n",
    "  <releases>\n" + release_xml,
)

for path, old in (
    ("docs/rufusarm64-cli.1", '.TH RUFUSARM64-CLI 1 "17 July 2026" "RufusArm64 0.10.6" "User Commands"'),
    ("docs/rufusarm64-persistence.1", '.TH RUFUSARM64-PERSISTENCE 1 "July 2026" "RufusArm64 0.10.5" "User Commands"'),
    ("docs/rufusarm64.1", '.TH RUFUSARM64 1 "July 2026" "RufusArm64 0.10.5" "User Commands"'),
):
    name = old.split()[1]
    replace_once(path, old, f'.TH {name} 1 "{DATE_LONG}" "RufusArm64 {VERSION}" "User Commands"')

replace_once("README.md", "sudo apt install ./rufusarm64_0.10.6_arm64.deb", "sudo apt install ./rufusarm64_0.11.0_arm64.deb")
replace_once("README.md", "Version 0.10.6 retains", "Version 0.11.0 retains")
replace_once("README.md", "dist/rufusarm64_0.10.6_arm64.deb", "dist/rufusarm64_0.11.0_arm64.deb")
replace_once(
    "README.md",
    "- A guarded graphical workflow for persistent Ubuntu casper and Debian live-boot USB media, exposed through the single RufusArm64 application entry.\n",
    "- A guarded graphical workflow for persistent Ubuntu casper and Debian live-boot USB media, exposed through the single RufusArm64 application entry.\n- Descriptor-safe UEFI, DBX, and SBAT analysis plus optional ARM64 boot-time media-integrity validation for the supported persistent writable-copy path.\n",
)
replace_once(
    "README.md",
    "1. Open the **Create Persistent Live USB** action from the RufusArm64 application entry, or run `rufusarm64 --persistence`.\n2. Select the Linux ISO and exact removable USB.\n3. Choose a persistence size; zero uses the suitable remaining space.\n4. Run **Analyze selected image**. This identity-bound step mounts only the ISO read-only and never opens the USB device.\n5. Review the detected family, filesystem label, boot parameter, fresh GPT layout, required FAT32 capacity, and boot files to be changed.\n6. Confirm **Erase and create persistent USB**.\n7. Keep the drive connected while data are copied, flushed, and checked. Slow flash drives may spend several minutes committing cached writes.\n",
    "1. Open the **Create Persistent Live USB** action from the RufusArm64 application entry, or run `rufusarm64 --persistence`.\n2. Select the Linux ISO and exact removable USB.\n3. Choose a persistence size; zero uses the suitable remaining space.\n4. Optionally select **Validate media at UEFI boot**. The current package-owned ARM64 loader is unsigned, so Secure Boot compatibility is not established.\n5. Run **Analyze selected image**. This identity-bound step mounts only the ISO read-only and never opens the USB device; changing the option afterward requires analysis again.\n6. Review the detected family, filesystem label, boot parameter, fresh GPT layout, required FAT32 capacity, and boot files to be changed.\n7. Confirm **Erase and create persistent USB**.\n8. Keep the drive connected while data are copied, flushed, and checked. Slow flash drives may spend several minutes committing cached writes.\n",
)
replace_once(
    "README.md",
    "Compressed images, virtual disks, MBR/BIOS persistence, encrypted persistence, oversized FAT32 files, unknown boot layouts, bootloader replacement, kernel/initramfs replacement, and major distribution upgrades remain outside this persistence contract.",
    "Compressed images, virtual disks, MBR/BIOS persistence, encrypted persistence, oversized FAT32 files, unknown boot layouts, arbitrary bootloader replacement, kernel/initramfs replacement, and major distribution upgrades remain outside this persistence contract. The only fallback-loader wrapping is the explicit, transactional ARM64 runtime-integrity option described below.",
)
runtime_section = """
### Optional boot-time UEFI media validation

For compatible ARM64 persistent writable-copy media, the wizard can transactionally preserve the image's original `EFI/BOOT/BOOTAA64.EFI` as `EFI/BOOT/bootaa64_original.efi`, install the package-owned `uefi-md5sum` wrapper, and generate a verified root `md5sum.txt`. At boot, the wrapper checks the covered media tree and then chainloads the original fallback loader.

The canonical loader is built twice from pinned `uefi-md5sum` v1.2 and EDK2 commits and accepted only when the binaries and provenance are byte-for-byte identical. It is **unsigned**. Secure Boot compatibility is not established, and the option is off by default. Raw-image, Windows, NTFS, compressed-stream, and virtual-disk writers do not expose it.

The unchanged-media and intentional-corruption paths, including original-loader chainload, are qualified under pinned AArch64 QEMU firmware. That evidence does not replace physical qualification of the exact USB, controller, firmware, Secure Boot state, and computer.

"""
replace_once("README.md", "See `docs/persistence-user-guide.md` and `docs/persistence-qualification.md`.\n\n", "See `docs/persistence-user-guide.md` and `docs/persistence-qualification.md`.\n\n" + runtime_section)
replace_once(
    "README.md",
    "Requirements include Go 1.22 or newer, Python 3, Debian packaging tools, and the verified ARM64 WIM engine under `vendor/wimlib/arm64/`.",
    "Requirements include Go 1.22 or newer, Python 3, Debian packaging tools, the verified ARM64 WIM engine under `vendor/wimlib/arm64/`, and the reproducible package-private ARM64 `uefi-md5sum` artifact under `vendor/uefi-md5sum/arm64/`. Regenerating the loader additionally requires the pinned EDK2 toolchain dependencies documented in `docs/uefi-md5sum-build.md`.",
)
replace_once(
    "README.md",
    "That pre-boot structural/Secure Boot analysis is separate from Rufus's boot-time media-integrity option. The 0.11 development line includes descriptor-safe `uefi-md5sum` manifest generation and verification through the unprivileged CLI; it does not yet replace or chainload the media fallback loader.",
    "That pre-boot structural/Secure Boot analysis is separate from the boot-time media-integrity option. Version 0.11.0 also provides descriptor-safe manifest generation and verification through the unprivileged CLI and an opt-in transactional ARM64 wrapper in the guarded persistent-media workflow; the wrapper is unsigned and is not offered by other writer modes.",
)

roadmap = """## 0.11 — UEFI analysis and runtime media integrity (completed)

- Descriptor-rooted fallback-loader, PE/COFF, DBX, SBAT, and firmware-policy analysis with CLI and GTK reporting
- Rufus-compatible `md5sum.txt` generation, parsing, and full-tree verification
- Reproducibly built, source-retained ARM64 `uefi-md5sum` loader with transactional installation and rollback
- Guarded persistent-writer and GUI integration with explicit unsigned disclosure and unsupported-mode refusal
- Pinned AArch64 QEMU success, corruption, and original-loader chainload qualification
- Physical Surface Pro 11 and broader hardware qualification remains tracked under 0.5

"""
replace_once("ROADMAP.md", "## 1.0 — supportable stable release\n", roadmap + "## 1.0 — supportable stable release\n")

release_notes = """# RufusArm64 0.11.0

RufusArm64 0.11.0 adds two complementary UEFI safety features: a read-only structural and Secure Boot analyzer, and an optional boot-time media-integrity validator for the supported ARM64 persistent Ubuntu/Debian writable-copy path.

## Highlights

- Validate mounted or extracted media for the architecture-specific fallback loader, PE/COFF structure, DBX revocations, SBAT metadata, and trusted local or running-firmware SBAT policy.
- Generate and verify Rufus-compatible `md5sum.txt` manifests through the unprivileged CLI.
- Optionally install a transactional ARM64 `uefi-md5sum` wrapper when creating supported persistent Ubuntu/Debian media. The original fallback loader is preserved and chainloaded after validation.
- Reproduce the package-private loader from exact upstream `uefi-md5sum` v1.2 and EDK2 commits in two independent builds, retaining provenance and corresponding source.
- Qualify unchanged and intentionally corrupted GPT/FAT32 media under pinned AArch64 QEMU firmware, including original-loader chainload and complete diagnostic evidence.

## Important boundaries

The runtime-validation option is off by default and is limited to the guarded ARM64 persistent writable-copy workflow. Raw-image, Windows, NTFS, compressed-stream, and virtual-disk writers do not expose it.

The current runtime loader is **unsigned**. Secure Boot compatibility is not established. The QEMU test mode suppresses the normal interactive error prompt so CI can require deterministic success, corruption reporting, chainload, and shutdown behavior.

Software and QEMU qualification are not universal firmware or hardware guarantees. Physical Surface Pro 11 boot and persistence start/reboot/verify evidence remains a separate qualification step for the exact ISO, USB media, controller, firmware, Secure Boot state, and computer.

## Supply-chain and release assets

The tagged release builds and publishes the ARM64 Debian package, checksum sidecar, deterministic project source archive, pinned WIM corresponding source, and deterministic `uefi-md5sum` corresponding source. The unsigned EFI wrapper remains package-private rather than being published as a standalone boot binary.
"""
write("docs/release-0.11.0.md", release_notes)

version_check = r'''#!/usr/bin/env python3
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
'''
write("scripts/check-version-sync.py", version_check)
Path("scripts/check-version-sync.py").chmod(0o755)

replace_once(
    "scripts/test.sh",
    'grep -Fq "rufusarm64_${VERSION}_arm64.deb" README.md\n',
    'grep -Fq "rufusarm64_${VERSION}_arm64.deb" README.md\npython3 scripts/check-version-sync.py\n',
)

print("Staged synchronized RufusArm64 0.11.0 release metadata.")
