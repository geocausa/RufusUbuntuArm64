#!/usr/bin/env python3
"""One-shot package integration for the Stage 2 non-bootable formatter."""

from pathlib import Path


def insert_after_unique(lines: list[str], marker: str, addition: list[str], label: str) -> None:
    matches = [index for index, line in enumerate(lines) if line == marker]
    if len(matches) != 1:
        raise SystemExit(f"{label}: expected one marker, found {len(matches)}")
    index = matches[0] + 1
    lines[index:index] = addition


def require_once(text: str, fragment: str, label: str) -> None:
    count = text.count(fragment)
    if count != 1:
        raise SystemExit(f"{label}: expected one occurrence, found {count}")


build = Path("scripts/build-deb.sh")
lines = build.read_text(encoding="utf-8").splitlines(keepends=True)
insert_after_unique(
    lines,
    '  "${ROOT_DIR}/cmd/rufus-device-backup"\n',
    [
        "CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \\\n",
        '  go build -buildvcs=false -trimpath -ldflags="-buildid= -s -w -X main.version=${VERSION}" \\\n',
        '  -o "${PACKAGE_DIR}/usr/lib/rufusarm64/rufusarm64-nonbootable-format" \\\n',
        '  "${ROOT_DIR}/cmd/rufus-nonbootable-format"\n',
    ],
    "backup build marker",
)
insert_after_unique(
    lines,
    '  "${PACKAGE_DIR}/usr/bin/rufusarm64-device-backup"\n',
    [
        "ln -s ../lib/rufusarm64/rufusarm64-nonbootable-format \\\n",
        '  "${PACKAGE_DIR}/usr/bin/rufusarm64-nonbootable-format"\n',
    ],
    "backup symlink marker",
)
text = "".join(lines)
old = "for page in rufusarm64 rufusarm64-cli rufusarm64-persistence rufusarm64-device-qualify rufusarm64-device-backup; do"
new = "for page in rufusarm64 rufusarm64-cli rufusarm64-persistence rufusarm64-device-qualify rufusarm64-device-backup rufusarm64-nonbootable-format; do"
require_once(text, old, "man page loop marker")
text = text.replace(old, new, 1)
old = "Depends: libc6 (>= 2.38), python3 (>= 3.10), python3-gi, gir1.2-gtk-3.0, pkexec, mount, dosfstools, e2fsprogs, ntfs-3g, udev, xz-utils, zstd, qemu-utils"
new_dependencies = "Depends: libc6 (>= 2.38), python3 (>= 3.10), python3-gi, gir1.2-gtk-3.0, pkexec, mount, fdisk, dosfstools, exfatprogs, e2fsprogs, ntfs-3g, udev, xz-utils, zstd, qemu-utils"
require_once(text, old, "dependency marker")
text = text.replace(old, new_dependencies, 1)
for fragment, label in (
    ('-o "${PACKAGE_DIR}/usr/lib/rufusarm64/rufusarm64-nonbootable-format"', "package-private binary"),
    ('"${ROOT_DIR}/cmd/rufus-nonbootable-format"', "formatter source command"),
    ("ln -s ../lib/rufusarm64/rufusarm64-nonbootable-format", "formatter symlink source"),
    ('"${PACKAGE_DIR}/usr/bin/rufusarm64-nonbootable-format"', "formatter symlink destination"),
    (new, "formatter man page loop"),
    (new_dependencies, "formatter package dependencies"),
):
    require_once(text, fragment, label)
build.write_text(text, encoding="utf-8")

policy = Path("packaging/io.github.geocausa.RufusArm64.policy")
text = policy.read_text(encoding="utf-8")
action = """  <action id="io.github.geocausa.RufusArm64.format-data">
    <description>Format a removable drive as data-only media</description>
    <message>Administrator authentication is required to erase and format the selected removable drive.</message>
    <defaults>
      <allow_any>no</allow_any>
      <allow_inactive>no</allow_inactive>
      <allow_active>auth_admin</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.exec.path">/usr/lib/rufusarm64/rufusarm64-nonbootable-format</annotate>
  </action>
"""
require_once(text, "</policyconfig>", "policy closing marker")
text = text.replace("</policyconfig>", action + "</policyconfig>", 1)
require_once(text, 'id="io.github.geocausa.RufusArm64.format-data"', "formatter Polkit action")
policy.write_text(text, encoding="utf-8")

Path(".github/scripts/apply_nonbootable_package.py").unlink()
