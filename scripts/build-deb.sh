#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_VERSION="$(tr -d '
' < "${ROOT_DIR}/VERSION")"
VERSION="${VERSION:-${PROJECT_VERSION}}"
RUFUS_ALLOW_NONRELEASE_VERSION="${RUFUS_ALLOW_NONRELEASE_VERSION:-0}"
if [[ "${VERSION}" != "${PROJECT_VERSION}" && "${RUFUS_ALLOW_NONRELEASE_VERSION}" != "1" ]]; then
  echo "Non-release version ${VERSION} requires RUFUS_ALLOW_NONRELEASE_VERSION=1" >&2
  exit 1
fi
if ! dpkg --validate-version "${VERSION}" >/dev/null 2>&1; then
  echo "Invalid Debian package version: ${VERSION}" >&2
  exit 1
fi
ARCH="arm64"
OUTPUT_DIR="${OUTPUT_DIR:-${ROOT_DIR}/dist}"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(python3 - "${ROOT_DIR}/CHANGELOG.md" "${PROJECT_VERSION}" <<'PYDATE'
import datetime
import pathlib
import re
import sys

changelog = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
version = re.escape(sys.argv[2])
match = re.search(rf"^## {version} — (\d{{4}}-\d{{2}}-\d{{2}})$", changelog, re.MULTILINE)
if match is None:
    raise SystemExit("canonical release date is missing from CHANGELOG.md")
date = datetime.date.fromisoformat(match.group(1))
moment = datetime.datetime.combine(date, datetime.time(), datetime.timezone.utc)
print(int(moment.timestamp()))
PYDATE
)}"
export SOURCE_DATE_EPOCH
export LC_ALL=C
export TZ=UTC
PACKAGE_DIR="$(mktemp -d)"
trap 'rm -rf "${PACKAGE_DIR}"' EXIT

mkdir -p "${OUTPUT_DIR}"
rm -f "${OUTPUT_DIR}/rufusarm64_${VERSION}_${ARCH}.deb" \
      "${OUTPUT_DIR}/rufusarm64_${VERSION}_${ARCH}.deb.sha256"

CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -buildvcs=false -trimpath -ldflags="-buildid= -s -w -X main.version=${VERSION}" \
  -o "${PACKAGE_DIR}/usr/lib/rufusarm64/rufusarm64-helper" \
  "${ROOT_DIR}/cmd/rufus-linux"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -buildvcs=false -trimpath -ldflags="-buildid= -s -w -X main.version=${VERSION}" \
  -o "${PACKAGE_DIR}/usr/lib/rufusarm64/rufusarm64-persistence-helper" \
  "${ROOT_DIR}/cmd/rufus-persistence-helper"

install -Dm755 "${ROOT_DIR}/gui/rufusarm64.py" \
  "${PACKAGE_DIR}/usr/lib/rufusarm64/rufusarm64.py"
# The source-tree constant is a development fallback. Stamp the canonical
# repository version into the installed GUI. All interface semantics live in the
# tested source file; packaging must not rewrite application behavior or wording.
GUI_TARGET="${PACKAGE_DIR}/usr/lib/rufusarm64/rufusarm64.py"
python3 - "${GUI_TARGET}" "${VERSION}" <<'PYVERSION'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
version = sys.argv[2]
text = path.read_text(encoding="utf-8")
text, count = re.subn(
    r'^VERSION = "[^"]*"$',
    f'VERSION = "{version}"',
    text,
    count=1,
    flags=re.MULTILINE,
)
if count != 1:
    raise SystemExit("could not stamp the canonical version into the installed GUI")
path.write_text(text, encoding="utf-8")
PYVERSION
grep -Fxq "VERSION = \"${VERSION}\"" "${GUI_TARGET}"
grep -Fq 'Gtk.Expander(label="Persistent storage")' "${GUI_TARGET}"
grep -Fq "Keep files and settings across reboots" "${GUI_TARGET}"
if grep -Fq "Open Persistent USB Creator" "${GUI_TARGET}"; then
  echo "Packaged GUI must not expose the removed secondary persistence window" >&2
  exit 1
fi
grep -Fq "Checksums…" "${GUI_TARGET}"
install -Dm644 "${ROOT_DIR}/gui/rufusarm64_logic.py" \
  "${PACKAGE_DIR}/usr/lib/rufusarm64/rufusarm64_logic.py"
install -Dm644 "${ROOT_DIR}/gui/rufusarm64_checksums.py" \
  "${PACKAGE_DIR}/usr/lib/rufusarm64/rufusarm64_checksums.py"
install -Dm755 "${ROOT_DIR}/gui/rufusarm64_persistence.py" \
  "${PACKAGE_DIR}/usr/lib/rufusarm64/rufusarm64_persistence.py"
install -Dm644 "${ROOT_DIR}/gui/rufusarm64_persistence_logic.py" \
  "${PACKAGE_DIR}/usr/lib/rufusarm64/rufusarm64_persistence_logic.py"

# Include the verified package-private ARM64 WIM engine. It is deliberately
# built without FUSE or NTFS-3G support and may depend only on the standard C
# runtime. Failing closed here prevents accidentally publishing a package that
# silently needs Ubuntu's optional wimtools package.
WIMLIB_SOURCE="${WIMLIB_ARM64_BINARY:-${ROOT_DIR}/vendor/wimlib/arm64/wimlib-imagex}"
if [[ ! -f "${WIMLIB_SOURCE}" ]]; then
  echo "Missing verified ARM64 WIM engine: ${WIMLIB_SOURCE}" >&2
  exit 1
fi
expected_wim_hash="$(awk 'NF {print $1; exit}' "${ROOT_DIR}/vendor/wimlib/arm64/wimlib-imagex.sha256")"
actual_wim_hash="$(sha256sum "${WIMLIB_SOURCE}" | awk '{print $1}')"
[[ -n "${expected_wim_hash}" && "${actual_wim_hash}" == "${expected_wim_hash}" ]] || {
  echo "Refusing unpinned ARM64 WIM engine: ${actual_wim_hash}" >&2
  exit 1
}
file "${WIMLIB_SOURCE}" | grep -Eq 'ARM aarch64|AArch64' || {
  echo "Refusing to bundle a non-AArch64 WIM engine: ${WIMLIB_SOURCE}" >&2
  exit 1
}
needed="$(readelf -d "${WIMLIB_SOURCE}" | sed -n 's/.*Shared library: \[\(.*\)\].*/\1/p')"
while IFS= read -r library; do
  [[ -z "${library}" || "${library}" == "libc.so.6" || "${library}" == "ld-linux-aarch64.so.1" ]] || {
    echo "Refusing WIM engine with unexpected runtime dependency: ${library}" >&2
    exit 1
  }
done <<< "${needed}"
install -Dm755 "${WIMLIB_SOURCE}" \
  "${PACKAGE_DIR}/usr/lib/rufusarm64/wimlib-imagex"
for file in COPYING COPYING.GPLv3 COPYING.LGPL README.md; do
  install -Dm644 "${ROOT_DIR}/vendor/wimlib/${file}" \
    "${PACKAGE_DIR}/usr/share/doc/rufusarm64/wimlib/${file}"
done
for file in BUILD_CONFIGURATION UPSTREAM_COMMIT UPSTREAM_SOURCE; do
  install -Dm644 "${ROOT_DIR}/vendor/wimlib/source/${file}" \
    "${PACKAGE_DIR}/usr/share/doc/rufusarm64/wimlib/source/${file}"
done
for file in wimlib-1.14.5-source.tar.gz wimlib-1.14.5-source.tar.gz.sha256; do
  install -Dm644 "${ROOT_DIR}/vendor/wimlib/source/${file}" \
    "${PACKAGE_DIR}/usr/share/doc/rufusarm64/wimlib/source/${file}"
done
install -Dm644 "${ROOT_DIR}/vendor/wimlib/arm64/wimlib-imagex.sha256" \
  "${PACKAGE_DIR}/usr/share/doc/rufusarm64/wimlib/wimlib-imagex.sha256"

# Include the independently reproduced upstream ARM64 uefi-md5sum loader. It is
# unsigned and package-private; the writer must disclose that state explicitly.
UEFI_MD5SUM_DIR="${UEFI_MD5SUM_DIR:-${ROOT_DIR}/vendor/uefi-md5sum/arm64}"
UEFI_MD5SUM_SHA256="543615a8e97fed1cb5293bee7bdfe10f9feb6979f191b20ab32dafdcf097b502"
for file in bootaa64.efi bootaa64.efi.sha256 provenance.json SOURCE-COMMITS.txt \
  REPRODUCIBILITY.txt uefi-md5sum-v1.2-source.tar.gz uefi-md5sum-v1.2-source.tar.gz.sha256; do
  [[ -f "${UEFI_MD5SUM_DIR}/${file}" ]] || {
    echo "Missing reproduced ARM64 uefi-md5sum artifact: ${file}" >&2
    exit 1
  }
done
actual_md5sum_hash="$(sha256sum "${UEFI_MD5SUM_DIR}/bootaa64.efi" | awk '{print $1}')"
[[ "${actual_md5sum_hash}" == "${UEFI_MD5SUM_SHA256}" ]] || {
  echo "Refusing modified ARM64 uefi-md5sum loader: ${actual_md5sum_hash}" >&2
  exit 1
}
[[ "$(stat -c %s "${UEFI_MD5SUM_DIR}/bootaa64.efi")" -eq 40960 ]] || {
  echo "Unexpected ARM64 uefi-md5sum loader size" >&2
  exit 1
}
(
  cd "${UEFI_MD5SUM_DIR}"
  sha256sum -c bootaa64.efi.sha256
  sha256sum -c uefi-md5sum-v1.2-source.tar.gz.sha256
)
python3 - "${UEFI_MD5SUM_DIR}/provenance.json" <<'PYUEFIMD5'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)
artifact = data["artifact"]
assert artifact["sha256"] == "543615a8e97fed1cb5293bee7bdfe10f9feb6979f191b20ab32dafdcf097b502"
assert artifact["size"] == 40960
assert artifact["pe"]["machine"] == 0xAA64
assert artifact["pe"]["subsystem"] == 10
assert artifact["authenticode"]["present"] is False
assert artifact["secure_boot"]["compatibility_established"] is False
PYUEFIMD5
install -Dm644 "${UEFI_MD5SUM_DIR}/bootaa64.efi" \
  "${PACKAGE_DIR}/usr/lib/rufusarm64/bootaa64-uefi-md5sum.efi"
for file in bootaa64.efi.sha256 provenance.json SOURCE-COMMITS.txt REPRODUCIBILITY.txt \
  uefi-md5sum-v1.2-source.tar.gz uefi-md5sum-v1.2-source.tar.gz.sha256; do
  install -Dm644 "${UEFI_MD5SUM_DIR}/${file}" \
    "${PACKAGE_DIR}/usr/share/doc/rufusarm64/uefi-md5sum/${file}"
done

# Include Rufus 4.15's pinned, multi-architecture UEFI:NTFS FAT image.
# Its checksum is fixed in source so an altered boot path cannot enter a package.
UEFI_NTFS_SOURCE="${ROOT_DIR}/vendor/uefi-ntfs/uefi-ntfs.img"
UEFI_NTFS_SHA256="72683fa1250eeea772d3399277b434d4e55ba8dd0dc926e52d817e701fc2eb9e"
[[ -f "${UEFI_NTFS_SOURCE}" ]] || { echo "Missing verified UEFI:NTFS image" >&2; exit 1; }
actual_uefi_hash="$(sha256sum "${UEFI_NTFS_SOURCE}" | awk '{print $1}')"
[[ "${actual_uefi_hash}" == "${UEFI_NTFS_SHA256}" ]] || {
  echo "Refusing modified UEFI:NTFS image: ${actual_uefi_hash}" >&2
  exit 1
}
[[ "$(stat -c %s "${UEFI_NTFS_SOURCE}")" -eq 1048576 ]] || {
  echo "Unexpected UEFI:NTFS image size" >&2
  exit 1
}
install -Dm644 "${UEFI_NTFS_SOURCE}" \
  "${PACKAGE_DIR}/usr/lib/rufusarm64/uefi-ntfs.img"
for file in README-RUFUS-UEFI-NTFS.txt SHA256SUMS; do
  install -Dm644 "${ROOT_DIR}/vendor/uefi-ntfs/${file}" \
    "${PACKAGE_DIR}/usr/share/doc/rufusarm64/uefi-ntfs/${file}"
done

# Ship the exact GPL ms-sys source fragments used to derive the embedded
# Windows MBR/PBR byte arrays, plus the pin metadata and upstream hashes.
for file in PINNED-UPSTREAM.txt UPSTREAM-SHA256SUMS br.c ntfs.c fat32.c \
  mbr_win7.h br_ntfs_0x0.h br_ntfs_0x54.h br_fat32_0x0.h \
  br_fat32pe_0x52.h br_fat32pe_0x3f0.h br_fat32pe_0x1800.h; do
  install -Dm644 "${ROOT_DIR}/vendor/ms-sys/${file}" \
    "${PACKAGE_DIR}/usr/share/doc/rufusarm64/ms-sys/${file}"
done
install -Dm755 "${ROOT_DIR}/packaging/rufusarm64" \
  "${PACKAGE_DIR}/usr/bin/rufusarm64"
install -Dm755 "${ROOT_DIR}/packaging/rufusarm64-persistence" \
  "${PACKAGE_DIR}/usr/bin/rufusarm64-persistence"
ln -s ../lib/rufusarm64/rufusarm64-helper \
  "${PACKAGE_DIR}/usr/bin/rufusarm64-cli"
install -Dm644 "${ROOT_DIR}/packaging/io.github.geocausa.RufusArm64.desktop" \
  "${PACKAGE_DIR}/usr/share/applications/io.github.geocausa.RufusArm64.desktop"
install -Dm644 "${ROOT_DIR}/packaging/io.github.geocausa.RufusArm64.Persistence.desktop" \
  "${PACKAGE_DIR}/usr/share/applications/io.github.geocausa.RufusArm64.Persistence.desktop"
install -Dm644 "${ROOT_DIR}/packaging/io.github.geocausa.RufusArm64.svg" \
  "${PACKAGE_DIR}/usr/share/icons/hicolor/scalable/apps/io.github.geocausa.RufusArm64.svg"
install -Dm644 "${ROOT_DIR}/packaging/io.github.geocausa.RufusArm64.metainfo.xml" \
  "${PACKAGE_DIR}/usr/share/metainfo/io.github.geocausa.RufusArm64.metainfo.xml"
install -Dm644 "${ROOT_DIR}/packaging/io.github.geocausa.RufusArm64.policy" \
  "${PACKAGE_DIR}/usr/share/polkit-1/actions/io.github.geocausa.RufusArm64.policy"
install -Dm644 "${ROOT_DIR}/packaging/acquisition/channel.json" \
  "${PACKAGE_DIR}/usr/share/rufusarm64/acquisition/channel.json"
install -Dm644 "${ROOT_DIR}/README.md" \
  "${PACKAGE_DIR}/usr/share/doc/rufusarm64/README.md"
install -Dm644 "${ROOT_DIR}/docs/acquisition-channel.md" \
  "${PACKAGE_DIR}/usr/share/doc/rufusarm64/acquisition-channel.md"
install -Dm644 "${ROOT_DIR}/docs/acquisition-admin.md" \
  "${PACKAGE_DIR}/usr/share/doc/rufusarm64/acquisition-admin.md"
install -Dm644 "${ROOT_DIR}/docs/persistence-user-guide.md" \
  "${PACKAGE_DIR}/usr/share/doc/rufusarm64/persistence-user-guide.md"
install -Dm644 "${ROOT_DIR}/docs/persistence-qualification.md" \
  "${PACKAGE_DIR}/usr/share/doc/rufusarm64/persistence-qualification.md"
install -Dm644 "${ROOT_DIR}/NOTICE" \
  "${PACKAGE_DIR}/usr/share/doc/rufusarm64/NOTICE"
install -Dm644 "${ROOT_DIR}/LICENSE" \
  "${PACKAGE_DIR}/usr/share/doc/rufusarm64/LICENSE"
install -Dm644 "${ROOT_DIR}/packaging/copyright" \
  "${PACKAGE_DIR}/usr/share/doc/rufusarm64/copyright"
install -Dm644 "${ROOT_DIR}/CHANGELOG.md" \
  "${PACKAGE_DIR}/usr/share/doc/rufusarm64/changelog"
gzip -9n "${PACKAGE_DIR}/usr/share/doc/rufusarm64/changelog"
for page in rufusarm64 rufusarm64-cli rufusarm64-persistence; do
  install -Dm644 "${ROOT_DIR}/docs/${page}.1" \
    "${PACKAGE_DIR}/usr/share/man/man1/${page}.1"
  gzip -9n "${PACKAGE_DIR}/usr/share/man/man1/${page}.1"
done
install -Dm644 "${ROOT_DIR}/packaging/rufusarm64.lintian-overrides" \
  "${PACKAGE_DIR}/usr/share/lintian/overrides/rufusarm64"

mkdir -p "${PACKAGE_DIR}/DEBIAN"
INSTALLED_SIZE="$(du -sk "${PACKAGE_DIR}/usr" | awk '{print $1}')"
cat > "${PACKAGE_DIR}/DEBIAN/control" <<CONTROL
Package: rufusarm64
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Maintainer: geocausa <noreply@github.com>
Installed-Size: ${INSTALLED_SIZE}
Depends: libc6 (>= 2.38), python3 (>= 3.10), python3-gi, gir1.2-gtk-3.0, pkexec, mount, dosfstools, e2fsprogs, ntfs-3g, udev, xz-utils, zstd, qemu-utils
Homepage: https://github.com/geocausa/RufusUbuntuArm64
Description: Bootable USB creator for Ubuntu ARM64
 A graphical utility that writes Linux ISOHybrid/raw images, creates verified
 persistent Ubuntu/Debian live media, and creates Windows installation USB media
 using GPT or MBR, UEFI or x86-family BIOS/CSM, FAT32 or NTFS, and
 compressed or virtual-disk inputs. It includes Secure Boot DBX checks,
 verified boot assets, WIM splitting, and optional drivers.
CONTROL

cat > "${PACKAGE_DIR}/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database -q /usr/share/applications || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
fi
exit 0
POSTINST
chmod 0755 "${PACKAGE_DIR}/DEBIAN/postinst"

cat > "${PACKAGE_DIR}/DEBIAN/postrm" <<'POSTRM'
#!/bin/sh
set -e
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database -q /usr/share/applications || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
fi
exit 0
POSTRM
chmod 0755 "${PACKAGE_DIR}/DEBIAN/postrm"

find "${PACKAGE_DIR}" -type d -exec chmod 0755 {} +
find "${PACKAGE_DIR}" -exec touch --no-dereference --date="@${SOURCE_DATE_EPOCH}" {} +
dpkg-deb --root-owner-group -Zgzip -z9 --build "${PACKAGE_DIR}" \
  "${OUTPUT_DIR}/rufusarm64_${VERSION}_${ARCH}.deb"
(
  cd "${OUTPUT_DIR}"
  sha256sum "rufusarm64_${VERSION}_${ARCH}.deb" > "rufusarm64_${VERSION}_${ARCH}.deb.sha256"
)

echo "Built ${OUTPUT_DIR}/rufusarm64_${VERSION}_${ARCH}.deb"
