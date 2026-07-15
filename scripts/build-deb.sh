#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${VERSION:-0.4.0}"
ARCH="arm64"
OUTPUT_DIR="${ROOT_DIR}/dist"
PACKAGE_DIR="$(mktemp -d)"
trap 'rm -rf "${PACKAGE_DIR}"' EXIT

mkdir -p "${OUTPUT_DIR}"
rm -f "${OUTPUT_DIR}/rufusarm64_${VERSION}_${ARCH}.deb" \
      "${OUTPUT_DIR}/rufusarm64_${VERSION}_${ARCH}.deb.sha256"

CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
  -o "${PACKAGE_DIR}/usr/lib/rufusarm64/rufusarm64-helper" \
  "${ROOT_DIR}/cmd/rufus-linux"

install -Dm755 "${ROOT_DIR}/gui/rufusarm64.py" \
  "${PACKAGE_DIR}/usr/lib/rufusarm64/rufusarm64.py"
install -Dm644 "${ROOT_DIR}/gui/rufusarm64_logic.py" \
  "${PACKAGE_DIR}/usr/lib/rufusarm64/rufusarm64_logic.py"

# Include the verified package-private ARM64 WIM engine. It is deliberately
# built without FUSE or NTFS-3G support and may depend only on the standard C
# runtime. Failing closed here prevents accidentally publishing a package that
# silently needs Ubuntu's optional wimtools package.
WIMLIB_SOURCE="${WIMLIB_ARM64_BINARY:-${ROOT_DIR}/vendor/wimlib/arm64/wimlib-imagex}"
if [[ ! -f "${WIMLIB_SOURCE}" ]]; then
  echo "Missing verified ARM64 WIM engine: ${WIMLIB_SOURCE}" >&2
  exit 1
fi
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
install -Dm755 "${ROOT_DIR}/packaging/rufusarm64" \
  "${PACKAGE_DIR}/usr/bin/rufusarm64"
ln -s ../lib/rufusarm64/rufusarm64-helper \
  "${PACKAGE_DIR}/usr/bin/rufusarm64-cli"
install -Dm644 "${ROOT_DIR}/packaging/io.github.geocausa.RufusArm64.desktop" \
  "${PACKAGE_DIR}/usr/share/applications/io.github.geocausa.RufusArm64.desktop"
install -Dm644 "${ROOT_DIR}/packaging/io.github.geocausa.RufusArm64.svg" \
  "${PACKAGE_DIR}/usr/share/icons/hicolor/scalable/apps/io.github.geocausa.RufusArm64.svg"
install -Dm644 "${ROOT_DIR}/packaging/io.github.geocausa.RufusArm64.metainfo.xml" \
  "${PACKAGE_DIR}/usr/share/metainfo/io.github.geocausa.RufusArm64.metainfo.xml"
install -Dm644 "${ROOT_DIR}/packaging/io.github.geocausa.RufusArm64.policy" \
  "${PACKAGE_DIR}/usr/share/polkit-1/actions/io.github.geocausa.RufusArm64.policy"
install -Dm644 "${ROOT_DIR}/README.md" \
  "${PACKAGE_DIR}/usr/share/doc/rufusarm64/README.md"
install -Dm644 "${ROOT_DIR}/LICENSE" \
  "${PACKAGE_DIR}/usr/share/doc/rufusarm64/copyright"
install -Dm644 "${ROOT_DIR}/docs/rufusarm64-cli.1" \
  "${PACKAGE_DIR}/usr/share/man/man1/rufusarm64-cli.1"
gzip -9n "${PACKAGE_DIR}/usr/share/man/man1/rufusarm64-cli.1"

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
Depends: python3 (>= 3.10), python3-gi, gir1.2-gtk-3.0, pkexec, util-linux, mount, dosfstools, udev
Homepage: https://github.com/geocausa/RufusArm64
Description: Bootable USB creator for Ubuntu ARM64
 A graphical utility that writes Linux ISOHybrid/raw images and creates modern
 Windows UEFI installation USB media using FAT32 and automatic WIM splitting.
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
dpkg-deb --root-owner-group -Zxz --build "${PACKAGE_DIR}" \
  "${OUTPUT_DIR}/rufusarm64_${VERSION}_${ARCH}.deb"
(
  cd "${OUTPUT_DIR}"
  sha256sum "rufusarm64_${VERSION}_${ARCH}.deb" > "rufusarm64_${VERSION}_${ARCH}.deb.sha256"
)

echo "Built ${OUTPUT_DIR}/rufusarm64_${VERSION}_${ARCH}.deb"
