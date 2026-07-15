#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${VERSION:-0.2.0}"
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
Depends: python3 (>= 3.10), python3-gi, gir1.2-gtk-3.0, policykit-1, util-linux, parted, dosfstools, udev, wimtools
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
