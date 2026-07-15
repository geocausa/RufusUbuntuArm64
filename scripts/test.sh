#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="${VERSION:-0.4.0}"
PACKAGE="dist/rufusarm64_${VERSION}_arm64.deb"

unformatted="$(gofmt -l cmd internal)"
if [[ -n "${unformatted}" ]]; then
  echo "The following Go files need gofmt:" >&2
  echo "${unformatted}" >&2
  exit 1
fi

go test -race ./...
go test -shuffle=on -count=3 ./...
go vet ./...
go test -cover ./...
python3 -m py_compile gui/rufusarm64.py gui/rufusarm64_logic.py
PYTHONPATH=gui python3 -m unittest discover -s gui -p 'test_*.py'

native_dir="$(mktemp -d)"
native_helper="${native_dir}/rufusarm64-helper"
go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o "${native_helper}" ./cmd/rufus-linux
[[ "$("${native_helper}" version)" == "${VERSION}" ]]
printf 'rufusarm64-smoke' > "${native_dir}/sample.img"
expected_hash="$(sha256sum "${native_dir}/sample.img" | awk '{print $1}')"
actual_hash="$("${native_helper}" hash "${native_dir}/sample.img" | awk '{print $1}')"
[[ "${actual_hash}" == "${expected_hash}" ]]
# Build a minimal coherent MBR image and smoke-test the read-only inspector used
# by the graphical interface.
python3 - "${native_dir}/mbr.img" <<'PYIMAGE'
import struct, sys
path = sys.argv[1]
data = bytearray(2 * 1024 * 1024)
data[446 + 4] = 0x0C
struct.pack_into('<I', data, 446 + 8, 1)
struct.pack_into('<I', data, 446 + 12, 1024)
data[510:512] = b'\x55\xaa'
with open(path, 'wb') as handle:
    handle.write(data)
PYIMAGE
"${native_helper}" inspect --image "${native_dir}/mbr.img" --json | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["mode"] == "raw" and d["partition_scheme"] == "From image"'
rm -rf "${native_dir}"
for script in scripts/*.sh; do bash -n "${script}"; done
sh -n packaging/rufusarm64
if [[ -f vendor/wimlib/source/wimlib-1.14.5-source.tar.gz ]]; then
  (
    cd vendor/wimlib/source
    sha256sum -c wimlib-1.14.5-source.tar.gz.sha256
    tar -tzf wimlib-1.14.5-source.tar.gz >/dev/null
  )
fi

python3 - <<'PY'
import configparser
import pathlib
import xml.etree.ElementTree as ET

ET.parse("packaging/io.github.geocausa.RufusArm64.metainfo.xml")
ET.parse("packaging/io.github.geocausa.RufusArm64.policy")
ET.parse("packaging/io.github.geocausa.RufusArm64.svg")
parser = configparser.ConfigParser(interpolation=None)
parser.read("packaging/io.github.geocausa.RufusArm64.desktop")
entry = parser["Desktop Entry"]
for key in ("Name", "Exec", "Type", "Icon"):
    if not entry.get(key):
        raise SystemExit(f"desktop file is missing {key}")
if entry["Type"] != "Application":
    raise SystemExit("desktop Type must be Application")
PY

VERSION="${VERSION}" scripts/build-deb.sh
dpkg-deb --info "${PACKAGE}" >/dev/null
dpkg-deb --contents "${PACKAGE}" >/dev/null

extract_dir="$(mktemp -d)"
trap 'rm -rf "${extract_dir}" gui/__pycache__' EXIT
dpkg-deb -x "${PACKAGE}" "${extract_dir}"
dpkg-deb -e "${PACKAGE}" "${extract_dir}/DEBIAN"
helper="${extract_dir}/usr/lib/rufusarm64/rufusarm64-helper"
[[ -x "${helper}" ]]
[[ -f "${extract_dir}/usr/lib/rufusarm64/rufusarm64.py" ]]
[[ -f "${extract_dir}/usr/lib/rufusarm64/rufusarm64_logic.py" ]]
wim_engine="${extract_dir}/usr/lib/rufusarm64/wimlib-imagex"
[[ -x "${wim_engine}" ]]
file "${wim_engine}" | grep -Eq 'ARM aarch64|AArch64'
readelf -h "${wim_engine}" | grep -q 'Machine:.*AArch64'
while IFS= read -r library; do
  [[ -z "${library}" || "${library}" == "libc.so.6" || "${library}" == "ld-linux-aarch64.so.1" ]] || {
    echo "Unexpected bundled WIM dependency: ${library}" >&2
    exit 1
  }
done < <(readelf -d "${wim_engine}" | sed -n 's/.*Shared library: \[\(.*\)\].*/\1/p')
expected_wim_hash="$(awk '{print $1}' vendor/wimlib/arm64/wimlib-imagex.sha256)"
actual_wim_hash="$(sha256sum "${wim_engine}" | awk '{print $1}')"
[[ "${actual_wim_hash}" == "${expected_wim_hash}" ]]
for file in COPYING COPYING.GPLv3 COPYING.LGPL README.md; do
  [[ -f "${extract_dir}/usr/share/doc/rufusarm64/wimlib/${file}" ]]
done
for file in BUILD_CONFIGURATION UPSTREAM_COMMIT UPSTREAM_SOURCE; do
  [[ -f "${extract_dir}/usr/share/doc/rufusarm64/wimlib/source/${file}" ]]
done
for file in wimlib-1.14.5-source.tar.gz wimlib-1.14.5-source.tar.gz.sha256; do
  [[ -f "${extract_dir}/usr/share/doc/rufusarm64/wimlib/source/${file}" ]]
done
(
  cd "${extract_dir}/usr/share/doc/rufusarm64/wimlib/source"
  sha256sum -c wimlib-1.14.5-source.tar.gz.sha256
  tar -tzf wimlib-1.14.5-source.tar.gz >/dev/null
)
[[ -L "${extract_dir}/usr/bin/rufusarm64-cli" ]]
[[ -f "${extract_dir}/usr/share/man/man1/rufusarm64-cli.1.gz" ]]
file "${helper}" | grep -q 'ARM aarch64'
file "${helper}" | grep -q 'statically linked'
readelf -h "${helper}" | grep -q 'Machine:.*AArch64'
! readelf -l "${helper}" | grep -q 'Requesting program interpreter'
grep -q '^Architecture: arm64$' "${extract_dir}/DEBIAN/control"
grep -q 'Depends:.*mount' "${extract_dir}/DEBIAN/control"
! grep -q '^Suggests:.*wimtools' "${extract_dir}/DEBIAN/control"
! grep -q 'Depends:.*parted' "${extract_dir}/DEBIAN/control"
[[ "$(readlink "${extract_dir}/usr/bin/rufusarm64-cli")" == "../lib/rufusarm64/rufusarm64-helper" ]]
grep -q '<allow_active>auth_admin</allow_active>' "${extract_dir}/usr/share/polkit-1/actions/io.github.geocausa.RufusArm64.policy"
! grep -q 'auth_admin_keep' "${extract_dir}/usr/share/polkit-1/actions/io.github.geocausa.RufusArm64.policy"
gzip -t "${extract_dir}/usr/share/man/man1/rufusarm64-cli.1.gz"
grep -q 'GNU GENERAL PUBLIC LICENSE' "${extract_dir}/usr/share/doc/rufusarm64/copyright"
(cd dist && sha256sum -c "rufusarm64_${VERSION}_arm64.deb.sha256")
