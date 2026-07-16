#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
PROJECT_VERSION="$(tr -d '\r\n' < VERSION)"
VERSION="${VERSION:-${PROJECT_VERSION}}"
if [[ "${VERSION}" != "${PROJECT_VERSION}" ]]; then
  echo "Requested version ${VERSION} does not match repository VERSION ${PROJECT_VERSION}" >&2
  exit 1
fi
export VERSION
PACKAGE="dist/rufusarm64_${VERSION}_arm64.deb"

grep -Fq "RufusArm64 ${VERSION}" docs/rufusarm64-cli.1
grep -Fq "## ${VERSION} —" CHANGELOG.md
grep -Fq "release version=\"${VERSION}\"" packaging/io.github.geocausa.RufusArm64.metainfo.xml
grep -Fq "rufusarm64_${VERSION}_arm64.deb" README.md

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
python3 -m py_compile \
  gui/rufusarm64.py gui/rufusarm64_logic.py \
  gui/rufusarm64_persistence.py gui/rufusarm64_persistence_logic.py
PYTHONPATH=gui python3 -m unittest discover -s gui -p 'test_*.py'

native_dir="$(mktemp -d)"
native_helper="${native_dir}/rufusarm64-helper"
native_persistence_helper="${native_dir}/rufusarm64-persistence-helper"
go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o "${native_helper}" ./cmd/rufus-linux
go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o "${native_persistence_helper}" ./cmd/rufus-persistence-helper
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
gzip -n -c "${native_dir}/mbr.img" > "${native_dir}/mbr.img.gz"
"${native_helper}" inspect --image "${native_dir}/mbr.img.gz" --json | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["mode"] == "raw" and d["container_format"] == "gzip"'
python3 - "${native_dir}/windows.iso" "${native_dir}/test.dbx" <<'PYSECURE'
import hashlib, struct, sys
iso, dbx = sys.argv[1:]
data = bytearray(160 * 1024)
offset = 16 * 2048
data[offset] = 1
data[offset + 1:offset + 6] = b"CD001"
data[offset + 6] = 1
open(iso, "wb").write(data)
# EFI_CERT_SHA256_GUID in EFI byte order, one owner GUID, one digest.
guid = bytes.fromhex("2616c4c14c509240aca941f936934328")
owner = bytes(16)
digest = hashlib.sha256(b"revoked-test").digest()
size = 28 + 16 + len(digest)
blob = guid + struct.pack("<III", size, 0, 16 + len(digest)) + owner + digest
open(dbx, "wb").write(blob)
PYSECURE
gzip -n -c "${native_dir}/windows.iso" > "${native_dir}/windows.iso.gz"
"${native_helper}" inspect --image "${native_dir}/windows.iso.gz" --json | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["mode"] == "windows" and d["windows_options"] and d["container_format"] == "gzip"'
"${native_helper}" dbx inspect --file "${native_dir}/test.dbx" --json | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["sha256_hashes"] == 1 and d["signatures"] == 1'
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o "${native_dir}/helper-arm64" ./cmd/rufus-linux
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o "${native_dir}/helper-amd64" ./cmd/rufus-linux
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o "${native_dir}/persistence-helper-arm64" ./cmd/rufus-persistence-helper
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o "${native_dir}/persistence-helper-amd64" ./cmd/rufus-persistence-helper
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o "${native_dir}/channel-admin-arm64" ./cmd/rufus-channel-admin
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "${native_dir}/channel-admin-amd64" ./cmd/rufus-channel-admin
readelf -h "${native_dir}/helper-arm64" | grep -q 'Machine:.*AArch64'
readelf -h "${native_dir}/helper-amd64" | grep -q 'Machine:.*Advanced Micro Devices X86-64'
readelf -h "${native_dir}/persistence-helper-arm64" | grep -q 'Machine:.*AArch64'
readelf -h "${native_dir}/persistence-helper-amd64" | grep -q 'Machine:.*Advanced Micro Devices X86-64'
readelf -h "${native_dir}/channel-admin-arm64" | grep -q 'Machine:.*AArch64'
readelf -h "${native_dir}/channel-admin-amd64" | grep -q 'Machine:.*Advanced Micro Devices X86-64'
! grep -q -- '--private-key' cmd/rufus-channel-admin/main.go
! grep -q 'ed25519.PrivateKey' cmd/rufus-channel-admin/main.go
! grep -q 'ed25519.Sign(' cmd/rufus-channel-admin/main.go
rm -rf "${native_dir}"
for script in scripts/*.sh; do bash -n "${script}"; done
sh -n packaging/rufusarm64
test "$(stat -c %s vendor/uefi-ntfs/uefi-ntfs.img)" -eq 1048576
(
  cd vendor/uefi-ntfs
  sha256sum -c SHA256SUMS
)

python3 - <<'PYBOOT'
import hashlib
from pathlib import Path
expected = {
    "windows7-mbr-code.bin": "59019b8b59cffb325855cdc7716d38f8ce2112b9b027f2f8516992e2e686525b",
    "ntfs-pbr-0x0.bin": "31d8233ca5e09344616973de6908c8eb0d6b6792d6aac6950e44b92ad796fb52",
    "ntfs-pbr-0x54.bin": "331cd27121fb2f9954e2c269e95a0111066d8479f78f44272b4491c6b36128fd",
    "fat32-pbr-0x0.bin": "e08eb0254294a42a6dc29fa094f8c6e4fee38513b4082deb81f305b2c31e5531",
    "fat32-pbr-0x52.bin": "45fd3b18c1d320ea854fdfdcac06ef4d9ae846d84daa728f6fcdd0eeb3d6d7b1",
    "fat32-pbr-0x3f0.bin": "c412950968e5b783040d78831ebec5a33ea2cc51239c32dd92b7b8729a58c669",
    "fat32-pbr-0x1800.bin": "ed75f19c0705c18b3628db1e981e6c314f80009f791399abbf291513f7cbd9b4",
}
root = Path("internal/windowsmedia/bootassets")
for name, digest in expected.items():
    data = (root / name).read_bytes()
    actual = hashlib.sha256(data).hexdigest()
    if actual != digest:
        raise SystemExit(f"{name}: expected {digest}, got {actual}")
for name in ("PINNED-UPSTREAM.txt", "UPSTREAM-SHA256SUMS", "br.c", "ntfs.c", "fat32.c", "mbr_win7.h", "br_ntfs_0x0.h", "br_ntfs_0x54.h", "br_fat32_0x0.h", "br_fat32pe_0x52.h", "br_fat32pe_0x3f0.h", "br_fat32pe_0x1800.h"):
    if not (Path("vendor/ms-sys") / name).is_file():
        raise SystemExit(f"missing pinned ms-sys source: {name}")
PYBOOT

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
import json
channel_path = pathlib.Path("packaging/acquisition/channel.json")
channel = json.loads(channel_path.read_text(encoding="utf-8"))
expected_keys = {"schema", "enabled", "bootstrap_root", "root_url", "catalog_url", "allowed_hosts"}
if set(channel) != expected_keys or channel["schema"] != 1 or channel["enabled"] is not False:
    raise SystemExit("packaged acquisition channel must remain an explicit disabled schema-1 configuration")
if any(channel[name] for name in ("bootstrap_root", "root_url", "catalog_url", "allowed_hosts")):
    raise SystemExit("disabled acquisition channel must not contain placeholder trust material or URLs")
if "PRIVATE KEY" in channel_path.read_text(encoding="utf-8"):
    raise SystemExit("private acquisition key material must never be packaged")
parser = configparser.ConfigParser(interpolation=None)
for desktop in (
    "packaging/io.github.geocausa.RufusArm64.desktop",
    "packaging/io.github.geocausa.RufusArm64.Persistence.desktop",
):
    parser.clear()
    parser.read(desktop)
    entry = parser["Desktop Entry"]
    for key in ("Name", "Exec", "Type", "Icon"):
        if not entry.get(key):
            raise SystemExit(f"{desktop} is missing {key}")
    if entry["Type"] != "Application":
        raise SystemExit(f"{desktop} Type must be Application")
PY

VERSION="${VERSION}" scripts/build-deb.sh
dpkg-deb --info "${PACKAGE}" >/dev/null
dpkg-deb --contents "${PACKAGE}" >/dev/null

extract_dir="$(mktemp -d)"
trap 'rm -rf "${extract_dir}" gui/__pycache__' EXIT
dpkg-deb -x "${PACKAGE}" "${extract_dir}"
dpkg-deb -e "${PACKAGE}" "${extract_dir}/DEBIAN"
helper="${extract_dir}/usr/lib/rufusarm64/rufusarm64-helper"
persistence_helper="${extract_dir}/usr/lib/rufusarm64/rufusarm64-persistence-helper"
installed_gui="${extract_dir}/usr/lib/rufusarm64/rufusarm64.py"
[[ -x "${helper}" ]]
[[ -x "${persistence_helper}" ]]
[[ -f "${installed_gui}" ]]
[[ -f "${extract_dir}/usr/lib/rufusarm64/rufusarm64_logic.py" ]]
[[ -f "${extract_dir}/usr/lib/rufusarm64/rufusarm64_persistence.py" ]]
[[ -f "${extract_dir}/usr/lib/rufusarm64/rufusarm64_persistence_logic.py" ]]
grep -Fxq "VERSION = \"${VERSION}\"" "${installed_gui}"
grep -Fxq "Version: ${VERSION}" "${extract_dir}/DEBIAN/control"
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
uefi_image="${extract_dir}/usr/lib/rufusarm64/uefi-ntfs.img"
[[ -f "${uefi_image}" ]]
[[ "$(stat -c %s "${uefi_image}")" -eq 1048576 ]]
expected_uefi_hash="$(awk '/uefi-ntfs.img$/ {print $1}' vendor/uefi-ntfs/SHA256SUMS | head -n1)"
actual_uefi_hash="$(sha256sum "${uefi_image}" | awk '{print $1}')"
[[ "${actual_uefi_hash}" == "${expected_uefi_hash}" ]]
for file in README-RUFUS-UEFI-NTFS.txt SHA256SUMS; do
  [[ -f "${extract_dir}/usr/share/doc/rufusarm64/uefi-ntfs/${file}" ]]
done
for file in PINNED-UPSTREAM.txt UPSTREAM-SHA256SUMS br.c ntfs.c fat32.c \
  mbr_win7.h br_ntfs_0x0.h br_ntfs_0x54.h br_fat32_0x0.h \
  br_fat32pe_0x52.h br_fat32pe_0x3f0.h br_fat32pe_0x1800.h; do
  [[ -f "${extract_dir}/usr/share/doc/rufusarm64/ms-sys/${file}" ]]
done
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
[[ -x "${extract_dir}/usr/bin/rufusarm64-persistence" ]]
[[ -f "${extract_dir}/usr/share/applications/io.github.geocausa.RufusArm64.Persistence.desktop" ]]
[[ -f "${extract_dir}/usr/share/man/man1/rufusarm64-cli.1.gz" ]]
[[ -f "${extract_dir}/usr/share/doc/rufusarm64/acquisition-channel.md" ]]
[[ -f "${extract_dir}/usr/share/doc/rufusarm64/acquisition-admin.md" ]]
[[ -f "${extract_dir}/usr/share/doc/rufusarm64/persistence-user-guide.md" ]]
[[ -f "${extract_dir}/usr/share/doc/rufusarm64/persistence-qualification.md" ]]
[[ ! -e "${extract_dir}/usr/bin/rufus-channel-admin" ]]
[[ ! -e "${extract_dir}/usr/lib/rufusarm64/rufus-channel-admin" ]]
channel_config="${extract_dir}/usr/share/rufusarm64/acquisition/channel.json"
[[ -f "${channel_config}" ]]
cmp -s packaging/acquisition/channel.json "${channel_config}"
python3 - "${channel_config}" <<'PYCHANNEL'
import json, pathlib, sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert value["schema"] == 1 and value["enabled"] is False
assert not value["bootstrap_root"] and not value["root_url"] and not value["catalog_url"] and not value["allowed_hosts"]
PYCHANNEL
file "${helper}" | grep -q 'ARM aarch64'
file "${helper}" | grep -q 'statically linked'
file "${persistence_helper}" | grep -q 'ARM aarch64'
file "${persistence_helper}" | grep -q 'statically linked'
readelf -h "${helper}" | grep -q 'Machine:.*AArch64'
readelf -h "${persistence_helper}" | grep -q 'Machine:.*AArch64'
! readelf -l "${helper}" | grep -q 'Requesting program interpreter'
! readelf -l "${persistence_helper}" | grep -q 'Requesting program interpreter'
grep -q '^Architecture: arm64$' "${extract_dir}/DEBIAN/control"
grep -q 'Depends:.*mount' "${extract_dir}/DEBIAN/control"
grep -q 'Depends:.*e2fsprogs' "${extract_dir}/DEBIAN/control"
grep -q 'Depends:.*ntfs-3g' "${extract_dir}/DEBIAN/control"
grep -q 'Depends:.*xz-utils' "${extract_dir}/DEBIAN/control"
grep -q 'Depends:.*zstd' "${extract_dir}/DEBIAN/control"
grep -q 'Depends:.*qemu-utils' "${extract_dir}/DEBIAN/control"
! grep -q '^Suggests:.*wimtools' "${extract_dir}/DEBIAN/control"
! grep -q 'Depends:.*parted' "${extract_dir}/DEBIAN/control"
[[ "$(readlink "${extract_dir}/usr/bin/rufusarm64-cli")" == "../lib/rufusarm64/rufusarm64-helper" ]]
grep -q '<allow_active>auth_admin</allow_active>' "${extract_dir}/usr/share/polkit-1/actions/io.github.geocausa.RufusArm64.policy"
! grep -q 'auth_admin_keep' "${extract_dir}/usr/share/polkit-1/actions/io.github.geocausa.RufusArm64.policy"
gzip -t "${extract_dir}/usr/share/man/man1/rufusarm64-cli.1.gz"
grep -q 'GNU GENERAL PUBLIC LICENSE' "${extract_dir}/usr/share/doc/rufusarm64/copyright"
(cd dist && sha256sum -c "rufusarm64_${VERSION}_arm64.deb.sha256")
