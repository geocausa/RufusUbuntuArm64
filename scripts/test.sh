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
python3 scripts/check-release-runtime-integrity.py

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
  gui/rufusarm64_persistence.py gui/rufusarm64_persistence_logic.py \
  scripts/check-release-runtime-integrity.py
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
open(iso, 'wb').write(data)
# EFI_CERT_SHA256_GUID in EFI byte order, one owner GUID, one digest.
guid = bytes.fromhex("2616c4c14c509240aca941f936934328")
owner = bytes(range(16))
digest = hashlib.sha256(b"revoked").digest()
entry = owner + digest
payload = guid + struct.pack('<III', 28 + len(entry), 16, len(entry)) + entry
open(dbx, 'wb').write(payload)
PYSECURE
"${native_helper}" inspect --image "${native_dir}/windows.iso" --json | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["mode"] == "windows" and d["partition_scheme"] == "GPT" and d["target_system"] == "UEFI (non-CSM)"'
"${native_helper}" dbx inspect --dbx "${native_dir}/test.dbx" --json | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["sha256_count"] == 1 and d["x509_count"] == 0'
# Smoke-test the runtime-integrity manifest and verifier through the actual CLI
# before package construction.
integrity_root="${native_dir}/integrity"
mkdir -p "${integrity_root}/EFI/BOOT"
printf 'payload\n' > "${integrity_root}/payload.bin"
printf 'efi\n' > "${integrity_root}/EFI/BOOT/BOOTAA64.EFI"
"${native_helper}" uefi integrity manifest --directory "${integrity_root}" > "${integrity_root}/md5sum.txt"
"${native_helper}" uefi integrity verify --directory "${integrity_root}" --json | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["valid"] is True and d["declared_total_bytes"] == d["actual_total_bytes"]'

./scripts/build-deb.sh
[[ -f "${PACKAGE}" ]]

dpkg-deb --info "${PACKAGE}" >/dev/null
package_version="$(dpkg-deb -f "${PACKAGE}" Version)"
[[ "${package_version}" == "${VERSION}" ]]
package_arch="$(dpkg-deb -f "${PACKAGE}" Architecture)"
[[ "${package_arch}" == "arm64" ]]
package_depends="$(dpkg-deb -f "${PACKAGE}" Depends)"
[[ "${package_depends}" == *"policykit-1"* ]]
[[ "${package_depends}" == *"dosfstools"* ]]
[[ "${package_depends}" == *"e2fsprogs"* ]]
[[ "${package_depends}" == *"gdisk"* ]]
[[ "${package_depends}" == *"util-linux"* ]]
[[ "${package_depends}" == *"procps"* ]]
[[ "${package_depends}" == *"mount"* ]]
[[ "${package_depends}" == *"ntfs-3g"* ]]
[[ "${package_depends}" == *"qemu-utils"* ]]
[[ "${package_depends}" == *"python3-gi"* ]]
[[ "${package_depends}" == *"gir1.2-gtk-3.0"* ]]
[[ "${package_depends}" == *"python3-nacl"* ]]
[[ "${package_depends}" == *"python3-requests"* ]]
[[ "${package_depends}" != *"wimtools"* ]]
package_suggests="$(dpkg-deb -f "${PACKAGE}" Suggests)"
[[ "${package_suggests}" == *"wimtools"* ]]

extract_dir="$(mktemp -d)"
dpkg-deb -x "${PACKAGE}" "${extract_dir}"
[[ -x "${extract_dir}/usr/bin/rufusarm64" ]]
[[ -x "${extract_dir}/usr/lib/rufusarm64/rufusarm64-helper" ]]
[[ -x "${extract_dir}/usr/lib/rufusarm64/rufusarm64-persistence-helper" ]]
[[ -x "${extract_dir}/usr/lib/rufusarm64/wimlib-imagex" ]]
[[ -x "${extract_dir}/usr/bin/rufusarm64-cli" ]]
[[ -x "${extract_dir}/usr/bin/rufusarm64-persistence" ]]
[[ -x "${extract_dir}/usr/share/rufusarm64/rufusarm64.py" ]]
[[ -x "${extract_dir}/usr/share/rufusarm64/rufusarm64_persistence.py" ]]
[[ -f "${extract_dir}/usr/share/rufusarm64/rufusarm64_logic.py" ]]
[[ -f "${extract_dir}/usr/share/rufusarm64/rufusarm64_persistence_logic.py" ]]
[[ -f "${extract_dir}/usr/share/applications/io.github.geocausa.RufusArm64.desktop" ]]
[[ ! -f "${extract_dir}/usr/share/applications/io.github.geocausa.RufusArm64.Persistence.desktop" ]]
[[ -f "${extract_dir}/usr/share/metainfo/io.github.geocausa.RufusArm64.metainfo.xml" ]]
[[ -f "${extract_dir}/usr/share/polkit-1/actions/io.github.geocausa.RufusArm64.policy" ]]
[[ -f "${extract_dir}/usr/share/man/man1/rufusarm64.1.gz" ]]
[[ -f "${extract_dir}/usr/share/man/man1/rufusarm64-persistence.1.gz" ]]
[[ -f "${extract_dir}/usr/share/doc/rufusarm64/README.md.gz" ]]
[[ -f "${extract_dir}/usr/share/doc/rufusarm64/CHANGELOG.md.gz" ]]
[[ -f "${extract_dir}/usr/share/doc/rufusarm64/copyright" ]]
[[ -f "${extract_dir}/usr/share/doc/rufusarm64/wimlib/wimlib-imagex.sha256" ]]
[[ -f "${extract_dir}/usr/share/doc/rufusarm64/wimlib/wimlib-1.14.5-source.tar.gz" ]]
[[ -f "${extract_dir}/usr/share/doc/rufusarm64/wimlib/wimlib-1.14.5-source.tar.gz.sha256" ]]
expected_wim_hash="$(awk '{print $1}' "${extract_dir}/usr/share/doc/rufusarm64/wimlib/wimlib-imagex.sha256")"
actual_wim_hash="$(sha256sum "${extract_dir}/usr/lib/rufusarm64/wimlib-imagex" | awk '{print $1}')"
[[ "${actual_wim_hash}" == "${expected_wim_hash}" ]]
runtime_loader="${extract_dir}/usr/lib/rufusarm64/bootaa64-uefi-md5sum.efi"
[[ -f "${runtime_loader}" ]]
[[ "$(stat -c %s "${runtime_loader}")" -eq 40960 ]]
[[ "$(sha256sum "${runtime_loader}" | awk '{print $1}')" == "543615a8e97fed1cb5293bee7bdfe10f9feb6979f191b20ab32dafdcf097b502" ]]
for file in bootaa64.efi.sha256 provenance.json SOURCE-COMMITS.txt REPRODUCIBILITY.txt \
  uefi-md5sum-v1.2-source.tar.gz uefi-md5sum-v1.2-source.tar.gz.sha256; do
  [[ -f "${extract_dir}/usr/share/doc/rufusarm64/uefi-md5sum/${file}" ]]
done
python3 - "${extract_dir}/usr/share/doc/rufusarm64/uefi-md5sum/provenance.json" <<'PYUEFIPKG'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)
assert data["artifact"]["authenticode"]["present"] is False
assert data["artifact"]["secure_boot"]["compatibility_established"] is False
PYUEFIPKG
uefi_image="${extract_dir}/usr/lib/rufusarm64/uefi-ntfs.img"
[[ -f "${uefi_image}" ]]
[[ "$(stat -c %s "${uefi_image}")" -eq 1048576 ]]
[[ "$(sha256sum "${uefi_image}" | awk '{print $1}')" == "b92461e0c2977db69fb3124789a029f82b6e324e937de5059c516058ec9cf184" ]]
[[ "$(${extract_dir}/usr/bin/rufusarm64-cli version)" == "${VERSION}" ]]
[[ "$(${extract_dir}/usr/lib/rufusarm64/rufusarm64-persistence-helper --help 2>&1 || true)" != "" ]]
cmp -s gui/rufusarm64.py "${extract_dir}/usr/share/rufusarm64/rufusarm64.py"
cmp -s gui/rufusarm64_logic.py "${extract_dir}/usr/share/rufusarm64/rufusarm64_logic.py"
cmp -s gui/rufusarm64_persistence.py "${extract_dir}/usr/share/rufusarm64/rufusarm64_persistence.py"
cmp -s gui/rufusarm64_persistence_logic.py "${extract_dir}/usr/share/rufusarm64/rufusarm64_persistence_logic.py"
gzip -cd "${extract_dir}/usr/share/man/man1/rufusarm64.1.gz" | grep -Fq "RufusArm64 ${VERSION}"
gzip -cd "${extract_dir}/usr/share/man/man1/rufusarm64-persistence.1.gz" | grep -Fq "RufusArm64 ${VERSION}"
gzip -cd "${extract_dir}/usr/share/doc/rufusarm64/README.md.gz" | grep -Fq "rufusarm64_${VERSION}_arm64.deb"
gzip -cd "${extract_dir}/usr/share/doc/rufusarm64/CHANGELOG.md.gz" | grep -Fq "## ${VERSION} —"
grep -Fq "release version=\"${VERSION}\"" "${extract_dir}/usr/share/metainfo/io.github.geocausa.RufusArm64.metainfo.xml"
grep -Fq 'Create Persistent Live USB' "${extract_dir}/usr/share/applications/io.github.geocausa.RufusArm64.desktop"
grep -Fq 'Exec=rufusarm64-persistence' "${extract_dir}/usr/share/applications/io.github.geocausa.RufusArm64.desktop"

echo "All tests passed."
