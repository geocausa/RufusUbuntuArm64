#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_DIR="${1:-${ROOT_DIR}/artifacts/uefi-runtime-qemu}"
EDK2_REPOSITORY="https://github.com/tianocore/edk2.git"
EDK2_COMMIT="3d244c3b364bd4e21261380662186d064659161c"
LOADER_SHA256="543615a8e97fed1cb5293bee7bdfe10f9feb6979f191b20ab32dafdcf097b502"
DISK_BYTES=$((64 * 1024 * 1024))
SECTOR_BYTES=512
PARTITION_START=2048
PARTITION_SECTORS=126976
PARTITION_END=$((PARTITION_START + PARTITION_SECTORS - 1))
FIRMWARE_BYTES=$((64 * 1024 * 1024))

export LC_ALL=C
export TZ=UTC
export PYTHONHASHSEED=0
export PYTHON_COMMAND=python3
export SOURCE_DATE_EPOCH=1781373190

for command in \
  git make python3 go aarch64-linux-gnu-gcc aarch64-linux-gnu-ld \
  qemu-system-aarch64 sgdisk mkfs.vfat mcopy mdir sha256sum gzip timeout; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "Missing QEMU qualification program: ${command}" >&2
    exit 1
  }
done

work_dir="$(mktemp -d)"
trap 'rm -rf -- "${work_dir}"' EXIT
mkdir -p "${ARTIFACT_DIR}"
ARTIFACT_DIR="$(cd "${ARTIFACT_DIR}" && pwd)"

loader_dir="${work_dir}/loader"
bash "${ROOT_DIR}/scripts/build-uefi-md5sum-arm64.sh" "${loader_dir}"
actual_loader_sha="$(sha256sum "${loader_dir}/bootaa64.efi" | awk '{print $1}')"
[[ "${actual_loader_sha}" == "${LOADER_SHA256}" ]] || {
  echo "QEMU qualification loader hash is ${actual_loader_sha}, expected ${LOADER_SHA256}" >&2
  exit 1
}
[[ "$(stat -c %s "${loader_dir}/bootaa64.efi")" -eq 40960 ]] || {
  echo "QEMU qualification loader has an unexpected size" >&2
  exit 1
}

edk2_dir="${work_dir}/edk2"
git init -q "${edk2_dir}"
git -C "${edk2_dir}" remote add origin "${EDK2_REPOSITORY}"
git -C "${edk2_dir}" fetch --depth 1 origin "${EDK2_COMMIT}"
git -C "${edk2_dir}" checkout -q --detach FETCH_HEAD
test "$(git -C "${edk2_dir}" rev-parse HEAD)" = "${EDK2_COMMIT}"
git -C "${edk2_dir}" submodule update --init --recursive --depth 1
make -C "${edk2_dir}/BaseTools" -j"$(nproc)"

(
  cd "${edk2_dir}"
  export WORKSPACE="${edk2_dir}"
  export PACKAGES_PATH="${edk2_dir}"
  export GCC_AARCH64_PREFIX="aarch64-linux-gnu-"
  set +u
  # shellcheck source=/dev/null
  source "${edk2_dir}/edksetup.sh" BaseTools
  set -u
  build -a AARCH64 -b RELEASE -t GCC -p ArmVirtPkg/ArmVirtQemu.dsc
)
mapfile -t firmware_candidates < <(find "${edk2_dir}/Build" -type f -path '*/FV/QEMU_EFI.fd' -print)
[[ "${#firmware_candidates[@]}" -eq 1 ]] || {
  printf 'Expected one QEMU_EFI.fd, found %d\n' "${#firmware_candidates[@]}" >&2
  printf '%s\n' "${firmware_candidates[@]}" >&2
  exit 1
}
firmware="${work_dir}/QEMU_EFI.fd"
cp "${firmware_candidates[0]}" "${firmware}"
firmware_size="$(stat -c %s "${firmware}")"
[[ "${firmware_size}" -le "${FIRMWARE_BYTES}" ]] || {
  echo "Pinned EDK2 firmware exceeds the 64 MiB pflash extent" >&2
  exit 1
}
truncate -s "${FIRMWARE_BYTES}" "${firmware}"

app_workspace="${work_dir}/chainload-workspace"
mkdir -p "${app_workspace}/RufusChainloadTestPkg"
cp "${ROOT_DIR}/tests/uefi-chainload/"* "${app_workspace}/RufusChainloadTestPkg/"
(
  cd "${app_workspace}"
  export WORKSPACE="${app_workspace}"
  export PACKAGES_PATH="${app_workspace}:${edk2_dir}"
  export GCC_AARCH64_PREFIX="aarch64-linux-gnu-"
  set +u
  # shellcheck source=/dev/null
  source "${edk2_dir}/edksetup.sh" BaseTools
  set -u
  build -a AARCH64 -b RELEASE -t GCC -p RufusChainloadTestPkg/RufusChainloadTestPkg.dsc
)
mapfile -t app_candidates < <(find "${app_workspace}/Build" -type f -name RufusChainloadTest.efi -print)
[[ "${#app_candidates[@]}" -eq 1 ]] || {
  printf 'Expected one RufusChainloadTest.efi, found %d\n' "${#app_candidates[@]}" >&2
  printf '%s\n' "${app_candidates[@]}" >&2
  exit 1
}
chainload_app="${app_candidates[0]}"

cli="${work_dir}/rufusarm64-cli"
(
  cd "${ROOT_DIR}"
  go build -trimpath -o "${cli}" ./cmd/rufus-linux
)

make_tree() {
  local tree="$1"
  mkdir -p "${tree}/EFI/BOOT"
  install -m 0644 "${loader_dir}/bootaa64.efi" "${tree}/EFI/BOOT/BOOTAA64.EFI"
  install -m 0644 "${chainload_app}" "${tree}/EFI/BOOT/bootaa64_original.efi"
  printf 'RufusArm64 deterministic runtime integrity payload\n' > "${tree}/payload.bin"
  "${cli}" uefi integrity manifest --directory "${tree}" > "${tree}/md5sum.txt"
  "${cli}" uefi integrity verify --directory "${tree}" --json > "${tree}/verification.json"
  rm "${tree}/verification.json"
}

make_disk() {
  local tree="$1"
  local disk="$2"
  truncate -s "${DISK_BYTES}" "${disk}"
  sgdisk --zap-all --clear \
    --new="1:${PARTITION_START}:${PARTITION_END}" \
    --typecode=1:ef00 --change-name=1:RUFUSARM64 "${disk}" >/dev/null
  mkfs.vfat -F 32 -n RUFUSQEMU --invariant --offset="${PARTITION_START}" \
    "${disk}" "$((PARTITION_SECTORS / 2))" >/dev/null
  local offset=$((PARTITION_START * SECTOR_BYTES))
  mcopy -i "${disk}@@${offset}" -s "${tree}"/* ::/
  mdir -i "${disk}@@${offset}" ::/EFI/BOOT >/dev/null
  sgdisk --verify "${disk}" >/dev/null
}

run_qemu() {
  local disk="$1"
  local log="$2"
  local -a qemu=(
    qemu-system-aarch64
    -M virt
    -cpu cortex-a57
    -m 1024
    -smbios 'type=0,vendor=GitHub Actions Test,version=v1.0'
    -drive "if=pflash,format=raw,unit=0,file=${firmware},readonly=on"
    -drive "if=none,format=raw,file=${disk},id=bootdisk"
    -device virtio-blk-device,drive=bootdisk
    -nodefaults
    -nographic
    -serial stdio
    -monitor none
    -net none
    -no-reboot
  )
  set +e
  timeout --foreground 180 "${qemu[@]}" >"${log}" 2>&1
  local status=$?
  set -e
  if [[ "${status}" -eq 124 ]]; then
    echo "QEMU runtime-integrity test timed out" >&2
    cat "${log}" >&2
    return 1
  fi
  if [[ "${status}" -ne 0 ]]; then
    echo "QEMU runtime-integrity test exited with status ${status}" >&2
    cat "${log}" >&2
    return 1
  fi
}

success_tree="${work_dir}/success-tree"
corrupt_tree="${work_dir}/corrupt-tree"
make_tree "${success_tree}"
cp -a "${success_tree}" "${corrupt_tree}"
printf 'corruption-after-manifest\n' >> "${corrupt_tree}/payload.bin"
set +e
"${cli}" uefi integrity verify --directory "${corrupt_tree}" --json > "${work_dir}/corrupt-verification.json"
corrupt_verify_status=$?
set -e
[[ "${corrupt_verify_status}" -ne 0 ]] || {
  echo "Production verifier accepted the intentionally corrupted tree" >&2
  exit 1
}
python3 - "${work_dir}/corrupt-verification.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    result = json.load(handle)
assert result["valid"] is False
assert any(item["path"] == "./payload.bin" and item["status"] == "changed" for item in result["files"])
PY

success_disk="${work_dir}/runtime-success.img"
corrupt_disk="${work_dir}/runtime-corrupt.img"
make_disk "${success_tree}" "${success_disk}"
make_disk "${corrupt_tree}" "${corrupt_disk}"

success_log="${ARTIFACT_DIR}/success-serial.log"
corrupt_log="${ARTIFACT_DIR}/corrupt-serial.log"
run_qemu "${success_disk}" "${success_log}"
run_qemu "${corrupt_disk}" "${corrupt_log}"

chainload_marker='[RUFUSARM64 TEST] ORIGINAL ARM64 FALLBACK CHAINLOADED'
grep -F '[TEST] TotalBytes =' "${success_log}" >/dev/null
grep -E '[0-9]+/[0-9]+ files? processed \[0 failed\]' "${success_log}" >/dev/null
grep -F "${chainload_marker}" "${success_log}" >/dev/null
if grep -F 'Checksum Error' "${success_log}" >/dev/null; then
  echo "Successful QEMU media validation reported a checksum error" >&2
  exit 1
fi
grep -F '[TEST] TotalBytes =' "${corrupt_log}" >/dev/null
grep -F 'payload.bin' "${corrupt_log}" | grep -F 'Checksum Error' >/dev/null
grep -E '[0-9]+/[0-9]+ files? processed \[[1-9][0-9]* failed\]' "${corrupt_log}" >/dev/null
grep -F "${chainload_marker}" "${corrupt_log}" >/dev/null

cp "${success_tree}/md5sum.txt" "${ARTIFACT_DIR}/success-md5sum.txt"
cp "${corrupt_tree}/md5sum.txt" "${ARTIFACT_DIR}/corrupt-md5sum.txt"
cp "${work_dir}/corrupt-verification.json" "${ARTIFACT_DIR}/corrupt-verification.json"
cp "${loader_dir}/provenance.json" "${ARTIFACT_DIR}/loader-provenance.json"
cp "${loader_dir}/REPRODUCIBILITY.txt" "${ARTIFACT_DIR}/loader-reproducibility.txt" 2>/dev/null || true

success_disk_sha="$(sha256sum "${success_disk}" | awk '{print $1}')"
corrupt_disk_sha="$(sha256sum "${corrupt_disk}" | awk '{print $1}')"
firmware_sha="$(sha256sum "${firmware}" | awk '{print $1}')"
chainload_sha="$(sha256sum "${chainload_app}" | awk '{print $1}')"
cat > "${ARTIFACT_DIR}/QUALIFICATION.txt" <<EOF
RufusArm64 ARM64 runtime UEFI media validation QEMU qualification
uefi-md5sum loader SHA-256: ${actual_loader_sha}
uefi-md5sum loader size: $(stat -c %s "${loader_dir}/bootaa64.efi")
EDK2 commit: ${EDK2_COMMIT}
AAVMF/QEMU_EFI.fd SHA-256: ${firmware_sha}
Chainload marker app SHA-256: ${chainload_sha}
Success GPT/FAT32 image SHA-256: ${success_disk_sha}
Corrupt GPT/FAT32 image SHA-256: ${corrupt_disk_sha}
QEMU: $(qemu-system-aarch64 --version | head -n 1)
Test mode: upstream SMBIOS vendor trigger; prompts are suppressed, errors are reported, the original loader is chainloaded, and QEMU is shut down.
Secure Boot: disabled; the runtime loader is unsigned and Secure Boot compatibility is not established.
EOF

gzip -n -9 -c "${firmware}" > "${ARTIFACT_DIR}/QEMU_EFI.fd.gz"
gzip -n -9 -c "${success_disk}" > "${ARTIFACT_DIR}/runtime-success.img.gz"
gzip -n -9 -c "${corrupt_disk}" > "${ARTIFACT_DIR}/runtime-corrupt.img.gz"
sha256sum "${ARTIFACT_DIR}"/* > "${ARTIFACT_DIR}/SHA256SUMS"

echo "ARM64 runtime UEFI media validation and original-loader chainload qualified under QEMU."
