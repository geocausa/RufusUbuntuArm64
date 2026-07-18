#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${1:-${ROOT_DIR}/dist/uefi-md5sum-arm64}"
UEFI_MD5SUM_REPOSITORY="https://github.com/pbatard/uefi-md5sum.git"
UEFI_MD5SUM_COMMIT="6195f2ef754c2ad390bda6590628708f410d55f6"
EDK2_REPOSITORY="https://github.com/tianocore/edk2.git"
EDK2_COMMIT="3d244c3b364bd4e21261380662186d064659161c"
SOURCE_DATE_EPOCH="1781373190"
BUILD_ROOT="${RUFUSARM64_UEFI_BUILD_ROOT:-/tmp/rufusarm64-uefi-md5sum-build}"

export LC_ALL=C
export TZ=UTC
export SOURCE_DATE_EPOCH
export PYTHONHASHSEED=0
export PYTHON_COMMAND=python3

for command in git make python3 aarch64-linux-gnu-gcc aarch64-linux-gnu-ld sha256sum gzip; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "Missing build program: ${command}" >&2
    exit 1
  }
done

case "${BUILD_ROOT}" in
  /*) ;;
  *)
    echo "RUFUSARM64_UEFI_BUILD_ROOT must be an absolute path" >&2
    exit 1
    ;;
esac
if [[ "${BUILD_ROOT}" == "/" || -e "${BUILD_ROOT}" ]]; then
  echo "Deterministic build root must be absent and must not be /: ${BUILD_ROOT}" >&2
  exit 1
fi
mkdir -m 0700 "${BUILD_ROOT}"
work_dir="${BUILD_ROOT}"
trap 'rm -rf -- "${work_dir}"' EXIT
source_dir="${work_dir}/uefi-md5sum"
edk2_dir="${work_dir}/edk2"

fetch_exact() {
  local repository="$1"
  local commit="$2"
  local destination="$3"
  git init -q "${destination}"
  git -C "${destination}" remote add origin "${repository}"
  git -C "${destination}" fetch --depth 1 origin "${commit}"
  git -C "${destination}" checkout -q --detach FETCH_HEAD
  test "$(git -C "${destination}" rev-parse HEAD)" = "${commit}"
}

fetch_exact "${UEFI_MD5SUM_REPOSITORY}" "${UEFI_MD5SUM_COMMIT}" "${source_dir}"
fetch_exact "${EDK2_REPOSITORY}" "${EDK2_COMMIT}" "${edk2_dir}"
git -C "${edk2_dir}" submodule update --init --recursive --depth 1

# Preserve deterministic corresponding source for the GPL bootloader.
mkdir -p "${OUTPUT_DIR}"
git -C "${source_dir}" archive --format=tar --prefix=uefi-md5sum-v1.2/ "${UEFI_MD5SUM_COMMIT}" \
  | gzip -n > "${OUTPUT_DIR}/uefi-md5sum-v1.2-source.tar.gz"
(
  cd "${OUTPUT_DIR}"
  sha256sum uefi-md5sum-v1.2-source.tar.gz > uefi-md5sum-v1.2-source.tar.gz.sha256
)

make -C "${edk2_dir}/BaseTools" -j"$(nproc)"
(
  cd "${source_dir}"
  export WORKSPACE="${source_dir}"
  export PACKAGES_PATH="${source_dir}:${edk2_dir}"
  export GCC_AARCH64_PREFIX="aarch64-linux-gnu-"
  # EDK2's legacy setup script probes optional unset variables. Keep the
  # surrounding build strict while containing that behavior to this source.
  set +u
  # shellcheck source=/dev/null
  source "${edk2_dir}/edksetup.sh" BaseTools
  set -u
  build -a AARCH64 -b RELEASE -t GCC -p Md5SumPkg.dsc
)

built_loader="${source_dir}/Build/RELEASE_GCC/AARCH64/Md5Sum.efi"
test -f "${built_loader}"
install -m 0644 "${built_loader}" "${OUTPUT_DIR}/bootaa64.efi"
(
  cd "${OUTPUT_DIR}"
  sha256sum bootaa64.efi > bootaa64.efi.sha256
)

printf '%s\n' \
  "uefi-md5sum repository: ${UEFI_MD5SUM_REPOSITORY}" \
  "uefi-md5sum tag: v1.2" \
  "uefi-md5sum commit: ${UEFI_MD5SUM_COMMIT}" \
  "edk2 repository: ${EDK2_REPOSITORY}" \
  "edk2 tag: edk2-stable202508.01" \
  "edk2 commit: ${EDK2_COMMIT}" \
  "source date epoch: ${SOURCE_DATE_EPOCH}" \
  "deterministic build root: ${BUILD_ROOT}" \
  > "${OUTPUT_DIR}/SOURCE-COMMITS.txt"

gcc_version="$(aarch64-linux-gnu-gcc --version | head -n 1)"
ld_version="$(aarch64-linux-gnu-ld --version | head -n 1)"
python3 "${ROOT_DIR}/scripts/inspect-uefi-pe.py" \
  --input "${OUTPUT_DIR}/bootaa64.efi" \
  --output "${OUTPUT_DIR}/provenance.json" \
  --uefi-md5sum-commit "${UEFI_MD5SUM_COMMIT}" \
  --edk2-commit "${EDK2_COMMIT}" \
  --source-date-epoch "${SOURCE_DATE_EPOCH}" \
  --gcc-version "${gcc_version}" \
  --ld-version "${ld_version}"

python3 -m json.tool "${OUTPUT_DIR}/provenance.json" >/dev/null
