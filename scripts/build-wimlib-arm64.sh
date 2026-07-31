#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${1:-${ROOT_DIR}/vendor/wimlib/arm64}"
UPSTREAM_COMMIT="$(tr -d '[:space:]' < "${ROOT_DIR}/vendor/wimlib/source/UPSTREAM_COMMIT")"
UPSTREAM_URL="$(tr -d '\r\n' < "${ROOT_DIR}/vendor/wimlib/source/UPSTREAM_SOURCE")"

if [[ "$(uname -m)" != "aarch64" ]]; then
  echo "The bundled WIM engine must be built natively on ARM64 (aarch64)." >&2
  exit 1
fi
for command in git autoconf automake libtoolize make gcc file readelf strip sha256sum pkg-config; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "Missing build program: ${command}" >&2
    exit 1
  }
done
pkg-config --exists libntfs-3g || {
  echo "Direct NTFS-volume support requires the ntfs-3g development package." >&2
  exit 1
}

work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT
source_dir="${work_dir}/wimlib"
git clone --filter=blob:none --no-checkout "${UPSTREAM_URL%/tree/*}" "${source_dir}"
git -C "${source_dir}" checkout --detach "${UPSTREAM_COMMIT}"
test "$(git -C "${source_dir}" rev-parse HEAD)" = "${UPSTREAM_COMMIT}"

# Preserve the exact corresponding source used to build the bundled GPL tool.
# The generated archive is carried in the Debian package and in release assets,
# but is not committed as a generated binary artifact.
source_archive="${ROOT_DIR}/vendor/wimlib/source/wimlib-1.14.5-source.tar.gz"
mkdir -p "$(dirname "${source_archive}")"
git -C "${source_dir}" archive --format=tar.gz --prefix=wimlib-1.14.5/ \
  -o "${source_archive}" "${UPSTREAM_COMMIT}"
(
  cd "$(dirname "${source_archive}")"
  sha256sum "$(basename "${source_archive}")" > "$(basename "${source_archive}").sha256"
)

# Normalize every known host/path source of variation. The build ID is omitted
# deliberately because it otherwise changes between identical temporary source
# directories. CI builds this engine twice and requires byte-for-byte identity.
SOURCE_DATE_EPOCH="$(git -C "${source_dir}" show -s --format=%ct "${UPSTREAM_COMMIT}")"
export SOURCE_DATE_EPOCH
export CFLAGS="-O2 -ffile-prefix-map=${source_dir}=. -fdebug-prefix-map=${source_dir}=."
export LDFLAGS="-Wl,--build-id=none"
export ARFLAGS="crD"

(
  cd "${source_dir}"
  ./bootstrap
  ./configure \
    --without-fuse \
    --with-ntfs-3g \
    --disable-shared \
    --enable-static
  make -j"$(nproc)"
  test -x wimlib-imagex
  strip --strip-all wimlib-imagex
)

mkdir -p "${OUTPUT_DIR}"
install -m 0755 "${source_dir}/wimlib-imagex" "${OUTPUT_DIR}/wimlib-imagex"
file "${OUTPUT_DIR}/wimlib-imagex" | grep -Eq 'ARM aarch64|AArch64'
needed="$(readelf -d "${OUTPUT_DIR}/wimlib-imagex" | sed -n 's/.*Shared library: \[\(.*\)\].*/\1/p')"
found_ntfs=0
while IFS= read -r library; do
  case "${library}" in
    "") ;;
    libntfs-3g.so.89) found_ntfs=1 ;;
    libc.so.6|ld-linux-aarch64.so.1) ;;
    *)
      echo "Unexpected WIM engine runtime dependency: ${library}" >&2
      exit 1
      ;;
  esac
done <<< "${needed}"
[[ "${found_ntfs}" -eq 1 ]] || {
  echo "The WIM engine was built without the required direct NTFS-volume provider." >&2
  exit 1
}
if readelf -n "${OUTPUT_DIR}/wimlib-imagex" | grep -q 'Build ID:'; then
  echo "The reproducible WIM engine must not contain a nondeterministic linker build ID." >&2
  exit 1
fi
(
  cd "${OUTPUT_DIR}"
  sha256sum wimlib-imagex > wimlib-imagex.sha256
)
"${OUTPUT_DIR}/wimlib-imagex" --version
