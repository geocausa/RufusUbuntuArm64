#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
PROJECT_VERSION="$(tr -d '\r\n' < VERSION)"
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
export VERSION RUFUS_ALLOW_NONRELEASE_VERSION
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

first="${work}/first"
second="${work}/second"
mkdir -p "${first}" "${second}"
OUTPUT_DIR="${first}" bash ./scripts/build-deb.sh
sleep 1
OUTPUT_DIR="${second}" bash ./scripts/build-deb.sh

package="rufusarm64_${VERSION}_arm64.deb"
checksum="${package}.sha256"
cmp --silent "${first}/${package}" "${second}/${package}" || {
  echo "Debian package is not reproducible across two clean builds" >&2
  sha256sum "${first}/${package}" "${second}/${package}" >&2
  exit 1
}
cmp --silent "${first}/${checksum}" "${second}/${checksum}" || {
  echo "Debian package checksum sidecar is not reproducible" >&2
  exit 1
}
echo "Reproducible package confirmed: ${package}"
