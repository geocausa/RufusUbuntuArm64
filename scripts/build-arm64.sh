#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p dist
PROJECT_VERSION="$(tr -d '\r\n' < VERSION)"
VERSION="${VERSION:-${PROJECT_VERSION}}"
if [[ "${VERSION}" != "${PROJECT_VERSION}" ]]; then
  echo "Requested version ${VERSION} does not match repository VERSION ${PROJECT_VERSION}" >&2
  exit 1
fi
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
  -o dist/rufusarm64-helper-arm64 ./cmd/rufus-linux
sha256sum dist/rufusarm64-helper-arm64 > dist/rufusarm64-helper-arm64.sha256
