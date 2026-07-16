#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p dist
VERSION="${VERSION:-0.8.0}"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
  -o dist/rufusarm64-helper-arm64 ./cmd/rufus-linux
sha256sum dist/rufusarm64-helper-arm64 > dist/rufusarm64-helper-arm64.sha256
