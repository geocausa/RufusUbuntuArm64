#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

unformatted="$(gofmt -l cmd internal)"
if [[ -n "${unformatted}" ]]; then
  echo "The following Go files need gofmt:" >&2
  echo "${unformatted}" >&2
  exit 1
fi

go test -race ./...
go vet ./...
python3 -m py_compile gui/rufusarm64.py
VERSION=0.2.0 scripts/build-deb.sh
dpkg-deb --info dist/rufusarm64_0.2.0_arm64.deb >/dev/null
dpkg-deb --contents dist/rufusarm64_0.2.0_arm64.deb >/dev/null
