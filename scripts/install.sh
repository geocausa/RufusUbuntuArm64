#!/usr/bin/env bash
set -euo pipefail
SOURCE="${1:-./dist/rufusarm64-helper-arm64}"
DESTDIR="${DESTDIR:-}"
PREFIX="${PREFIX:-/usr/local}"
install -Dm755 "$SOURCE" "$DESTDIR$PREFIX/bin/rufusarm64-cli"
echo "Installed $DESTDIR$PREFIX/bin/rufusarm64-cli"
