#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

for tool in staticcheck govulncheck actionlint; do
  command -v "${tool}" >/dev/null 2>&1 || {
    echo "Required audit tool is unavailable: ${tool}" >&2
    exit 1
  }
done

staticcheck ./...
govulncheck ./...
actionlint
