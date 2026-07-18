#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

for tool in staticcheck govulncheck actionlint; do
  command -v "${tool}" >/dev/null 2>&1 || {
    echo "Required audit tool is unavailable: ${tool}" >&2
    exit 1
  }
done

log_dir="${AUDIT_LOG_DIR:-dist/audit-logs}"
mkdir -p "${log_dir}"
status=0

run_audit() {
  local name="$1"
  shift
  echo "=== ${name} ==="
  if "$@" >"${log_dir}/${name}.log" 2>&1; then
    cat "${log_dir}/${name}.log"
  else
    result=$?
    cat "${log_dir}/${name}.log" >&2
    status=${result}
  fi
}

run_audit staticcheck staticcheck ./...
run_audit govulncheck govulncheck ./...
run_audit actionlint actionlint

exit "${status}"
