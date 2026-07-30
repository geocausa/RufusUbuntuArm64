#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 6 ]]; then
  echo "usage: $0 METADATA_DIR ASSET_DIR EXPECTED_TAG EXPECTED_COMMIT CHANNEL_CONFIG BOOTSTRAP_ROOT" >&2
  exit 2
fi

metadata_dir="$1"
asset_dir="$2"
expected_tag="$3"
expected_commit="$4"
channel_config="$5"
bootstrap_root="$6"

[[ -d "${metadata_dir}" && ! -L "${metadata_dir}" ]] || {
  echo "required metadata directory is missing or is a symlink: ${metadata_dir}" >&2
  exit 1
}
if [[ "${asset_dir}" != "-" ]]; then
  [[ -d "${asset_dir}" && ! -L "${asset_dir}" ]] || {
    echo "required asset directory is missing or is a symlink: ${asset_dir}" >&2
    exit 1
  }
fi
for path in "${channel_config}" "${bootstrap_root}"; do
  [[ -f "${path}" && ! -L "${path}" ]] || {
    echo "required product trust input is missing or is a symlink: ${path}" >&2
    exit 1
  }
done
for path in channel.json 1.root.json catalog.json release.json publication.json SHA256SUMS; do
  [[ -f "${metadata_dir}/${path}" && ! -L "${metadata_dir}/${path}" ]] || {
    echo "signed metadata publication is missing ${path}" >&2
    exit 1
  }
done

cmp "${channel_config}" "${metadata_dir}/channel.json" || {
  echo "tagged product channel configuration differs from the signed metadata publication" >&2
  exit 1
}
cmp "${bootstrap_root}" "${metadata_dir}/1.root.json" || {
  echo "tagged product bootstrap root differs from the signed metadata publication" >&2
  exit 1
}
python3 - "${channel_config}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text(encoding="utf-8"))
expected = {"schema", "enabled", "bootstrap_root", "root_url", "catalog_url", "release_url", "allowed_hosts"}
if set(value) != expected or value["schema"] != 1 or value["enabled"] is not True:
    raise SystemExit("release publication requires an explicit enabled schema-1 channel")
if value["bootstrap_root"] != "1.root.json" or not value["release_url"] or not value["allowed_hosts"]:
    raise SystemExit("release publication channel is missing bootstrap, release URL, or host trust")
PY

mapfile -t roots < <(
  find "${metadata_dir}" -maxdepth 1 -type f -regextype posix-extended \
    -regex '.*/[1-9][0-9]*\.root\.json' -printf '%p\n' | sort -V
)
[[ ${#roots[@]} -gt 0 && "$(basename "${roots[0]}")" = "1.root.json" ]] || {
  echo "signed metadata publication has no sequential bootstrap root chain" >&2
  exit 1
}

temporary="$(mktemp -d)"
cleanup() {
  rm -rf "${temporary}"
}
trap cleanup EXIT
admin="${RUFUS_CHANNEL_ADMIN:-${temporary}/rufus-channel-admin}"
if [[ -z "${RUFUS_CHANNEL_ADMIN:-}" ]]; then
  GOTOOLCHAIN="${GOTOOLCHAIN:-go1.26.5}" go build -trimpath -o "${admin}" ./cmd/rufus-channel-admin
fi

now_args=()
if [[ -n "${RELEASE_VERIFY_NOW:-}" ]]; then
  now_args=(--now "${RELEASE_VERIFY_NOW}")
fi
publish_args=(publish --catalog "${metadata_dir}/catalog.json" --release "${metadata_dir}/release.json" \
  --config "${metadata_dir}/channel.json" --directory "${temporary}/rebuilt" "${now_args[@]}")
identity_args=(verify release --release "${metadata_dir}/release.json" --json "${now_args[@]}")
verify_args=(verify release-assets --release "${metadata_dir}/release.json" --asset-dir "${asset_dir}" \
  --expected-tag "${expected_tag}" --expected-commit "${expected_commit}" --json "${now_args[@]}")
for root in "${roots[@]}"; do
  publish_args+=(--root "${root}")
  identity_args+=(--root "${root}")
  verify_args+=(--root "${root}")
done
"${admin}" "${publish_args[@]}" >/dev/null

python3 - "${metadata_dir}" "${temporary}/rebuilt" <<'PY'
import os
import pathlib
import stat
import sys

published = pathlib.Path(sys.argv[1])
rebuilt = pathlib.Path(sys.argv[2])


def inventory(root: pathlib.Path, allow_git: bool) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        current_path = pathlib.Path(current)
        if allow_git and current_path == root:
            directories[:] = [name for name in directories if name != ".git"]
        for directory in list(directories):
            path = current_path / directory
            if path.is_symlink():
                raise SystemExit(f"publication contains a symlink directory: {path}")
        for name in files:
            path = current_path / name
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise SystemExit(f"publication contains a non-regular or linked file: {path}")
            relative = path.relative_to(root).as_posix()
            result[relative] = path.read_bytes()
    return result

left = inventory(published, True)
right = inventory(rebuilt, False)
if left.keys() != right.keys():
    raise SystemExit(f"signed publication inventory differs from deterministic rebuild: {sorted(left)} != {sorted(right)}")
for name in left:
    if left[name] != right[name]:
        raise SystemExit(f"signed publication file differs from deterministic rebuild: {name}")
PY

identity_json="${temporary}/release-identity.json"
"${admin}" "${identity_args[@]}" > "${identity_json}"
python3 - "${identity_json}" "${expected_tag}" "${expected_commit}" <<'PYIDENTITY'
import json
import pathlib
import sys

value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if value.get("tag") != sys.argv[2]:
    raise SystemExit(f"signed release tag {value.get('tag')!r} does not match {sys.argv[2]!r}")
if value.get("commit") != sys.argv[3]:
    raise SystemExit(f"signed release commit {value.get('commit')!r} does not match {sys.argv[3]!r}")
PYIDENTITY
if [[ "${asset_dir}" = "-" ]]; then
  cat "${identity_json}"
else
  "${admin}" "${verify_args[@]}"
fi
