#!/usr/bin/env bash
set -euo pipefail

ENGINE="${1:-}"
[[ -x "${ENGINE}" ]] || {
  echo "Usage: $0 /path/to/wimlib-imagex" >&2
  exit 1
}
for command in mkfs.ntfs ntfsfix ntfscat ntfsls sha256sum; do
  command -v "${command}" >/dev/null 2>&1 || {
    echo "Missing direct-NTFS test program: ${command}" >&2
    exit 1
  }
done

work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT
source_dir="${work_dir}/source"
mkdir -p "${source_dir}/sub"
printf 'rufusarm64-direct-ntfs\n' > "${source_dir}/sub/file.txt"
ln "${source_dir}/sub/file.txt" "${source_dir}/hardlink.txt"
ln -s sub/file.txt "${source_dir}/link.txt"

"${ENGINE}" capture "${source_dir}" "${work_dir}/sample.wim" TEST \
  --compress=none >/dev/null
truncate -s 128M "${work_dir}/target.ntfs"
mkfs.ntfs -F -Q -L WIMTEST "${work_dir}/target.ntfs" >/dev/null
apply_output="$("${ENGINE}" apply "${work_dir}/sample.wim" 1 "${work_dir}/target.ntfs" 2>&1)"
printf '%s\n' "${apply_output}"
grep -Fq 'to NTFS volume' <<< "${apply_output}"
grep -Fq 'Done applying WIM image.' <<< "${apply_output}"
ntfsfix -n "${work_dir}/target.ntfs" >/dev/null

expected_hash="$(sha256sum "${source_dir}/sub/file.txt" | awk '{print $1}')"
actual_hash="$(ntfscat "${work_dir}/target.ntfs" /sub/file.txt | sha256sum | awk '{print $1}')"
[[ "${actual_hash}" == "${expected_hash}" ]]
actual_hardlink_hash="$(ntfscat "${work_dir}/target.ntfs" /hardlink.txt | sha256sum | awk '{print $1}')"
[[ "${actual_hardlink_hash}" == "${expected_hash}" ]]
listing="$(ntfsls -i -l -p / "${work_dir}/target.ntfs")"
printf '%s\n' "${listing}"
file_inode="$(awk '$NF == "sub" {next} $NF == "hardlink.txt" {print $1}' <<< "${listing}")"
[[ -n "${file_inode}" ]]
ntfsls -i -l -p /sub "${work_dir}/target.ntfs" | awk -v inode="${file_inode}" '$NF == "file.txt" && $1 == inode {found=1} END {exit !found}'

printf '%s\n' 'Direct NTFS-volume WIM apply smoke test passed.'
