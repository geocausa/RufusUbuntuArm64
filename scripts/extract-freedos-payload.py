#!/usr/bin/env python3
"""Reproduce and verify the minimal Rufus FreeDOS 1.4 payload.

The write mode accepts a locally supplied official FD14-FullUSB.zip. It never
fetches network content. Check mode validates only repository files.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PAYLOAD_DIR = ROOT / "internal" / "freedos" / "payload"
VENDOR_DIR = ROOT / "vendor" / "freedos"
SOURCE_DIR = VENDOR_DIR / "source"
METADATA_DIR = VENDOR_DIR / "metadata"
MANIFEST_PATH = VENDOR_DIR / "PAYLOADS.json"

FULLUSB_SHA256 = "cd440cd165f5a8a184870cb615f525af182660c15f9bcf1e9d198ca19cedcaff"
IMAGE_MEMBER = "FD14FULL.img"
SECTOR_SIZE = 512
PARTITION_START_SECTOR = 63
FORCELBA_OFFSET = 0x0D
FORCELBA_VALUE = 0x01
RUFUS_COMMIT = "6d8fbf98305ff37eb531c45cbd6ff44563c53917"
KERNEL_SOURCE_COMMIT = "d6791add2043c9d7b584d840a8ffaf8829fd2bdc"
FREECOM_SOURCE_COMMIT = "04fc21a9f6792abe9048598e8f2d048b4f6cd0e5"

PACKAGE_RECORDS = {
    "freecom.zip": {
        "image_path": "PACKAGES/BASE/FREECOM.ZIP",
        "size": 2_037_468,
        "sha256": "2529cf15c2ee7d7030ed99a6a88df2cf5eef87b9fe10f1c0fb643c38ea6aaa8e",
    },
    "kernel.zip": {
        "image_path": "PACKAGES/BASE/KERNEL.ZIP",
        "size": 772_721,
        "sha256": "38ce3c63e399c8f18ab6230d8988a5d1a1aa9be4e109d15c6f4842b5e8fe61e6",
    },
}

FILE_RECORDS = {
    "COMMAND.COM": {
        "path": "internal/freedos/payload/COMMAND.COM",
        "package": "freecom.zip",
        "member": "BIN/COMMAND.COM",
        "size": 87_772,
        "sha256": "077808379e896476f7f69d62e6c8989d8fc23e8ef58d1c8492db1ac106784107",
        "git_blob_sha1": "255525acc562e0411e3e5f000bc1ba788733056d",
    },
    "KERNL386.SYS": {
        "path": "internal/freedos/payload/KERNL386.SYS",
        "package": "kernel.zip",
        "member": "BIN/KERNL386.SYS",
        "size": 46_256,
        "sha256": "932c0c155701eddb7b902f7269a1b2ce31f5c82a6dc195172f2336d18a74e1fb",
        "git_blob_sha1": "bfe7cdfe616dc71ded366bc57fa8c370a548faa6",
        "force_lba_value": 0,
    },
    "KERNEL.SYS": {
        "path": "internal/freedos/payload/KERNEL.SYS",
        "derived_from": "KERNL386.SYS",
        "size": 46_256,
        "sha256": "57504a0d5e1d57a0407d995e77fcebb9627da2c0dbe0f1cbf7c5fa901d2efc6c",
        "git_blob_sha1": "6b524a99481f2286a5ddcb06c4fbccfe2bc5cfbd",
        "force_lba_value": FORCELBA_VALUE,
    },
    "freecom-sources.zip": {
        "path": "vendor/freedos/source/freecom-sources.zip",
        "package": "freecom.zip",
        "member": "SOURCE/FREECOM/SOURCES.ZIP",
        "size": 1_236_304,
        "sha256": "beef029a2268cac4dd5b729a649ea4e23f30c9cfee1788c4bbd64b4d4ddb093b",
        "git_blob_sha1": "ae07a929c0ee7e29fd4e0a986186eddb4784d167",
        "member_count": 825,
        "required_members": ["license"],
    },
    "kernel-sources.zip": {
        "path": "vendor/freedos/source/kernel-sources.zip",
        "package": "kernel.zip",
        "member": "SOURCE/KERNEL/SOURCES.ZIP",
        "size": 539_853,
        "sha256": "fda372721899e6a9cabbfa6beed259be19dafd0fe16d90b8f4da1a9397fde574",
        "git_blob_sha1": "189e2d1e2264f1649c67e3e52cd00d3466c58a6a",
        "member_count": 196,
        "required_members": ["COPYING"],
    },
    "FREECOM.LSM": {
        "path": "vendor/freedos/metadata/FREECOM.LSM",
        "package": "freecom.zip",
        "member": "APPINFO/FREECOM.LSM",
        "size": 585,
        "sha256": "0c370cb1cbbc41d775a478ce88baf2b01cca24c8a7311f4b1f4d094de2cd29d2",
        "git_blob_sha1": "9d3ff146e410c383030c03eee2ddd679f9a22e29",
    },
    "KERNEL.LSM": {
        "path": "vendor/freedos/metadata/KERNEL.LSM",
        "package": "kernel.zip",
        "member": "APPINFO/KERNEL.LSM",
        "size": 970,
        "sha256": "fcf0314885a8a4d5f82ecea0a82e81cafbd017a43959ed1de5c7e14011b2351e",
        "git_blob_sha1": "bc7d1d7ee4530a4aa481b9ec3dc5752a6a8e5d9a",
    },
    "KERNEL-COPYING": {
        "path": "vendor/freedos/metadata/KERNEL-COPYING",
        "package": "kernel.zip",
        "member": "DOC/KERNEL/COPYING",
        "size": 18_330,
        "sha256": "2ec21c4f10e9fc6bafbc619cf905424162a0b6443e482d599a6d0d7718e9ae58",
        "git_blob_sha1": "c478510e039a94aafa5f13cbac01dc6c31c3431e",
    },
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_blob_sha1(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()  # noqa: S324 - Git object identity


def canonical_manifest() -> dict[str, object]:
    return {
        "schema": 1,
        "distribution": "FreeDOS 1.4 FullUSB",
        "archive": {
            "name": "FD14-FullUSB.zip",
            "sha256": FULLUSB_SHA256,
        },
        "disk_image": {
            "member": IMAGE_MEMBER,
            "logical_sector_size": SECTOR_SIZE,
            "partition_start_sector": PARTITION_START_SECTOR,
        },
        "packages": PACKAGE_RECORDS,
        "files": FILE_RECORDS,
        "kernel_patch": {
            "offset": FORCELBA_OFFSET,
            "original_value": 0,
            "patched_value": FORCELBA_VALUE,
            "all_other_bytes_preserved": True,
        },
        "upstream": {
            "rufus_commit": RUFUS_COMMIT,
            "kernel_source_commit": KERNEL_SOURCE_COMMIT,
            "freecom_source_commit": FREECOM_SOURCE_COMMIT,
        },
        "scope": "provenance and ordinary-file validation only; no device operation is authorized",
    }


def require_record(name: str, data: bytes) -> None:
    record = FILE_RECORDS[name]
    if len(data) != record["size"]:
        raise SystemExit(f"{name}: expected {record['size']} bytes, got {len(data)}")
    if sha256(data) != record["sha256"]:
        raise SystemExit(f"{name}: SHA-256 does not match the reviewed record")
    if git_blob_sha1(data) != record["git_blob_sha1"]:
        raise SystemExit(f"{name}: Git blob identity does not match the reviewed record")


def read_member(archive: Path, member: str) -> bytes:
    with zipfile.ZipFile(archive) as handle:
        by_upper = {name.upper(): name for name in handle.namelist()}
        actual = by_upper.get(member.upper())
        if actual is None:
            raise SystemExit(f"missing {member} in {archive.name}")
        return handle.read(actual)


def validate_source_archive(name: str, data: bytes) -> None:
    record = FILE_RECORDS[name]
    with zipfile.ZipFile(io.BytesIO(data)) as handle:
        members = handle.namelist()
    if len(members) != record["member_count"]:
        raise SystemExit(f"{name}: unexpected source member count {len(members)}")
    members_upper = {member.upper() for member in members}
    for required in record["required_members"]:
        if required.upper() not in members_upper:
            raise SystemExit(f"{name}: missing required source member {required}")


def validate_payload_pair(original: bytes, patched: bytes) -> None:
    require_record("KERNL386.SYS", original)
    require_record("KERNEL.SYS", patched)
    if original[FORCELBA_OFFSET] != 0:
        raise SystemExit("KERNL386.SYS has an unexpected original FORCELBA value")
    if patched[FORCELBA_OFFSET] != FORCELBA_VALUE:
        raise SystemExit("KERNEL.SYS does not enable FORCELBA")
    differences = [index for index, pair in enumerate(zip(original, patched)) if pair[0] != pair[1]]
    if differences != [FORCELBA_OFFSET]:
        raise SystemExit(f"kernel derivation changed unexpected byte offsets: {differences[:16]}")


def check_repository() -> None:
    if not MANIFEST_PATH.is_file():
        raise SystemExit(f"missing {MANIFEST_PATH.relative_to(ROOT)}")
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    if manifest != canonical_manifest():
        raise SystemExit("FreeDOS payload manifest does not match the reviewed contract")

    loaded: dict[str, bytes] = {}
    for name, record in FILE_RECORDS.items():
        path = ROOT / record["path"]
        if not path.is_file():
            raise SystemExit(f"missing {path.relative_to(ROOT)}")
        data = path.read_bytes()
        require_record(name, data)
        loaded[name] = data
        if name.endswith("-sources.zip"):
            validate_source_archive(name, data)

    freecom_license_path = METADATA_DIR / "FREECOM-LICENSE"
    if not freecom_license_path.is_file():
        raise SystemExit("missing vendor/freedos/metadata/FREECOM-LICENSE")
    with zipfile.ZipFile(io.BytesIO(loaded["freecom-sources.zip"])) as handle:
        expected_freecom_license = handle.read("license")
    if freecom_license_path.read_bytes() != expected_freecom_license:
        raise SystemExit("FreeCOM licence text differs from the pinned source archive")

    validate_payload_pair(loaded["KERNL386.SYS"], loaded["KERNEL.SYS"])
    if b"GNU General Public License, Version 2" not in loaded["FREECOM.LSM"]:
        raise SystemExit("FreeCOM package metadata lost its GPLv2 declaration")
    if b"GNU General Public License, Version 2" not in loaded["KERNEL.LSM"]:
        raise SystemExit("kernel package metadata lost its GPLv2 declaration")
    if b"GNU GENERAL PUBLIC LICENSE" not in loaded["KERNEL-COPYING"]:
        raise SystemExit("kernel GPL text is not recognizable")


def verify_package(path: Path, name: str) -> None:
    data = path.read_bytes()
    record = PACKAGE_RECORDS[name]
    if len(data) != record["size"] or sha256(data) != record["sha256"]:
        raise SystemExit(f"{name}: package bytes do not match the official FullUSB record")


def extract_from_archive(archive: Path) -> dict[str, bytes]:
    if shutil.which("mcopy") is None:
        raise SystemExit("mcopy is required to extract packages from the FullUSB image")
    if sha256_path(archive) != FULLUSB_SHA256:
        raise SystemExit("FD14-FullUSB.zip SHA-256 does not match the official release")

    with tempfile.TemporaryDirectory(prefix="rufusarm64-freedos-") as directory:
        temporary = Path(directory)
        with zipfile.ZipFile(archive) as handle:
            names = {name.upper(): name for name in handle.namelist()}
            actual_image = names.get(IMAGE_MEMBER.upper())
            if actual_image is None:
                raise SystemExit(f"official archive does not contain {IMAGE_MEMBER}")
            image = temporary / IMAGE_MEMBER
            with handle.open(actual_image) as source, image.open("wb") as destination:
                shutil.copyfileobj(source, destination)

        with image.open("rb") as handle:
            mbr = handle.read(SECTOR_SIZE)
        if len(mbr) != SECTOR_SIZE or mbr[510:512] != b"\x55\xaa":
            raise SystemExit("FullUSB image has an invalid MBR")
        first = mbr[446:462]
        if first[0] != 0x80 or first[4] not in (0x0B, 0x0C):
            raise SystemExit("FullUSB image first partition is not active FAT32")
        start_sector = struct.unpack_from("<I", first, 8)[0]
        if start_sector != PARTITION_START_SECTOR:
            raise SystemExit(f"unexpected FullUSB partition start sector {start_sector}")
        image_spec = f"{image}@@{SECTOR_SIZE * start_sector}"

        packages: dict[str, Path] = {}
        for name, record in PACKAGE_RECORDS.items():
            destination = temporary / name
            subprocess.run(
                ["mcopy", "-i", image_spec, f"::/{record['image_path']}", str(destination)],
                check=True,
                env={**os.environ, "MTOOLS_SKIP_CHECK": "1"},
            )
            verify_package(destination, name)
            packages[name] = destination

        output: dict[str, bytes] = {}
        for name, record in FILE_RECORDS.items():
            if name == "KERNEL.SYS":
                continue
            data = read_member(packages[record["package"]], record["member"])
            require_record(name, data)
            output[name] = data
            if name.endswith("-sources.zip"):
                validate_source_archive(name, data)

        patched = bytearray(output["KERNL386.SYS"])
        patched[FORCELBA_OFFSET] = FORCELBA_VALUE
        output["KERNEL.SYS"] = bytes(patched)
        validate_payload_pair(output["KERNL386.SYS"], output["KERNEL.SYS"])
        return output


def write_repository(files: dict[str, bytes]) -> None:
    for name, data in files.items():
        path = ROOT / FILE_RECORDS[name]["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    with zipfile.ZipFile(io.BytesIO(files["freecom-sources.zip"])) as handle:
        freecom_license = handle.read("license")
    METADATA_DIR.mkdir(parents=True, exist_ok=True)
    (METADATA_DIR / "FREECOM-LICENSE").write_bytes(freecom_license)
    VENDOR_DIR.mkdir(parents=True, exist_ok=True)
    MANIFEST_PATH.write_text(
        json.dumps(canonical_manifest(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    check_repository()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, help="local official FD14-FullUSB.zip")
    parser.add_argument("--write", action="store_true", help="write reviewed repository assets")
    parser.add_argument("--check", action="store_true", help="validate repository assets")
    args = parser.parse_args()
    if args.write and args.archive is None:
        parser.error("--write requires --archive")
    if not args.write and not args.check:
        parser.error("select --write and/or --check")
    return args


def main() -> None:
    args = parse_args()
    if args.write:
        files = extract_from_archive(args.archive.resolve())
        write_repository(files)
    if args.check:
        check_repository()


if __name__ == "__main__":
    main()
