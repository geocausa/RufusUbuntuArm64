#!/usr/bin/env python3
"""Validate an immutable published GitHub release and its downloaded assets."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import NoReturn

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def read_version() -> str:
    version = Path("VERSION").read_text(encoding="utf-8").strip()
    if not version or any(char.isspace() for char in version):
        fail("VERSION must contain one non-empty token")
    return version


def expected_names(version: str) -> tuple[str, ...]:
    return (
        f"RufusArm64-{version}-source.zip",
        f"RufusArm64-{version}-uefi-md5sum-v1.2-source.tar.gz",
        f"RufusArm64-{version}-uefi-md5sum-v1.2-source.tar.gz.sha256",
        f"RufusArm64-{version}-wimlib-1.14.5-source.tar.gz",
        f"rufusarm64_{version}_arm64.deb",
        f"rufusarm64_{version}_arm64.deb.sha256",
    )


def expected_primary_names(version: str) -> tuple[str, ...]:
    return (
        f"rufusarm64_{version}_arm64.deb",
        f"RufusArm64-{version}-source.zip",
        f"RufusArm64-{version}-wimlib-1.14.5-source.tar.gz",
        f"RufusArm64-{version}-uefi-md5sum-v1.2-source.tar.gz",
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_asset_directory(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        fail(f"downloaded asset directory does not exist: {path}")
    if not stat.S_ISDIR(info.st_mode):
        fail(f"downloaded asset path is not a directory: {path}")


def require_regular_file(path: Path) -> os.stat_result:
    try:
        info = path.lstat()
    except FileNotFoundError:
        fail(f"missing published asset: {path.name}")
    if not stat.S_ISREG(info.st_mode):
        fail(f"published asset is not a regular file: {path.name}")
    return info


def parse_checksum_file(path: Path, expected: tuple[str, ...]) -> dict[str, str]:
    require_regular_file(path)
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except UnicodeDecodeError as exc:
        fail(f"{path.name}: checksum file is not ASCII: {exc}")
    result: dict[str, str] = {}
    for line_number, raw in enumerate(lines, 1):
        match = re.fullmatch(r"([0-9a-f]{64})  ([^/\\\x00-\x1f\x7f]+)", raw)
        if not match:
            fail(f"{path.name}:{line_number}: malformed SHA-256 record")
        digest, name = match.groups()
        if name in result:
            fail(f"{path.name}: duplicate checksum record for {name}")
        result[name] = digest
    if tuple(result) != expected:
        fail(
            f"{path.name}: checksum inventory mismatch: "
            f"expected {list(expected)!r}, got {list(result)!r}"
        )
    return result


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        fail(f"usage: {argv[0]} RELEASE_JSON DOWNLOADED_ASSET_DIRECTORY")

    version = read_version()
    tag = f"v{version}"
    metadata_path = Path(argv[1])
    asset_dir = Path(argv[2])
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))

    if not isinstance(metadata, dict):
        fail("release metadata must be a JSON object")
    if metadata.get("tagName") != tag:
        fail(f"release tag {metadata.get('tagName')!r} does not match {tag!r}")
    if metadata.get("isDraft") is not False:
        fail("release must not be a draft")
    if metadata.get("isPrerelease") is not False:
        fail("canonical release must not be a prerelease")
    if not metadata.get("publishedAt"):
        fail("release has no publication timestamp")
    expected_release_url = f"https://github.com/geocausa/RufusUbuntuArm64/releases/tag/{tag}"
    if metadata.get("url") != expected_release_url:
        fail(f"release URL does not match {expected_release_url!r}")

    assets = metadata.get("assets")
    if not isinstance(assets, list):
        fail("release assets must be a JSON array")
    expected = expected_names(version)
    by_name: dict[str, dict[str, object]] = {}
    for asset in assets:
        if not isinstance(asset, dict):
            fail("release asset metadata must be an object")
        name = asset.get("name")
        if not isinstance(name, str) or name in by_name:
            fail(f"invalid or duplicate release asset name: {name!r}")
        by_name[name] = asset
    if tuple(sorted(by_name)) != tuple(sorted(expected)):
        fail(
            "published asset inventory mismatch: "
            f"expected {sorted(expected)!r}, got {sorted(by_name)!r}"
        )

    require_asset_directory(asset_dir)
    downloaded = tuple(sorted(entry.name for entry in asset_dir.iterdir()))
    if downloaded != tuple(sorted(expected)):
        fail(
            "downloaded asset inventory mismatch: "
            f"expected {sorted(expected)!r}, got {list(downloaded)!r}"
        )

    for name in expected:
        asset = by_name[name]
        if asset.get("state") != "uploaded":
            fail(f"release asset is not uploaded: {name}")
        size = asset.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            fail(f"release asset has invalid size: {name}")
        digest_value = asset.get("digest")
        if not isinstance(digest_value, str) or not digest_value.startswith("sha256:"):
            fail(f"release asset has no SHA-256 digest: {name}")
        digest = digest_value.removeprefix("sha256:")
        if not SHA256_RE.fullmatch(digest):
            fail(f"release asset has malformed SHA-256 digest: {name}")
        expected_url = (
            f"https://github.com/geocausa/RufusUbuntuArm64/releases/download/{tag}/{name}"
        )
        if asset.get("url") != expected_url:
            fail(f"release asset URL mismatch for {name}")

        path = asset_dir / name
        info = require_regular_file(path)
        if info.st_size != size:
            fail(f"release asset size mismatch for {name}: metadata={size}, file={info.st_size}")
        if sha256_file(path) != digest:
            fail(f"release asset digest mismatch for {name}")

    package_sidecar = asset_dir / f"rufusarm64_{version}_arm64.deb.sha256"
    package_records = parse_checksum_file(package_sidecar, expected_primary_names(version))
    for name, digest in package_records.items():
        if sha256_file(asset_dir / name) != digest:
            fail(f"published checksum mismatch for {name}")

    loader_name = f"RufusArm64-{version}-uefi-md5sum-v1.2-source.tar.gz"
    loader_sidecar = asset_dir / f"{loader_name}.sha256"
    loader_records = parse_checksum_file(loader_sidecar, (loader_name,))
    if sha256_file(asset_dir / loader_name) != loader_records[loader_name]:
        fail(f"published checksum mismatch for {loader_name}")

    print(f"Published release {tag} has the exact verified six-asset contract.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
