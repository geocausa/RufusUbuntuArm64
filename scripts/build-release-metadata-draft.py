#!/usr/bin/env python3
"""Build a strict offline-signable release metadata draft from staged assets."""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import NoReturn

REPOSITORY = "geocausa/RufusUbuntuArm64"
PRODUCT = "RufusArm64"
MAX_ASSET_BYTES = 8 * 1024 * 1024 * 1024
MAX_SIDECAR_BYTES = 64 * 1024
VERSION_RE = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def parse_time(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        fail(f"invalid {label} timestamp: {exc}")
    if parsed.tzinfo is None:
        fail(f"{label} timestamp must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def expected_names(version: str) -> tuple[str, ...]:
    return tuple(
        sorted(
            (
                f"RufusArm64-{version}-source.zip",
                f"RufusArm64-{version}-uefi-md5sum-v1.2-source.tar.gz",
                f"RufusArm64-{version}-uefi-md5sum-v1.2-source.tar.gz.sha256",
                f"RufusArm64-{version}-wimlib-1.14.5-source.tar.gz",
                f"rufusarm64_{version}_arm64.deb",
                f"rufusarm64_{version}_arm64.deb.sha256",
            )
        )
    )


def read_asset(directory_fd: int, name: str) -> tuple[os.stat_result, str, bytes | None]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except OSError as exc:
        fail(f"cannot open release asset {name}: {exc}")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            fail(f"release asset is not a single-link regular file: {name}")
        if before.st_size <= 0 or before.st_size > MAX_ASSET_BYTES:
            fail(f"release asset size is invalid: {name}")
        collect = name.endswith(".sha256")
        if collect and before.st_size > MAX_SIDECAR_BYTES:
            fail(f"release checksum sidecar is too large: {name}")

        digest = hashlib.sha256()
        collected = bytearray() if collect else None
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            if collected is not None:
                collected.extend(chunk)

        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_after != identity_before:
            fail(f"release asset changed while hashing: {name}")
        return before, digest.hexdigest(), bytes(collected) if collected is not None else None
    finally:
        os.close(descriptor)


def parse_checksum_file(name: str, data: bytes) -> dict[str, str]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        fail(f"non-ASCII SHA-256 sidecar {name}: {exc}")
    records: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), 1):
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._+-]+)", line)
        if match is None:
            fail(f"malformed SHA-256 record in {name}:{line_number}")
        digest, asset_name = match.groups()
        if asset_name in records:
            fail(f"duplicate SHA-256 record for {asset_name} in {name}")
        records[asset_name] = digest
    if not records:
        fail(f"empty SHA-256 sidecar: {name}")
    return records


def verify_sidecars(version: str, digests: dict[str, str], sidecars: dict[str, bytes]) -> None:
    package = f"rufusarm64_{version}_arm64.deb"
    source = f"RufusArm64-{version}-source.zip"
    wim_source = f"RufusArm64-{version}-wimlib-1.14.5-source.tar.gz"
    loader_source = f"RufusArm64-{version}-uefi-md5sum-v1.2-source.tar.gz"
    package_sidecar = f"{package}.sha256"
    loader_sidecar = f"{loader_source}.sha256"

    package_records = parse_checksum_file(package_sidecar, sidecars[package_sidecar])
    expected_package_records = {package, source, wim_source, loader_source}
    if set(package_records) != expected_package_records:
        fail("package SHA-256 sidecar does not bind the exact four primary assets")
    for name in sorted(expected_package_records):
        if package_records[name] != digests[name]:
            fail(f"package SHA-256 sidecar mismatch for {name}")

    loader_records = parse_checksum_file(loader_sidecar, sidecars[loader_sidecar])
    if loader_records != {loader_source: digests[loader_source]}:
        fail("uefi-md5sum source SHA-256 sidecar mismatch")


def read_staged_assets(asset_dir: Path, version: str) -> tuple[tuple[str, ...], dict[str, int], dict[str, str]]:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        directory_fd = os.open(asset_dir, flags)
    except OSError as exc:
        fail(f"asset directory must be a real directory: {exc}")
    try:
        directory_info = os.fstat(directory_fd)
        if directory_info.st_uid != os.geteuid() or directory_info.st_mode & 0o022:
            fail("asset directory must be owned by the current user and not group/world writable")

        expected = expected_names(version)
        actual = tuple(sorted(os.listdir(directory_fd)))
        if actual != expected:
            fail(f"release asset inventory mismatch: expected {list(expected)}, got {list(actual)}")

        digests: dict[str, str] = {}
        sizes: dict[str, int] = {}
        sidecars: dict[str, bytes] = {}
        for name in expected:
            info, digest, sidecar = read_asset(directory_fd, name)
            sizes[name] = info.st_size
            digests[name] = digest
            if sidecar is not None:
                sidecars[name] = sidecar
            if SHA256_RE.fullmatch(digest) is None:
                fail(f"internal SHA-256 failure for {name}")
        verify_sidecars(version, digests, sidecars)
        return expected, sizes, digests
    finally:
        os.close(directory_fd)


def build_draft(args: argparse.Namespace) -> dict[str, object]:
    if VERSION_RE.fullmatch(args.version) is None:
        fail("version must be strict MAJOR.MINOR.PATCH text")
    if COMMIT_RE.fullmatch(args.commit) is None:
        fail("commit must be a lowercase 40-character hexadecimal value")
    if args.metadata_version <= 0:
        fail("metadata version must be positive")
    if args.channel not in ("stable", "prerelease"):
        fail("channel must be stable or prerelease")
    generated = parse_time(args.generated, "generated")
    expires = parse_time(args.expires, "expires")
    if expires <= generated:
        fail("release expiry must follow generation time")
    if expires - generated > timedelta(days=45):
        fail("release metadata lifetime exceeds 45 days")

    expected, sizes, digests = read_staged_assets(Path(args.asset_dir), args.version)
    tag = f"v{args.version}"
    assets = [
        {
            "name": name,
            "size": sizes[name],
            "sha256": digests[name],
            "url": f"https://github.com/{REPOSITORY}/releases/download/{tag}/{name}",
            "redirect_hosts": ["objects.githubusercontent.com"],
        }
        for name in expected
    ]
    return {
        "_type": "release",
        "schema": 1,
        "version": args.metadata_version,
        "generated": generated.isoformat().replace("+00:00", "Z"),
        "expires": expires.isoformat().replace("+00:00", "Z"),
        "product": PRODUCT,
        "repository": REPOSITORY,
        "release_version": args.version,
        "tag": tag,
        "commit": args.commit,
        "channel": args.channel,
        "assets": assets,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--asset-dir", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--metadata-version", required=True, type=int)
    parser.add_argument("--generated", required=True)
    parser.add_argument("--expires", required=True)
    parser.add_argument("--channel", choices=("stable", "prerelease"), required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    draft = build_draft(args)
    output = Path(args.output)
    if output.exists() or output.is_symlink():
        fail(f"refusing existing output: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.tmp-{os.getpid()}")
    try:
        with temporary.open("x", encoding="utf-8") as handle:
            os.chmod(temporary, 0o600)
            json.dump(draft, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    print(f"Wrote unsigned release metadata draft: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
