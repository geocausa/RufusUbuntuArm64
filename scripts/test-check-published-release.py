#!/usr/bin/env python3
"""Regression tests for the published-release asset contract."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check-published-release.py"
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
TAG = f"v{VERSION}"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class PublishedReleaseContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.assets = self.root / "assets"
        self.assets.mkdir()
        self.metadata_path = self.root / "release.json"
        self.package = f"rufusarm64_{VERSION}_arm64.deb"
        self.source = f"RufusArm64-{VERSION}-source.zip"
        self.wim_source = f"RufusArm64-{VERSION}-wimlib-1.14.5-source.tar.gz"
        self.loader_source = f"RufusArm64-{VERSION}-uefi-md5sum-v1.2-source.tar.gz"
        self.package_sidecar = f"{self.package}.sha256"
        self.loader_sidecar = f"{self.loader_source}.sha256"
        self.primary_names = (
            self.package,
            self.source,
            self.wim_source,
            self.loader_source,
        )
        payloads = {
            self.package: b"arm64 package\n",
            self.source: b"project source\n",
            self.wim_source: b"wimlib corresponding source\n",
            self.loader_source: b"uefi-md5sum corresponding source\n",
        }
        for name, data in payloads.items():
            (self.assets / name).write_bytes(data)
        package_records = "".join(
            f"{digest(payloads[name])}  {name}\n" for name in self.primary_names
        )
        (self.assets / self.package_sidecar).write_text(package_records, encoding="ascii")
        (self.assets / self.loader_sidecar).write_text(
            f"{digest(payloads[self.loader_source])}  {self.loader_source}\n",
            encoding="ascii",
        )
        self.metadata = self.build_metadata()
        self.write_metadata()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def build_metadata(self) -> dict[str, object]:
        asset_entries = []
        for path in sorted(self.assets.iterdir(), key=lambda value: value.name):
            data = path.read_bytes()
            asset_entries.append(
                {
                    "name": path.name,
                    "size": len(data),
                    "state": "uploaded",
                    "digest": f"sha256:{digest(data)}",
                    "url": (
                        "https://github.com/geocausa/RufusUbuntuArm64/"
                        f"releases/download/{TAG}/{path.name}"
                    ),
                }
            )
        return {
            "tagName": TAG,
            "targetCommitish": "main",
            "isDraft": False,
            "isPrerelease": False,
            "publishedAt": "2026-07-18T12:05:00Z",
            "url": f"https://github.com/geocausa/RufusUbuntuArm64/releases/tag/{TAG}",
            "assets": asset_entries,
        }

    def write_metadata(self) -> None:
        self.metadata_path.write_text(
            json.dumps(self.metadata, sort_keys=True), encoding="utf-8"
        )

    def run_validator(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(self.metadata_path), str(self.assets)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def assert_failure(self, message: str) -> None:
        result = self.run_validator()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(message, result.stderr + result.stdout)

    def refresh_asset_metadata(self, name: str) -> None:
        path = self.assets / name
        data = path.read_bytes()
        for asset in self.metadata["assets"]:  # type: ignore[index]
            if asset["name"] == name:
                asset["size"] = len(data)
                asset["digest"] = f"sha256:{digest(data)}"
                break
        else:
            self.fail(f"missing fixture metadata for {name}")
        self.write_metadata()

    def test_valid_release_passes(self) -> None:
        result = self.run_validator()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("exact verified six-asset contract", result.stdout)

    def test_missing_metadata_asset_fails(self) -> None:
        self.metadata["assets"] = self.metadata["assets"][:-1]  # type: ignore[index]
        self.write_metadata()
        self.assert_failure("published asset inventory mismatch")

    def test_extra_metadata_asset_fails(self) -> None:
        extra = copy.deepcopy(self.metadata["assets"][0])  # type: ignore[index]
        extra["name"] = "unexpected.bin"
        extra["url"] = (
            "https://github.com/geocausa/RufusUbuntuArm64/"
            f"releases/download/{TAG}/unexpected.bin"
        )
        self.metadata["assets"].append(extra)  # type: ignore[index]
        self.write_metadata()
        self.assert_failure("published asset inventory mismatch")

    def test_malformed_metadata_digest_fails(self) -> None:
        self.metadata["assets"][0]["digest"] = "sha256:not-a-digest"  # type: ignore[index]
        self.write_metadata()
        self.assert_failure("malformed SHA-256 digest")

    def test_downloaded_asset_substitution_fails(self) -> None:
        (self.assets / self.package).write_bytes(b"substituted package\n")
        self.assert_failure(f"release asset size mismatch for {self.package}")

    def test_malformed_checksum_record_fails(self) -> None:
        (self.assets / self.loader_sidecar).write_text(
            "not a checksum record\n", encoding="ascii"
        )
        self.refresh_asset_metadata(self.loader_sidecar)
        self.assert_failure("malformed SHA-256 record")

    def test_sidecar_checksum_mismatch_fails(self) -> None:
        records = (self.assets / self.package_sidecar).read_text(encoding="ascii")
        records = records.replace(
            records.splitlines()[0].split()[0], "0" * 64, 1
        )
        (self.assets / self.package_sidecar).write_text(records, encoding="ascii")
        self.refresh_asset_metadata(self.package_sidecar)
        self.assert_failure(f"published checksum mismatch for {self.package}")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_symlink_asset_fails(self) -> None:
        package_path = self.assets / self.package
        target = self.assets / "package-target"
        package_path.rename(target)
        package_path.symlink_to(target.name)
        self.assert_failure(f"published asset is not a regular file: {self.package}")


if __name__ == "__main__":
    unittest.main()
