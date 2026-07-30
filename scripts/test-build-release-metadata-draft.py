#!/usr/bin/env python3
"""Regression tests for deterministic release metadata draft generation."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build-release-metadata-draft.py"
VERSION = "0.16.0"
COMMIT = "a" * 40


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class ReleaseMetadataDraftTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.assets = self.root / "assets"
        self.assets.mkdir()
        self.assets.chmod(0o700)
        self.output = self.root / "release-draft.json"
        self.package = f"rufusarm64_{VERSION}_arm64.deb"
        self.source = f"RufusArm64-{VERSION}-source.zip"
        self.wim = f"RufusArm64-{VERSION}-wimlib-1.14.5-source.tar.gz"
        self.loader = f"RufusArm64-{VERSION}-uefi-md5sum-v1.2-source.tar.gz"
        self.payloads = {
            self.package: b"package\n",
            self.source: b"source\n",
            self.wim: b"wim source\n",
            self.loader: b"loader source\n",
        }
        for name, data in self.payloads.items():
            (self.assets / name).write_bytes(data)
        (self.assets / f"{self.package}.sha256").write_text(
            "".join(f"{digest(self.payloads[name])}  {name}\n" for name in (self.package, self.source, self.wim, self.loader)),
            encoding="ascii",
        )
        (self.assets / f"{self.loader}.sha256").write_text(
            f"{digest(self.payloads[self.loader])}  {self.loader}\n", encoding="ascii"
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_generator(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--asset-dir", str(self.assets),
                "--version", VERSION,
                "--commit", COMMIT,
                "--metadata-version", "7",
                "--generated", "2026-07-30T14:00:00Z",
                "--expires", "2026-08-06T14:00:00Z",
                "--channel", "stable",
                "--output", str(self.output),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def assert_failure(self, message: str) -> None:
        result = self.run_generator()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(message, result.stderr + result.stdout)

    def test_valid_exact_inventory_is_deterministic(self) -> None:
        first = self.run_generator()
        self.assertEqual(first.returncode, 0, first.stderr)
        data = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(data["version"], 7)
        self.assertEqual(data["release_version"], VERSION)
        self.assertEqual(data["tag"], f"v{VERSION}")
        self.assertEqual(data["commit"], COMMIT)
        names = [asset["name"] for asset in data["assets"]]
        self.assertEqual(names, sorted(names))
        package = next(asset for asset in data["assets"] if asset["name"] == self.package)
        self.assertEqual(package["sha256"], digest(self.payloads[self.package]))
        self.assertEqual(package["url"], f"https://github.com/geocausa/RufusUbuntuArm64/releases/download/v{VERSION}/{self.package}")

    def test_extra_asset_is_refused(self) -> None:
        (self.assets / "unexpected.bin").write_bytes(b"extra")
        self.assert_failure("release asset inventory mismatch")

    def test_sidecar_substitution_is_refused(self) -> None:
        sidecar = self.assets / f"{self.package}.sha256"
        sidecar.write_text(sidecar.read_text(encoding="ascii").replace(digest(self.payloads[self.package]), "0" * 64, 1), encoding="ascii")
        self.assert_failure(f"package SHA-256 sidecar mismatch for {self.package}")

    def test_symlink_asset_is_refused(self) -> None:
        target = self.root / "package-target"
        package = self.assets / self.package
        package.rename(target)
        package.symlink_to(target)
        self.assert_failure(f"cannot open release asset {self.package}")


    def test_writable_asset_directory_is_refused(self) -> None:
        self.assets.chmod(0o777)
        self.assert_failure("asset directory must be owned by the current user and not group/world writable")

    def test_existing_output_is_refused(self) -> None:
        self.output.write_text("existing", encoding="utf-8")
        self.assert_failure("refusing existing output")


if __name__ == "__main__":
    unittest.main()
