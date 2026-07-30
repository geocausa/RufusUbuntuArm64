#!/usr/bin/env python3
"""Run the versioned Linux ISO compatibility corpus without writing a device."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parent.parent
GUI = ROOT / "gui"
if str(GUI) not in sys.path:
    sys.path.insert(0, str(GUI))

from rufusarm64_linux_compatibility import linux_compatibility_profile  # noqa: E402

SCHEMA = 1
QUALIFICATION_STATES = {"qualified", "pending"}
DECISIONS = {"iso-image-candidate", "dd-only", "refuse"}


class CorpusError(ValueError):
    """Raised when the corpus or a result violates the reviewed contract."""


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CorpusError(f"read corpus manifest {path}: {exc}") from exc
    validate_manifest(value)
    return value


def validate_manifest(value: Any) -> None:
    if not isinstance(value, dict) or value.get("schema") != SCHEMA:
        raise CorpusError(f"corpus manifest must use schema {SCHEMA}")
    if not isinstance(value.get("corpus_version"), str) or not value["corpus_version"].strip():
        raise CorpusError("corpus manifest requires a non-empty corpus_version")
    entries = value.get("entries")
    if not isinstance(entries, list) or not entries:
        raise CorpusError("corpus manifest requires at least one entry")
    identifiers: set[str] = set()
    filenames: set[str] = set()
    for index, entry in enumerate(entries):
        label = f"entry {index + 1}"
        if not isinstance(entry, dict):
            raise CorpusError(f"{label} must be an object")
        identifier = _required_text(entry, "id", label)
        if identifier in identifiers:
            raise CorpusError(f"duplicate corpus id {identifier!r}")
        identifiers.add(identifier)
        _required_text(entry, "family", label)
        _required_text(entry, "architecture", label)
        filename = _required_text(entry, "filename", label)
        if os.path.basename(filename) != filename:
            raise CorpusError(f"{label} filename must be a basename")
        if filename in filenames:
            raise CorpusError(f"duplicate corpus filename {filename!r}")
        filenames.add(filename)
        state = entry.get("qualification_state")
        if state not in QUALIFICATION_STATES:
            raise CorpusError(f"{label} qualification_state must be qualified or pending")
        source = entry.get("source")
        if not isinstance(source, dict):
            raise CorpusError(f"{label} requires a source object")
        kind = str(source.get("kind") or "official").strip().lower()
        if kind not in {"official", "synthetic"}:
            raise CorpusError(f"{label} source kind must be official or synthetic")
        _required_text(source, "project", f"{label} source")
        if kind == "official":
            _required_text(source, "url", f"{label} source")
        else:
            _required_text(source, "generator", f"{label} source")
        if state == "qualified":
            size = entry.get("size")
            digest = entry.get("sha256")
            expected = entry.get("expected")
            if not isinstance(size, int) or size <= 0:
                raise CorpusError(f"{label} qualified size must be a positive integer")
            if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise CorpusError(f"{label} qualified sha256 must be lowercase hexadecimal")
            if not isinstance(expected, dict) or expected.get("decision") not in DECISIONS:
                raise CorpusError(f"{label} qualified expected decision is invalid")


def _required_text(value: dict[str, Any], key: str, label: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item.strip():
        raise CorpusError(f"{label} requires non-empty {key}")
    return item.strip()



def _catalogue_validation(platform: int) -> bytes:
    entry = bytearray(32)
    entry[0] = 1
    entry[1] = platform
    entry[30:32] = b"\x55\xaa"
    words = list(struct.unpack("<16H", entry))
    words[14] = (-sum(words)) & 0xFFFF
    return struct.pack("<16H", *words)


def materialize_fixture(generator: str, destination: Path) -> None:
    """Create one compact deterministic corpus fixture."""
    if generator == "arbitrary-unrecognized-v1":
        destination.write_bytes(b"RufusArm64 corpus: deliberately unrecognized input\n")
        return
    if generator == "bare-squashfs-v1":
        data = bytearray(4096)
        data[:4] = b"hsqs"
        destination.write_bytes(data)
        return
    specifications = {
        "hybrid-uefi-grub-v1": (True, 0xEF, b"GRUB"),
        "hybrid-bios-isolinux-v1": (True, 0x00, b"ISOLINUX"),
        "optical-uefi-grub-v1": (False, 0xEF, b"GRUB"),
    }
    if generator not in specifications:
        raise CorpusError(f"unsupported synthetic fixture generator {generator!r}")
    hybrid, platform, marker = specifications[generator]
    data = bytearray(256 * 1024)
    if hybrid:
        data[510:512] = b"\x55\xaa"
        data[446 + 4] = 0x17
        struct.pack_into("<I", data, 446 + 8, 1)
        struct.pack_into("<I", data, 446 + 12, 100)
    boot = 16 * 2048
    data[boot] = 0
    data[boot + 1 : boot + 6] = b"CD001"
    data[boot + 6] = 1
    data[boot + 7 : boot + 7 + len(b"EL TORITO SPECIFICATION")] = b"EL TORITO SPECIFICATION"
    struct.pack_into("<I", data, boot + 71, 20)
    primary = 17 * 2048
    data[primary] = 1
    data[primary + 1 : primary + 6] = b"CD001"
    data[primary + 6] = 1
    terminator = 18 * 2048
    data[terminator] = 255
    data[terminator + 1 : terminator + 6] = b"CD001"
    data[terminator + 6] = 1
    catalogue = 20 * 2048
    data[catalogue : catalogue + 32] = _catalogue_validation(platform)
    data[catalogue + 32] = 0x88
    struct.pack_into("<I", data, catalogue + 32 + 8, 40)
    data[40 * 2048 : 40 * 2048 + len(marker)] = marker
    destination.write_bytes(data)


def materialize_synthetic_entries(entries: list[dict[str, Any]], directory: Path) -> None:
    for entry in entries:
        source = entry.get("source") or {}
        if str(source.get("kind") or "official").lower() != "synthetic":
            continue
        destination = directory / entry["filename"]
        materialize_fixture(source["generator"], destination)

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(8 * 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def locate_image(filename: str, directories: Iterable[Path]) -> Path | None:
    for directory in directories:
        candidate = directory / filename
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        try:
            metadata = resolved.stat()
        except OSError:
            continue
        if resolved.is_file() and metadata.st_size > 0:
            return resolved
    return None


def inspect_image(helper: Path, image: Path) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            [str(helper), "inspect", "--image", str(image), "--json"],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=300,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise CorpusError(f"run image inspector for {image.name}: {exc}") from exc
    if completed.returncode != 0:
        diagnostic = (completed.stderr or completed.stdout).strip()
        return {
            "recognized": False,
            "mode": "refuse",
            "container_format": "plain",
            "inspector_refusal": diagnostic or f"exit status {completed.returncode}",
        }
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise CorpusError(f"image inspector returned invalid JSON for {image.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise CorpusError(f"image inspector returned a non-object for {image.name}")
    return value


def classify(inspection: dict[str, Any], profile: dict[str, Any]) -> str:
    if not inspection.get("recognized"):
        return "refuse"
    if inspection.get("mode") != "raw" or inspection.get("needs_preparation"):
        return "refuse"
    container = str(inspection.get("container_format") or "plain").lower()
    if container not in {"", "plain"}:
        return "refuse"
    if (
        profile.get("write_path") == "hybrid-direct-write"
        and profile.get("hybrid") is True
        and "UEFI" in (profile.get("boot_methods") or [])
    ):
        return "iso-image-candidate"
    return "dd-only"


def compare_expected(entry: dict[str, Any], actual: dict[str, Any]) -> list[str]:
    expected = entry.get("expected") or {}
    failures: list[str] = []
    if expected.get("decision") != actual.get("decision"):
        failures.append(
            f"decision expected {expected.get('decision')!r}, got {actual.get('decision')!r}"
        )
    expected_profile = expected.get("profile")
    if isinstance(expected_profile, dict):
        actual_profile = actual.get("profile") or {}
        for key, expected_value in expected_profile.items():
            if actual_profile.get(key) != expected_value:
                failures.append(
                    f"profile.{key} expected {expected_value!r}, got {actual_profile.get(key)!r}"
                )
    expected_inspection = expected.get("inspection")
    if isinstance(expected_inspection, dict):
        actual_inspection = actual.get("inspection") or {}
        for key, expected_value in expected_inspection.items():
            if actual_inspection.get(key) != expected_value:
                failures.append(
                    f"inspection.{key} expected {expected_value!r}, got {actual_inspection.get(key)!r}"
                )
    return failures


def run_entry(
    entry: dict[str, Any],
    directories: list[Path],
    helper: Path,
    allow_missing: bool,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": entry["id"],
        "family": entry["family"],
        "architecture": entry["architecture"],
        "filename": entry["filename"],
        "qualification_state": entry["qualification_state"],
    }
    image = locate_image(entry["filename"], directories)
    if image is None:
        allowed = entry["qualification_state"] == "pending" and allow_missing
        result.update(
            {
                "status": "missing",
                "passed": allowed,
                "failures": [] if allowed else ["image file was not found"],
            }
        )
        return result

    metadata = image.stat()
    digest = sha256_file(image)
    result.update({"path": str(image), "size": metadata.st_size, "sha256": digest})
    failures: list[str] = []
    if entry["qualification_state"] == "qualified":
        if metadata.st_size != entry["size"]:
            failures.append(f"size expected {entry['size']}, got {metadata.st_size}")
        if digest != entry["sha256"]:
            failures.append(f"sha256 expected {entry['sha256']}, got {digest}")

    try:
        inspection = inspect_image(helper, image)
        profile = linux_compatibility_profile(image, inspection)
        decision = classify(inspection, profile)
        result.update({"inspection": inspection, "profile": profile, "decision": decision})
        if entry["qualification_state"] == "qualified":
            failures.extend(compare_expected(entry, result))
    except CorpusError as exc:
        failures.append(str(exc))

    result["status"] = "checked"
    result["failures"] = failures
    result["passed"] = not failures
    return result


def run_corpus(
    manifest: dict[str, Any],
    directories: list[Path],
    helper: Path,
    allow_missing: bool,
    selected_ids: set[str] | None = None,
) -> dict[str, Any]:
    entries = manifest["entries"]
    if selected_ids:
        known = {entry["id"] for entry in entries}
        unknown = sorted(selected_ids - known)
        if unknown:
            raise CorpusError("unknown corpus ids: " + ", ".join(unknown))
        entries = [entry for entry in entries if entry["id"] in selected_ids]
    with tempfile.TemporaryDirectory(prefix="rufusarm64-linux-iso-corpus-") as temporary:
        fixture_dir = Path(temporary)
        materialize_synthetic_entries(entries, fixture_dir)
        effective_directories = [fixture_dir, *directories]
        results = [run_entry(entry, effective_directories, helper, allow_missing) for entry in entries]
    return {
        "schema": SCHEMA,
        "corpus_version": manifest["corpus_version"],
        "helper": str(helper),
        "image_directories": [str(path) for path in directories],
        "passed": all(result["passed"] for result in results),
        "results": results,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=ROOT / "docs" / "linux-iso-corpus.json",
        help="versioned corpus manifest",
    )
    parser.add_argument(
        "--image-dir",
        type=Path,
        action="append",
        dest="image_dirs",
        help="directory containing corpus images; may be repeated",
    )
    parser.add_argument(
        "--helper",
        type=Path,
        default=Path("/usr/lib/rufusarm64/rufusarm64-helper"),
        help="RufusArm64 helper used for read-only inspection",
    )
    parser.add_argument("--entry", action="append", dest="entries", help="run only one corpus id")
    parser.add_argument(
        "--allow-missing",
        action="store_true",
        help="report missing pending images without failing the run",
    )
    parser.add_argument("--json", action="store_true", help="emit the complete JSON report")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    directories = [path.resolve() for path in (args.image_dirs or [Path.cwd()])]
    try:
        manifest = load_manifest(args.manifest.resolve())
        helper = args.helper.resolve(strict=True)
        if not helper.is_file() or not os.access(helper, os.X_OK):
            raise CorpusError(f"helper is not executable: {helper}")
        report = run_corpus(
            manifest,
            directories,
            helper,
            args.allow_missing,
            set(args.entries or []) or None,
        )
    except (CorpusError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        json.dump(report, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        for result in report["results"]:
            state = "PASS" if result["passed"] else "FAIL"
            decision = result.get("decision") or result["status"]
            print(f"{state}\t{result['id']}\t{decision}\t{result['filename']}")
            for failure in result.get("failures") or []:
                print(f"  {failure}")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
