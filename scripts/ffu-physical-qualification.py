#!/usr/bin/env python3
"""Seal one human-assisted physical FFU qualification record without device access."""

import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "gui"))

from rufusarm64_ffu_physical_qualification import (  # noqa: E402
    ffu_physical_qualification_summary,
    normalize_ffu_physical_qualification,
)

_MAX_RECORD_BYTES = 32 * 1024 * 1024


def _reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_record(path):
    data = path.read_bytes()
    if len(data) > _MAX_RECORD_BYTES:
        raise ValueError("The qualification record exceeds the 32 MiB limit.")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("The qualification record is not valid UTF-8 JSON.") from exc


def _write_new(path, payload):
    encoded = (
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=(
            "Validate a complete FFU restore evidence chain and seal one bounded physical "
            "firmware-boot qualification record. This tool never opens a block device."
        )
    )
    parser.add_argument("--record", required=True, type=Path, help="input qualification JSON")
    parser.add_argument("--output", required=True, type=Path, help="new normalized JSON file")
    parser.add_argument("--summary", action="store_true", help="print bounded result text")
    args = parser.parse_args(argv)

    try:
        record = _read_record(args.record)
        result = normalize_ffu_physical_qualification(record)
        _write_new(args.output, result)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    if args.summary:
        print(ffu_physical_qualification_summary(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
