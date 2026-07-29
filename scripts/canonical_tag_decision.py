#!/usr/bin/env python3
"""Decide whether an immutable canonical release tag should be created."""

from __future__ import annotations

import argparse
import re

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{40}$")


def _commit_sha(value: str, *, required: bool) -> str:
    normalized = (value or "").strip().lower()
    if not normalized and not required:
        return ""
    if not _SHA256_PATTERN.fullmatch(normalized):
        raise ValueError("commit SHA must contain exactly 40 hexadecimal characters")
    return normalized


def canonical_tag_decision(current_sha: str, existing_sha: str = "") -> str:
    """Return create, already-current, or already-released without moving a tag."""
    current = _commit_sha(current_sha, required=True)
    existing = _commit_sha(existing_sha, required=False)
    if not existing:
        return "create"
    if existing == current:
        return "already-current"
    return "already-released"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--current-sha", required=True)
    parser.add_argument("--existing-sha", default="")
    args = parser.parse_args()
    try:
        print(canonical_tag_decision(args.current_sha, args.existing_sha))
    except ValueError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
