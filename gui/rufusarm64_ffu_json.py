#!/usr/bin/env python3
"""Strict FFU JSON parsing and bounded helper-process capture."""

import json

from rufusarm64_process import OutputLimitError, communicate_bounded as _communicate_bounded


MAX_FFU_STDOUT_BYTES = 32 * 1024 * 1024
MAX_FFU_STDERR_BYTES = 1024 * 1024
FFUOutputLimitError = OutputLimitError


def _reject_duplicate_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value):
    raise ValueError(f"Unsupported JSON constant: {value}")


def strict_json_loads(data):
    """Decode one strict JSON value while rejecting duplicate object members."""
    try:
        return json.loads(
            data,
            object_pairs_hook=_reject_duplicate_members,
            parse_constant=_reject_json_constant,
        )
    except (RecursionError, UnicodeDecodeError) as exc:
        raise ValueError("FFU evidence is not valid bounded UTF-8 JSON.") from exc


def communicate_bounded(
    process,
    *,
    stdout_limit=MAX_FFU_STDOUT_BYTES,
    stderr_limit=MAX_FFU_STDERR_BYTES,
    timeout=None,
    terminate=None,
):
    """Capture FFU evidence through the package-owned bounded process utility."""
    return _communicate_bounded(
        process,
        stdout_limit=stdout_limit,
        stderr_limit=stderr_limit,
        timeout=timeout,
        terminate=terminate,
        label="FFU helper",
    )
