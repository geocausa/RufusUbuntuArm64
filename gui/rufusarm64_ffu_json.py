#!/usr/bin/env python3
"""Strict FFU JSON parsing and bounded helper-process capture."""

import json
import os
import selectors
import subprocess
import time

MAX_FFU_STDOUT_BYTES = 32 * 1024 * 1024
MAX_FFU_STDERR_BYTES = 1024 * 1024
_READ_CHUNK_BYTES = 64 * 1024
_TERMINATION_GRACE_SECONDS = 2.0


class FFUOutputLimitError(ValueError):
    """Raised when a helper exceeds its bounded evidence or diagnostic channel."""


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


def _default_terminate(process, force):
    if process.poll() is not None:
        return
    if force:
        process.kill()
    else:
        process.terminate()


def communicate_bounded(
    process,
    *,
    stdout_limit=MAX_FFU_STDOUT_BYTES,
    stderr_limit=MAX_FFU_STDERR_BYTES,
    timeout=None,
    terminate=None,
):
    """Capture binary stdout/stderr without allowing unbounded memory growth.

    ``process`` must have binary stdout and stderr pipes. ``terminate`` receives
    ``False`` for an orderly stop and ``True`` for a forced stop. Output overflow
    and timeout terminate the process before returning an error.
    """
    if process is None or process.stdout is None or process.stderr is None:
        raise ValueError("The FFU helper process is missing output pipes.")
    if stdout_limit <= 0 or stderr_limit <= 0:
        raise ValueError("FFU helper output limits must be positive.")
    if timeout is not None and timeout <= 0:
        raise ValueError("FFU helper timeout must be positive.")

    terminate = terminate or (lambda force: _default_terminate(process, force))
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": int(stdout_limit), "stderr": int(stderr_limit)}
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    started = time.monotonic()
    stopping_at = None
    timeout_error = None
    limit_error = None

    def request_stop():
        nonlocal stopping_at
        if stopping_at is None:
            stopping_at = time.monotonic()
            try:
                terminate(False)
            except (ProcessLookupError, PermissionError, OSError):
                pass

    try:
        while selector.get_map() or process.poll() is None:
            now = time.monotonic()
            if timeout_error is None and timeout is not None and now - started > timeout:
                timeout_error = subprocess.TimeoutExpired(process.args, timeout)
                request_stop()
            if (
                stopping_at is not None
                and process.poll() is None
                and now - stopping_at > _TERMINATION_GRACE_SECONDS
            ):
                try:
                    terminate(True)
                except (ProcessLookupError, PermissionError, OSError):
                    try:
                        process.kill()
                    except (ProcessLookupError, PermissionError, OSError):
                        pass
                stopping_at = now

            events = selector.select(0.1)
            for key, _ in events:
                try:
                    chunk = os.read(key.fd, _READ_CHUNK_BYTES)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                channel = key.data
                if limit_error is not None:
                    continue
                buffer = buffers[channel]
                limit = limits[channel]
                if len(buffer) + len(chunk) > limit:
                    limit_error = FFUOutputLimitError(
                        f"The FFU helper {channel} exceeded the {limit}-byte safety limit."
                    )
                    request_stop()
                    continue
                buffer.extend(chunk)

            if process.poll() is not None and not selector.get_map():
                break
        process.wait()
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()

    if timeout_error is not None:
        raise timeout_error
    if limit_error is not None:
        raise limit_error
    try:
        return (
            bytes(buffers["stdout"]).decode("utf-8"),
            bytes(buffers["stderr"]).decode("utf-8"),
        )
    except UnicodeDecodeError as exc:
        raise ValueError("The FFU helper returned non-UTF-8 output.") from exc
