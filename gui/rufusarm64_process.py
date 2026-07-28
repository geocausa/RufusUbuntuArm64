#!/usr/bin/env python3
"""Bounded process-group execution helpers for package-owned GUI workflows."""

import os
import selectors
import signal
import subprocess
import threading
import time


READ_CHUNK_BYTES = 64 * 1024
DEFAULT_TERMINATION_GRACE_SECONDS = 2.0
DEFAULT_REAP_TIMEOUT_SECONDS = 5.0


class OutputLimitError(ValueError):
    """Raised when a helper exceeds a reviewed output channel limit."""


def terminate_process_group(process, force=False):
    """Signal only the owned process group created with ``start_new_session``."""
    if process is None or process.poll() is not None:
        return False
    os.killpg(process.pid, signal.SIGKILL if force else signal.SIGTERM)
    return True


def schedule_process_group_termination(process, grace_seconds=DEFAULT_TERMINATION_GRACE_SECONDS):
    """Request SIGTERM now and asynchronously escalate an unresponsive group."""
    if grace_seconds <= 0:
        raise ValueError("Process-group termination grace must be positive.")
    try:
        started = terminate_process_group(process)
    except (ProcessLookupError, PermissionError, OSError):
        return None
    if not started:
        return None

    def escalate():
        deadline = time.monotonic() + grace_seconds
        while process.poll() is None and time.monotonic() < deadline:
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
        if process.poll() is None:
            try:
                terminate_process_group(process, force=True)
            except (ProcessLookupError, PermissionError, OSError):
                pass

    thread = threading.Thread(target=escalate, name="rufusarm64-process-group-stop", daemon=True)
    thread.start()
    return thread


def terminate_and_reap(
    process,
    *,
    terminate_timeout=DEFAULT_REAP_TIMEOUT_SECONDS,
    kill_timeout=DEFAULT_REAP_TIMEOUT_SECONDS,
):
    """Terminate an owned process group, close captured pipes, and reap it."""
    if process is None:
        return None
    if terminate_timeout <= 0 or kill_timeout <= 0:
        raise ValueError("Process reaping timeouts must be positive.")
    if process.poll() is None:
        try:
            terminate_process_group(process)
        except (ProcessLookupError, PermissionError, OSError):
            pass
    try:
        process.communicate(timeout=terminate_timeout)
    except subprocess.TimeoutExpired:
        try:
            terminate_process_group(process, force=True)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                process.kill()
            except (ProcessLookupError, PermissionError, OSError):
                pass
        try:
            process.communicate(timeout=kill_timeout)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("The helper process group could not be reaped after SIGKILL.") from exc
    return process.returncode


def communicate_bounded(
    process,
    *,
    stdout_limit,
    stderr_limit,
    timeout=None,
    terminate=None,
    label="helper",
    termination_grace=DEFAULT_TERMINATION_GRACE_SECONDS,
):
    """Capture binary stdout/stderr with byte, time, group-stop, and reaping bounds."""
    if process is None or process.stdout is None or process.stderr is None:
        raise ValueError(f"The {label} process is missing output pipes.")
    if stdout_limit <= 0 or stderr_limit <= 0:
        raise ValueError(f"The {label} output limits must be positive.")
    if timeout is not None and timeout <= 0:
        raise ValueError(f"The {label} timeout must be positive.")
    if termination_grace <= 0:
        raise ValueError(f"The {label} termination grace must be positive.")

    terminate = terminate or (lambda force: terminate_process_group(process, force=force))
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
            if stopping_at is not None and process.poll() is None and now - stopping_at > termination_grace:
                try:
                    terminate(True)
                except (ProcessLookupError, PermissionError, OSError):
                    try:
                        process.kill()
                    except (ProcessLookupError, PermissionError, OSError):
                        pass
                stopping_at = now

            for key, _ in selector.select(0.1):
                try:
                    chunk = os.read(key.fd, READ_CHUNK_BYTES)
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
                    limit_error = OutputLimitError(
                        f"The {label} {channel} exceeded the {limit}-byte safety limit."
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
        raise ValueError(f"The {label} returned non-UTF-8 output.") from exc


def run_bounded(
    args,
    *,
    stdout_limit,
    stderr_limit,
    timeout=None,
    label="helper",
):
    """Run one helper in an owned session and return a bounded CompletedProcess."""
    process = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, stderr = communicate_bounded(
            process,
            stdout_limit=stdout_limit,
            stderr_limit=stderr_limit,
            timeout=timeout,
            label=label,
        )
    except Exception:
        if process.poll() is None:
            terminate_and_reap(process)
        raise
    return subprocess.CompletedProcess(args, process.returncode, stdout, stderr)


def iter_bounded_process_utf8_lines(
    process,
    *,
    stdout_line_limit,
    stdout_total_limit,
    stderr_line_limit,
    stderr_total_limit,
    timeout=None,
    terminate=None,
    label="helper",
    termination_grace=DEFAULT_TERMINATION_GRACE_SECONDS,
):
    """Yield decoded lines from both binary pipes without deadlock or unbounded evidence."""
    if process is None or process.stdout is None or process.stderr is None:
        raise ValueError(f"The {label} process is missing output pipes.")
    limits = {
        "stdout": (int(stdout_line_limit), int(stdout_total_limit)),
        "stderr": (int(stderr_line_limit), int(stderr_total_limit)),
    }
    for channel, (line_limit, total_limit) in limits.items():
        if line_limit <= 0 or total_limit <= 0 or line_limit > total_limit:
            raise ValueError(f"The {label} {channel} limits are invalid.")
    if timeout is not None and timeout <= 0:
        raise ValueError(f"The {label} timeout must be positive.")
    if termination_grace <= 0:
        raise ValueError(f"The {label} termination grace must be positive.")

    terminate = terminate or (lambda force: terminate_process_group(process, force=force))
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    pending = {"stdout": bytearray(), "stderr": bytearray()}
    totals = {"stdout": 0, "stderr": 0}
    started = time.monotonic()
    stopping_at = None
    pending_error = None

    def request_stop(error):
        nonlocal stopping_at, pending_error
        if pending_error is None:
            pending_error = error
        if stopping_at is None:
            stopping_at = time.monotonic()
            try:
                terminate(False)
            except (ProcessLookupError, PermissionError, OSError):
                pass

    def decode_line(channel, raw):
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            request_stop(ValueError(f"The {label} {channel} returned non-UTF-8 output."))
            return None

    try:
        while selector.get_map() or process.poll() is None:
            now = time.monotonic()
            if timeout is not None and pending_error is None and now - started > timeout:
                request_stop(subprocess.TimeoutExpired(process.args, timeout))
            if stopping_at is not None and process.poll() is None and now - stopping_at > termination_grace:
                try:
                    terminate(True)
                except (ProcessLookupError, PermissionError, OSError):
                    try:
                        process.kill()
                    except (ProcessLookupError, PermissionError, OSError):
                        pass
                stopping_at = now

            for key, _ in selector.select(0.1):
                channel = key.data
                try:
                    chunk = os.read(key.fd, READ_CHUNK_BYTES)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    tail = bytes(pending[channel])
                    pending[channel].clear()
                    if tail and pending_error is None:
                        decoded = decode_line(channel, tail)
                        if decoded is not None:
                            yield channel, decoded
                    continue
                if pending_error is not None:
                    continue
                line_limit, total_limit = limits[channel]
                totals[channel] += len(chunk)
                if totals[channel] > total_limit:
                    request_stop(OutputLimitError(
                        f"The {label} {channel} exceeded the {total_limit}-byte safety limit."
                    ))
                    continue
                pending[channel].extend(chunk)
                while True:
                    newline = pending[channel].find(b"\n")
                    if newline < 0:
                        break
                    raw = bytes(pending[channel][: newline + 1])
                    del pending[channel][: newline + 1]
                    if len(raw) > line_limit:
                        request_stop(OutputLimitError(
                            f"The {label} {channel} line exceeded the {line_limit}-byte safety limit."
                        ))
                        break
                    decoded = decode_line(channel, raw)
                    if decoded is not None:
                        yield channel, decoded
                    if pending_error is not None:
                        break
                if len(pending[channel]) > line_limit and pending_error is None:
                    request_stop(OutputLimitError(
                        f"The {label} {channel} line exceeded the {line_limit}-byte safety limit."
                    ))

            if process.poll() is not None and not selector.get_map():
                break
        process.wait()
    finally:
        selector.close()
        if process.poll() is None:
            terminate_and_reap(process)
        process.stdout.close()
        process.stderr.close()

    if pending_error is not None:
        raise pending_error


def iter_bounded_utf8_lines(stream, *, line_limit, total_limit, label="helper output"):
    """Yield UTF-8 lines from one binary pipe without allowing unbounded records."""
    if stream is None:
        raise ValueError(f"The {label} pipe is missing.")
    if line_limit <= 0 or total_limit <= 0 or line_limit > total_limit:
        raise ValueError(f"The {label} limits are invalid.")
    total = 0
    while True:
        raw = stream.readline(line_limit + 1)
        if not raw:
            return
        total += len(raw)
        if len(raw) > line_limit:
            raise OutputLimitError(f"The {label} line exceeded the {line_limit}-byte safety limit.")
        if total > total_limit:
            raise OutputLimitError(f"The {label} exceeded the {total_limit}-byte safety limit.")
        try:
            yield raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"The {label} returned non-UTF-8 output.") from exc
