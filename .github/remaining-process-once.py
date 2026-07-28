#!/usr/bin/env python3
"""Apply the remaining Stage 4 GTK helper-process migration once."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, text: str) -> None:
    (ROOT / path).write_text(text, encoding="utf-8")


def replace_once(path: str, old: str, new: str, label: str) -> None:
    text = read(path)
    if text.count(old) != 1:
        raise SystemExit(f"{label} changed: found {text.count(old)}")
    write(path, text.replace(old, new, 1))


def replace_span(path: str, start_marker: str, end_marker: str, replacement: str, label: str, *, offset: int = 0) -> None:
    text = read(path)
    try:
        start = text.index(start_marker, offset)
        end = text.index(end_marker, start)
    except ValueError as exc:
        raise SystemExit(f"{label} boundary changed") from exc
    write(path, text[:start] + replacement.rstrip() + text[end:])


def replace_class_method(path: str, class_name: str, method_name: str, next_marker: str, replacement: str) -> None:
    text = read(path)
    class_start = text.index(f"class {class_name}")
    start = text.index(f"    def {method_name}", class_start)
    end = text.index(next_marker, start)
    write(path, text[:start] + replacement.rstrip() + text[end:])


def run(*args: str) -> None:
    subprocess.run(args, cwd=ROOT, check=True)


# Shared bounded execution and concurrent two-pipe streaming.
process_path = "gui/rufusarm64_process.py"
anchor = "\n\ndef iter_bounded_utf8_lines(stream, *, line_limit, total_limit, label=\"helper output\"):\n"
addition = r'''

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
'''
replace_once(process_path, anchor, addition + anchor, "shared process iterator anchor")

# Common test imports and runtime coverage.
test_process = "gui/test_process_cleanup.py"
replace_once(
    test_process,
    "    iter_bounded_utf8_lines,\n",
    "    iter_bounded_process_utf8_lines,\n    iter_bounded_utf8_lines,\n    run_bounded,\n",
    "process test imports",
)
test_addition = r'''

class BoundedProcessStreamTests(unittest.TestCase):
    def start(self, code):
        return subprocess.Popen(
            [sys.executable, "-c", code],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )

    def test_two_pipe_streaming_is_concurrent_bounded_and_reaped(self):
        process = self.start(
            "import sys; "
            "[print(f'out-{i}', flush=True) or print(f'err-{i}', file=sys.stderr, flush=True) for i in range(4)]"
        )
        lines = list(iter_bounded_process_utf8_lines(
            process,
            stdout_line_limit=32,
            stdout_total_limit=256,
            stderr_line_limit=32,
            stderr_total_limit=256,
            label="dual test helper",
        ))
        self.assertEqual(process.returncode, 0)
        self.assertEqual([line for channel, line in lines if channel == "stdout"], [f"out-{i}\n" for i in range(4)])
        self.assertEqual([line for channel, line in lines if channel == "stderr"], [f"err-{i}\n" for i in range(4)])
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)

    def test_two_pipe_limit_stops_and_reaps_owned_group(self):
        process = self.start(
            "import signal,sys,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "sys.stderr.write('x'*10000); sys.stderr.flush(); time.sleep(30)"
        )
        with self.assertRaises(OutputLimitError):
            list(iter_bounded_process_utf8_lines(
                process,
                stdout_line_limit=32,
                stdout_total_limit=128,
                stderr_line_limit=64,
                stderr_total_limit=128,
                label="dual limit helper",
                termination_grace=0.1,
            ))
        self.assertIsNotNone(process.returncode)
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)

    def test_run_bounded_rejects_oversized_capture_and_reaps(self):
        with self.assertRaises(OutputLimitError):
            run_bounded(
                [sys.executable, "-c", "print('x'*10000)"],
                stdout_limit=100,
                stderr_limit=100,
                timeout=5,
                label="bounded run test",
            )
'''
replace_once(test_process, "\n\nif __name__ == \"__main__\":\n", test_addition + "\n\nif __name__ == \"__main__\":\n", "process runtime test anchor")

# Main application workers.
main = "gui/rufusarm64.py"
replace_once(main, "import signal\n", "", "main direct signal import")
main_import = '''from rufusarm64_process import (
    communicate_bounded,
    iter_bounded_utf8_lines,
    run_bounded,
    schedule_process_group_termination,
    terminate_and_reap,
)

GUI_STDOUT_LIMIT = 32 * 1024 * 1024
GUI_STDERR_LIMIT = 2 * 1024 * 1024
GUI_STREAM_LINE_LIMIT = 1024 * 1024
GUI_STREAM_TOTAL_LIMIT = 64 * 1024 * 1024

'''
replace_once(main, '\nAPP_ID = "io.github.geocausa.RufusArm64"\n', "\n" + main_import + 'APP_ID = "io.github.geocausa.RufusArm64"\n', "main process imports")
replace_span(main, "    def _destroyed(self, *_):", "\n    @staticmethod\n    def _chooser", '''    def _destroyed(self, *_):
        self.closed = True
        process = self.channel_process
        if process and process.poll() is None:
            schedule_process_group_termination(process, grace_seconds=5)
''', "acquisition destroy cleanup")
replace_span(main, "    def _run_channel_refresh(self, command):", "\n    def _finish_channel_refresh", '''    def _run_channel_refresh(self, command):
        process = None
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            self.channel_process = process
            if self.closed and process.poll() is None:
                schedule_process_group_termination(process, grace_seconds=5)
            stdout, stderr = communicate_bounded(
                process,
                stdout_limit=GUI_STDOUT_LIMIT,
                stderr_limit=GUI_STDERR_LIMIT,
                timeout=900,
                label="acquisition channel refresh",
            )
            if process.returncode != 0:
                raise RuntimeError(stderr.strip() or stdout.strip() or "Built-in catalog refresh failed")
            metadata = normalize_acquisition_channel(json.loads(stdout))
            GLib.idle_add(self._finish_channel_refresh, metadata, "")
        except Exception as exc:
            if process is not None and process.poll() is None:
                try:
                    terminate_and_reap(process)
                except (OSError, RuntimeError, ValueError):
                    pass
            if not self.closed:
                GLib.idle_add(self._finish_channel_refresh, {}, str(exc))
        finally:
            if self.channel_process is process:
                self.channel_process = None
''', "acquisition channel worker")
replace_span(main, "    def _run_catalog_verify(self, command, selection, generation):", "\n    def _finish_catalog_verify", '''    def _run_catalog_verify(self, command, selection, generation):
        images = []
        error = ""
        try:
            result = run_bounded(
                command,
                stdout_limit=GUI_STDOUT_LIMIT,
                stderr_limit=GUI_STDERR_LIMIT,
                timeout=20,
                label="local acquisition catalog verification",
            )
            if result.returncode != 0:
                raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "Catalog verification failed")
            images = normalize_acquisition_images(json.loads(result.stdout))
        except Exception as exc:
            error = str(exc)
        GLib.idle_add(self._finish_catalog_verify, images, error, selection, generation)
''', "local acquisition worker")
replace_span(main, "    def run_download(self, command):", "\n    def finish_download", '''    def run_download(self, command):
        result_payload = {}
        process = None
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            self.process = process
            if self.cancel_requested and process.poll() is None:
                schedule_process_group_termination(process, grace_seconds=5)
            for raw in iter_bounded_utf8_lines(
                process.stdout,
                line_limit=GUI_STREAM_LINE_LIMIT,
                total_limit=GUI_STREAM_TOTAL_LIMIT,
                label="verified download helper output",
            ):
                line = raw.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    GLib.idle_add(self.append_log, line)
                    continue
                if isinstance(payload, dict) and payload.get("event"):
                    GLib.idle_add(self.handle_event, payload)
                elif isinstance(payload, dict) and payload.get("path"):
                    result_payload = payload
            process.stdout.close()
            return_code = process.wait()
            GLib.idle_add(self.finish_download, return_code, result_payload)
        except Exception as exc:
            if process is not None and process.poll() is None:
                try:
                    terminate_and_reap(process)
                except (OSError, RuntimeError, ValueError):
                    pass
            GLib.idle_add(self.append_log, f"Verified download failed: {exc}")
            GLib.idle_add(self.finish_download, 1, {})
        finally:
            if self.process is process:
                self.process = None
''', "verified download worker")
replace_span(main, "    def run_persistence_plan(self, command, plan_key, source_identity):", "\n    def finish_persistence_plan", '''    def run_persistence_plan(self, command, plan_key, source_identity):
        process = None
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            self.process = process
            stdout, stderr = communicate_bounded(
                process,
                stdout_limit=GUI_STDOUT_LIMIT,
                stderr_limit=GUI_STDERR_LIMIT,
                timeout=300,
                label="integrated persistence analysis helper",
            )
            return_code = process.returncode
            payload = json.loads(stdout) if return_code == 0 else {}
            error = (stderr.strip() or stdout.strip()) if return_code != 0 else ""
            GLib.idle_add(self.finish_persistence_plan, return_code, payload, error, plan_key, source_identity)
        except Exception as exc:
            if process is not None and process.poll() is None:
                try:
                    terminate_and_reap(process)
                except (OSError, RuntimeError, ValueError):
                    pass
            GLib.idle_add(self.finish_persistence_plan, 1, {}, str(exc), plan_key, source_identity)
        finally:
            if self.process is process:
                self.process = None
''', "integrated persistence plan worker")
replace_span(main, "    def run_writer(self, command):", "\n    def handle_event", '''    def run_writer(self, command):
        process = None
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            self.process = process
            if self.cancel_requested and process.poll() is None:
                schedule_process_group_termination(process, grace_seconds=5)
            for raw in iter_bounded_utf8_lines(
                process.stdout,
                line_limit=GUI_STREAM_LINE_LIMIT,
                total_limit=GUI_STREAM_TOTAL_LIMIT,
                label="writer helper output",
            ):
                line = raw.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    GLib.idle_add(self.append_log, line)
                    continue
                GLib.idle_add(self.handle_event, event)
            process.stdout.close()
            return_code = process.wait()
            GLib.idle_add(self.finish, return_code)
        except Exception as exc:
            if process is not None and process.poll() is None:
                try:
                    terminate_and_reap(process)
                except (OSError, RuntimeError, ValueError):
                    pass
            GLib.idle_add(self.append_log, f"Failed to start the writer: {exc}")
            GLib.idle_add(self.finish, 1)
        finally:
            if self.process is process:
                self.process = None
''', "primary writer worker")
replace_span(main, "    def cancel(self, *_):", "\n    def message", '''    def cancel(self, *_):
        if not self.busy:
            return
        self.cancel_requested = True
        self.cancel_button.set_sensitive(False)
        if self.active_job == "writer":
            self.append_log("Cancellation requested. Do not remove the USB until RufusArm64 confirms that writing has stopped.")
            self.progress.set_text("Cancelling safely…")
            self.progress_detail.set_text("Waiting for the privileged writer to reach a safe cancellation point. Do not unplug the USB.")
        else:
            self.append_log("Cancellation requested.")
            self.progress.set_text("Cancelling…")
            self.progress_detail.set_text("Stopping the read-only operation. No unverified download will be installed.")
        if self.cancel_path:
            try:
                fd = os.open(self.cancel_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                os.close(fd)
            except FileExistsError:
                pass
            except OSError as exc:
                self.append_log(f"Could not create cancellation marker: {exc}")
        process = self.process
        if process and process.poll() is None:
            schedule_process_group_termination(process, grace_seconds=5)
''', "main cancellation")

# FFU uses the shared process lifecycle without a local signal implementation.
ffu = "gui/rufusarm64_ffu_dialog.py"
replace_once(ffu, "import signal\n", "", "FFU signal import")
replace_once(ffu, "from rufusarm64_ffu_json import communicate_bounded, strict_json_loads\n", "from rufusarm64_ffu_json import communicate_bounded, strict_json_loads\nfrom rufusarm64_process import schedule_process_group_termination, terminate_and_reap, terminate_process_group\n", "FFU process imports")
replace_span(ffu, "def _terminate_process_group(process, force=False):", "\n\nclass FFUReviewDialog", "", "FFU local group helper")
text = read(ffu)
text = text.replace("terminate=lambda force: _terminate_process_group(process, force),", "terminate=lambda force: terminate_process_group(process, force=force),")
text = text.replace("_terminate_process_group(process)", "terminate_process_group(process)")
write(ffu, text)
replace_span(ffu, "    def cancel_restore(self, *_):", "\n    def _finish_restore", '''    def cancel_restore(self, *_):
        if not self.running or not self.restoring:
            return
        self.cancel_requested = True
        self.cancel_button.set_sensitive(False)
        self.status.set_text(
            "Cancellation requested. Waiting for the provider's final evidence; the target state is not yet known."
        )
        process = self.process
        if process is not None and process.poll() is None:
            schedule_process_group_termination(process, grace_seconds=5)
''', "FFU cancellation")

# Checksum one-shot capture.
checksums = "gui/rufusarm64_checksums.py"
replace_once(checksums, "import subprocess\n", "import subprocess\n", "checksum subprocess import")
replace_once(checksums, "from rufusarm64_logic import build_checksum_command, checksum_summary, normalize_checksum_result\n", "from rufusarm64_logic import build_checksum_command, checksum_summary, normalize_checksum_result\nfrom rufusarm64_process import run_bounded\n", "checksum process import")
replace_span(checksums, "    def _run(self, command, generation):", "\n    def _finish", '''    def _run(self, command, generation):
        payload = None
        failure = ""
        try:
            completed = run_bounded(
                command,
                stdout_limit=8 * 1024 * 1024,
                stderr_limit=1024 * 1024,
                timeout=900,
                label="checksum helper",
            )
            if completed.returncode != 0:
                failure = completed.stderr.strip() or "The checksum helper failed."
            elif not completed.stdout.strip():
                failure = "The checksum helper returned no result."
            else:
                normalized = normalize_checksum_result(json.loads(completed.stdout))
                expected_path = os.path.realpath(os.path.abspath(self.image_path))
                if normalized["path"] != expected_path:
                    failure = "The checksum helper result does not match the selected image."
                else:
                    payload = normalized
        except subprocess.TimeoutExpired:
            failure = "Checksum calculation exceeded the fifteen-minute safety limit."
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            failure = str(exc)
        GLib.idle_add(self._finish, generation, payload, failure)
''', "checksum worker")

# Non-bootable formatter.
nonboot = "gui/rufusarm64_nonbootable_dialog.py"
replace_once(nonboot, "import signal\n", "", "nonbootable signal import")
replace_once(nonboot, "from gi.repository import GLib, Gtk\n", "from gi.repository import GLib, Gtk\n\nfrom rufusarm64_process import communicate_bounded, run_bounded, terminate_and_reap\n", "nonbootable process import")
replace_span(nonboot, "    def _plan_worker(self, command, generation, scheme, filesystem, label):", "\n    def _plan_ready", '''    def _plan_worker(self, command, generation, scheme, filesystem, label):
        try:
            completed = run_bounded(
                command,
                stdout_limit=8 * 1024 * 1024,
                stderr_limit=1024 * 1024,
                timeout=30,
                label="non-bootable formatter plan helper",
            )
            if completed.returncode != 0:
                raise RuntimeError((completed.stderr or completed.stdout or "Formatting plan failed.").strip())
            payload = normalize_plan(json.loads(completed.stdout))
            if payload["plan"]["device_path"] != self.device or payload["identity"] != self.identity:
                raise ValueError("Formatting plan no longer refers to the selected device.")
            if (
                payload["plan"]["scheme"] != scheme
                or payload["plan"]["filesystem"] != filesystem
                or payload["plan"]["label"] != label
            ):
                raise ValueError("Formatting plan no longer matches the selected layout choices.")
            GLib.idle_add(self._plan_ready, generation, payload, "")
        except Exception as exc:
            GLib.idle_add(self._plan_ready, generation, None, str(exc))
''', "nonbootable plan worker")
replace_span(nonboot, "    def _run_worker(self, command, generation, reviewed):", "\n    def _run_ready", '''    def _run_worker(self, command, generation, reviewed):
        diagnostics = []
        diagnostics_size = 0
        payload = None
        returncode = 1
        process = None
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            self.process = process
            stdout, stderr = communicate_bounded(
                process,
                stdout_limit=8 * 1024 * 1024,
                stderr_limit=1024 * 1024,
                label="non-bootable formatter helper",
            )
            returncode = process.returncode
            self.process = None
            for line in stderr.splitlines():
                text = line.strip()
                if text and len(diagnostics) < 64 and diagnostics_size + len(text) <= 32768:
                    diagnostics.append(text)
                    diagnostics_size += len(text)
            if stdout.strip():
                payload = normalize_report(json.loads(stdout), reviewed)
            if payload is None:
                raise RuntimeError("Non-bootable formatting did not return its final report.")
            if (returncode == 0) != (payload["status"] == "passed"):
                raise ValueError("Formatting report status does not match the helper exit status.")
            GLib.idle_add(self._run_ready, generation, payload, "\n".join(diagnostics), returncode)
        except Exception as exc:
            self.process = None
            if process is not None and process.poll() is None:
                try:
                    terminate_and_reap(process)
                except (OSError, RuntimeError, ValueError):
                    pass
            detail = str(exc)
            if diagnostics:
                detail += "\n\nDiagnostics:\n" + "\n".join(diagnostics)
            GLib.idle_add(self._run_ready, generation, None, detail, returncode)
''', "nonbootable run worker")

# FreeDOS progress plus final report on separate pipes.
freedos = "gui/rufusarm64_freedos_dialog.py"
replace_once(freedos, "import signal\n", "", "FreeDOS signal import")
replace_once(freedos, "from gi.repository import GLib, Gtk\n", "from gi.repository import GLib, Gtk\n\nfrom rufusarm64_process import iter_bounded_process_utf8_lines, run_bounded, terminate_and_reap\n", "FreeDOS process import")
replace_span(freedos, "    def _plan_worker(self, command, generation, label):", "\n    def _plan_ready", '''    def _plan_worker(self, command, generation, label):
        try:
            completed = run_bounded(
                command,
                stdout_limit=8 * 1024 * 1024,
                stderr_limit=1024 * 1024,
                timeout=30,
                label="FreeDOS plan helper",
            )
            if completed.returncode != 0:
                raise RuntimeError((completed.stderr or completed.stdout or "FreeDOS planning failed.").strip())
            payload = normalize_plan(json.loads(completed.stdout))
            if payload["plan"]["device_path"] != self.device or payload["identity"] != self.identity:
                raise ValueError("FreeDOS plan no longer refers to the selected device.")
            if payload["plan"]["label"] != label:
                raise ValueError("FreeDOS plan no longer matches the selected volume label.")
            GLib.idle_add(self._plan_ready, generation, payload, "")
        except Exception as exc:
            GLib.idle_add(self._plan_ready, generation, None, str(exc))
''', "FreeDOS plan worker")
replace_span(freedos, "    def _run_worker(self, command, generation, reviewed):", "\n    def _progress_ready", '''    def _run_worker(self, command, generation, reviewed):
        diagnostics = []
        diagnostics_size = 0
        stdout_lines = []
        payload = None
        returncode = 1
        process = None
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            self.process = process
            last_done = 0
            for channel, line in iter_bounded_process_utf8_lines(
                process,
                stdout_line_limit=1024 * 1024,
                stdout_total_limit=8 * 1024 * 1024,
                stderr_line_limit=1024 * 1024,
                stderr_total_limit=64 * 1024 * 1024,
                label="FreeDOS creation helper",
            ):
                if channel == "stdout":
                    stdout_lines.append(line)
                    continue
                progress = decode_progress_line(line)
                if progress is not None:
                    progress = validate_progress_against_plan(progress, reviewed)
                    if progress["overall_done"] < last_done:
                        raise ValueError("FreeDOS helper progress moved backwards.")
                    last_done = progress["overall_done"]
                    GLib.idle_add(self._progress_ready, generation, progress)
                    continue
                text = line.strip()
                if text and len(diagnostics) < 64 and diagnostics_size + len(text) <= 32768:
                    diagnostics.append(text)
                    diagnostics_size += len(text)
            returncode = process.returncode
            self.process = None
            stdout = "".join(stdout_lines)
            if stdout.strip():
                payload = normalize_report(json.loads(stdout), reviewed)
            if payload is None:
                raise RuntimeError("FreeDOS creation did not return its final media-state report.")
            if (returncode == 0) != (payload["status"] == "succeeded"):
                raise ValueError("FreeDOS report status does not match the helper exit status.")
            GLib.idle_add(self._run_ready, generation, payload, "\n".join(diagnostics), returncode)
        except Exception as exc:
            self.process = None
            if process is not None and process.poll() is None:
                try:
                    terminate_and_reap(process)
                except (OSError, RuntimeError, ValueError):
                    pass
            detail = str(exc)
            if diagnostics:
                detail += "\n\nDiagnostics:\n" + "\n".join(diagnostics)
            GLib.idle_add(self._run_ready, generation, None, detail, returncode)
''', "FreeDOS run worker")

# Qualification and raw backup base dialog.
qualify = "gui/rufusarm64_device_qualify_dialog.py"
replace_once(qualify, "import signal\n", "", "qualification signal import")
replace_once(qualify, "from gi.repository import GLib, Gtk\n", "from gi.repository import GLib, Gtk\n\nfrom rufusarm64_process import (\n    communicate_bounded,\n    iter_bounded_process_utf8_lines,\n    run_bounded,\n    schedule_process_group_termination,\n    terminate_and_reap,\n)\n", "qualification process imports")
replace_class_method(qualify, "DeviceQualificationDialog", "_plan_worker(self, command):", "\n    def _plan_ready", '''    def _plan_worker(self, command):
        try:
            completed = run_bounded(
                command,
                stdout_limit=8 * 1024 * 1024,
                stderr_limit=1024 * 1024,
                timeout=30,
                label="USB qualification plan helper",
            )
            if completed.returncode != 0:
                raise RuntimeError((completed.stderr or completed.stdout or "Plan failed").strip())
            payload = normalize_plan(json.loads(completed.stdout))
            GLib.idle_add(self._plan_ready, payload, "")
        except Exception as exc:
            GLib.idle_add(self._plan_ready, None, str(exc))
''')
replace_class_method(qualify, "DeviceQualificationDialog", "_run_worker(self, command):", "\n    def _run_ready", '''    def _run_worker(self, command):
        process = None
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            self.process = process
            stdout, stderr = communicate_bounded(
                process,
                stdout_limit=8 * 1024 * 1024,
                stderr_limit=1024 * 1024,
                label="USB qualification helper",
            )
            returncode = process.returncode
            self.process = None
            payload = normalize_report(json.loads(stdout)) if stdout.strip() else None
            if payload is None:
                raise RuntimeError((stderr or "Qualification did not return a report.").strip())
            GLib.idle_add(self._run_ready, payload, stderr.strip(), returncode)
        except Exception as exc:
            self.process = None
            if process is not None and process.poll() is None:
                try:
                    terminate_and_reap(process)
                except (OSError, RuntimeError, ValueError):
                    pass
            GLib.idle_add(self._run_ready, None, str(exc), 1)
''')
replace_class_method(qualify, "DeviceQualificationDialog", "cancel_run(self, *_):", "\n\n\nclass DriveImageBackupDialog", '''    def cancel_run(self, *_):
        process = self.process
        if not process or process.poll() is not None:
            return
        self.status.set_text("Cancelling after the current I/O operation…")
        thread = schedule_process_group_termination(process, grace_seconds=5)
        if thread is None and process.poll() is None:
            self.status.set_text("Could not request cancellation of the owned qualification process group.")
''')
replace_class_method(qualify, "DriveImageBackupDialog", "_run_worker(self, command, generation):", "\n    def _progress_ready", '''    def _run_worker(self, command, generation):
        diagnostics = []
        diagnostics_size = 0
        stdout_lines = []
        payload = None
        returncode = 1
        process = None
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            self.process = process
            planned = int(self.plan["destination"]["required_bytes"])
            last_done = 0
            for channel, line in iter_bounded_process_utf8_lines(
                process,
                stdout_line_limit=1024 * 1024,
                stdout_total_limit=8 * 1024 * 1024,
                stderr_line_limit=1024 * 1024,
                stderr_total_limit=64 * 1024 * 1024,
                label="drive-image backup helper",
            ):
                if channel == "stdout":
                    stdout_lines.append(line)
                    continue
                progress = backup_decode_progress_line(line)
                if progress is not None:
                    if progress["total"] != planned or progress["done"] < last_done:
                        raise ValueError("Backup progress violated the planned byte accounting.")
                    last_done = progress["done"]
                    GLib.idle_add(self._progress_ready, generation, progress)
                    continue
                text = line.strip()
                if text and len(diagnostics) < 64 and diagnostics_size + len(text) <= 32768:
                    diagnostics.append(text)
                    diagnostics_size += len(text)
            returncode = process.returncode
            self.process = None
            stdout = "".join(stdout_lines)
            if stdout.strip():
                payload = backup_normalize_report(json.loads(stdout))
            if payload is None:
                raise RuntimeError("Drive-image backup did not return its final report.")
            if payload["planned_bytes"] != planned:
                raise ValueError("Backup report does not match the reviewed plan.")
            if (returncode == 0) != (payload["status"] == "passed"):
                raise ValueError("Backup report status does not match the helper exit status.")
            if payload["status"] == "passed":
                info = os.lstat(self.output_path)
                if not stat.S_ISREG(info.st_mode) or info.st_size != payload["completed_bytes"] or info.st_uid != os.getuid():
                    raise ValueError("The completed destination file does not match the verified report or desktop user.")
            GLib.idle_add(self._run_ready, generation, payload, "\n".join(diagnostics), returncode)
        except Exception as exc:
            self.process = None
            if process is not None and process.poll() is None:
                try:
                    terminate_and_reap(process)
                except (OSError, RuntimeError, ValueError):
                    pass
            detail = str(exc)
            if diagnostics:
                detail += "\n\nDiagnostics:\n" + "\n".join(diagnostics)
            GLib.idle_add(self._run_ready, generation, None, detail, returncode)
''')
replace_class_method(qualify, "DriveImageBackupDialog", "cancel_run(self, *_):", "\n    def on_delete_event", '''    def cancel_run(self, *_):
        process = self.process
        if not process or process.poll() is not None:
            return
        self.cancel_button.set_sensitive(False)
        self.status.set_text("Cancelling after the current read operation; incomplete temporary output will be removed…")
        self.progress.set_text("Cancelling safely…")
        thread = schedule_process_group_termination(process, grace_seconds=5)
        if thread is None and process.poll() is None:
            self.status.set_text("Could not request cancellation of the owned backup process group.")
''')

# Container backup extension.
formats = "gui/rufusarm64_drive_backup_formats.py"
replace_once(formats, "import signal\n", "", "container backup signal import")
replace_once(formats, "from gi.repository import GLib, Gtk\n", "from gi.repository import GLib, Gtk\n\nfrom rufusarm64_process import iter_bounded_process_utf8_lines, run_bounded, terminate_and_reap\n", "container backup process imports")
replace_span(formats, "    def format_plan_worker(dialog, command, generation, format_name, output_path):", "\n    def set_running", '''    def format_plan_worker(dialog, command, generation, format_name, output_path):
        try:
            completed = run_bounded(
                command,
                stdout_limit=8 * 1024 * 1024,
                stderr_limit=1024 * 1024,
                timeout=30,
                label="container backup plan helper",
            )
            if completed.returncode != 0:
                raise RuntimeError((completed.stderr or completed.stdout or "Backup planning failed.").strip())
            payload = backup_normalize_plan(json.loads(completed.stdout))
            if payload["device"]["path"] != dialog.device:
                raise ValueError("Backup plan no longer refers to the selected device.")
            if payload["identity"] != dialog.identity:
                raise ValueError("Backup plan no longer refers to the selected device identity.")
            if payload["destination"]["path"] != output_path:
                raise ValueError("Backup plan returned a different destination path.")
            if payload["destination"]["format"] != format_name:
                raise ValueError("Backup plan returned a different output format.")
            GLib.idle_add(dialog._plan_ready, generation, payload, "")
        except Exception as exc:
            GLib.idle_add(dialog._plan_ready, generation, None, str(exc))
''', "container backup plan worker")
replace_span(formats, "    def format_run_worker(dialog, command, generation):", "\n    def format_progress_ready", '''    def format_run_worker(dialog, command, generation):
        diagnostics = []
        diagnostics_size = 0
        stdout_lines = []
        payload = None
        returncode = 1
        process = None
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            dialog.process = process
            source_bytes = int(dialog.plan["destination"]["source_bytes"])
            planned_format = str(dialog.plan["destination"]["format"])
            last_by_phase = {}
            for channel, line in iter_bounded_process_utf8_lines(
                process,
                stdout_line_limit=1024 * 1024,
                stdout_total_limit=8 * 1024 * 1024,
                stderr_line_limit=1024 * 1024,
                stderr_total_limit=64 * 1024 * 1024,
                label="container backup helper",
            ):
                if channel == "stdout":
                    stdout_lines.append(line)
                    continue
                progress = backup_decode_progress_line(line)
                if progress is not None:
                    phase = progress["phase"]
                    if phase in _SOURCE_PHASES and progress["total"] != source_bytes:
                        raise ValueError("Backup progress violated the reviewed source capacity.")
                    if progress["done"] < last_by_phase.get(phase, 0):
                        raise ValueError("Backup progress moved backwards within a phase.")
                    last_by_phase[phase] = progress["done"]
                    GLib.idle_add(dialog._format_progress_ready, generation, progress)
                    continue
                text = line.strip()
                if text and len(diagnostics) < 64 and diagnostics_size + len(text) <= 32768:
                    diagnostics.append(text)
                    diagnostics_size += len(text)
            returncode = process.returncode
            dialog.process = None
            stdout = "".join(stdout_lines)
            if stdout.strip():
                payload = backup_normalize_report(json.loads(stdout))
            if payload is None:
                raise RuntimeError("Drive-image backup did not return its final report.")
            if payload["planned_bytes"] != source_bytes or payload["format"] != planned_format:
                raise ValueError("Backup report does not match the reviewed plan.")
            if (returncode == 0) != (payload["status"] == "passed"):
                raise ValueError("Backup report status does not match the helper exit status.")
            if payload["status"] == "passed":
                info = os.lstat(dialog.output_path)
                if not stat.S_ISREG(info.st_mode) or info.st_size != payload["output_bytes"] or info.st_uid != os.getuid():
                    raise ValueError("The completed destination file does not match the verified report or desktop user.")
            GLib.idle_add(dialog._run_ready, generation, payload, "\n".join(diagnostics), returncode)
        except Exception as exc:
            dialog.process = None
            if process is not None and process.poll() is None:
                try:
                    terminate_and_reap(process)
                except (OSError, RuntimeError, ValueError):
                    pass
            detail = str(exc)
            if diagnostics:
                detail += "\n\nDiagnostics:\n" + "\n".join(diagnostics)
            GLib.idle_add(dialog._run_ready, generation, None, detail, returncode)
''', "container backup run worker")

# Filesystem ISO backup extension.
iso = "gui/rufusarm64_drive_backup_iso.py"
replace_once(iso, "import signal\n", "", "ISO backup signal import")
replace_once(iso, "import rufusarm64_drive_backup_formats as formats\n", "import rufusarm64_drive_backup_formats as formats\nfrom rufusarm64_process import iter_bounded_process_utf8_lines, run_bounded, terminate_and_reap\n", "ISO process imports")
replace_span(iso, "    def format_plan_worker(dialog, command, generation, format_name, output_path):", "\n    def plan_ready", '''    def format_plan_worker(dialog, command, generation, format_name, output_path):
        if format_name != "iso":
            return original_plan_worker(dialog, command, generation, format_name, output_path)
        try:
            completed = run_bounded(
                command,
                stdout_limit=8 * 1024 * 1024,
                stderr_limit=1024 * 1024,
                timeout=120,
                label="filesystem ISO plan helper",
            )
            if completed.returncode != 0:
                raise RuntimeError((completed.stderr or completed.stdout or "Filesystem ISO planning failed.").strip())
            payload = normalize_plan(json.loads(completed.stdout))
            if payload["device"]["path"] != dialog.device:
                raise ValueError("ISO plan no longer refers to the selected drive.")
            if payload["identity"] != dialog.identity:
                raise ValueError("ISO plan no longer refers to the selected drive identity.")
            if payload["destination"]["path"] != output_path:
                raise ValueError("ISO plan returned a different destination path.")
            GLib.idle_add(dialog._plan_ready, generation, payload, "")
        except Exception as exc:
            GLib.idle_add(dialog._plan_ready, generation, None, str(exc))
''', "ISO plan worker")
replace_span(iso, "    def format_run_worker(dialog, command, generation):", "\n    def format_progress_ready", '''    def format_run_worker(dialog, command, generation):
        planned_format = str((dialog.plan or {}).get("destination", {}).get("format") or "")
        if planned_format != "iso":
            return original_run_worker(dialog, command, generation)
        diagnostics = []
        diagnostics_size = 0
        stdout_lines = []
        payload = None
        returncode = 1
        process = None
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            dialog.process = process
            plan = normalize_plan(dialog.plan)
            source_bytes = int(plan["filesystem_capture"]["source_bytes"])
            required_bytes = int(plan["filesystem_capture"]["required_bytes"])
            last_by_phase = {}
            for channel, line in iter_bounded_process_utf8_lines(
                process,
                stdout_line_limit=1024 * 1024,
                stdout_total_limit=8 * 1024 * 1024,
                stderr_line_limit=1024 * 1024,
                stderr_total_limit=64 * 1024 * 1024,
                label="filesystem ISO capture helper",
            ):
                if channel == "stdout":
                    stdout_lines.append(line)
                    continue
                progress = decode_progress_line(line)
                if progress is not None:
                    phase = progress["phase"]
                    if progress["done"] < last_by_phase.get(phase, 0):
                        raise ValueError("Filesystem ISO progress moved backwards within a phase.")
                    if phase == "master":
                        total = progress["total"]
                        if total > required_bytes or (total not in {0, required_bytes} and progress["done"] != total):
                            raise ValueError("Filesystem ISO mastering progress violated the admitted bound.")
                    if phase == "validate_content" and progress["total"] > source_bytes:
                        raise ValueError("Filesystem ISO validation progress exceeded the reviewed content size.")
                    if progress["total"] > required_bytes and phase not in {"validate_content"}:
                        raise ValueError("Filesystem ISO progress exceeded the reviewed destination bound.")
                    last_by_phase[phase] = progress["done"]
                    GLib.idle_add(dialog._format_progress_ready, generation, progress)
                    continue
                text = line.strip()
                if text and len(diagnostics) < 64 and diagnostics_size + len(text) <= 32768:
                    diagnostics.append(text)
                    diagnostics_size += len(text)
            returncode = process.returncode
            dialog.process = None
            stdout = "".join(stdout_lines)
            if stdout.strip():
                payload = normalize_report(json.loads(stdout))
            if payload is None:
                raise RuntimeError("Filesystem ISO capture did not return its final report.")
            if payload["source_device"] != dialog.device:
                raise ValueError("Filesystem ISO report refers to a different source disk.")
            if payload["source_node"] != plan["source_node"]:
                raise ValueError("Filesystem ISO report refers to a different mounted source node.")
            if payload["source_mount"] != plan["filesystem_capture"]["source_mount"]:
                raise ValueError("Filesystem ISO report refers to a different source mountpoint.")
            if payload["destination"] != dialog.output_path:
                raise ValueError("Filesystem ISO report refers to a different destination.")
            if payload["status"] == "passed":
                if payload["source_bytes"] != source_bytes or payload["required_bytes"] != required_bytes:
                    raise ValueError("Successful filesystem ISO report does not match the reviewed plan.")
                if payload["source_content_sha256"] != plan["filesystem_capture"]["source_content_sha256"]:
                    raise ValueError("Successful filesystem ISO report contains different source content.")
            elif payload["source_bytes"] not in {0, source_bytes} or payload["required_bytes"] not in {0, required_bytes}:
                raise ValueError("Filesystem ISO failure report contains impossible plan evidence.")
            if (returncode == 0) != (payload["status"] == "passed"):
                raise ValueError("Filesystem ISO report status does not match the helper exit status.")
            if payload["status"] == "passed":
                info = os.lstat(dialog.output_path)
                if not stat.S_ISREG(info.st_mode) or info.st_size != payload["output_bytes"] or info.st_uid != os.getuid():
                    raise ValueError("The completed ISO does not match the verified report or desktop user.")
            GLib.idle_add(dialog._run_ready, generation, payload, "\n".join(diagnostics), returncode)
        except Exception as exc:
            dialog.process = None
            if process is not None and process.poll() is None:
                try:
                    terminate_and_reap(process)
                except (OSError, RuntimeError, ValueError):
                    pass
            detail = str(exc)
            if diagnostics:
                detail += "\n\nDiagnostics:\n" + "\n".join(diagnostics)
            GLib.idle_add(dialog._run_ready, generation, None, detail, returncode)
''', "ISO run worker")

# Deterministic source inventory prevents future direct signal/unbounded-stream regressions.
contract_path = "gui/test_remaining_process_workers.py"
contract = '''from pathlib import Path
import unittest


GUI = Path(__file__).resolve().parent


class RemainingProcessWorkerContractTests(unittest.TestCase):
    def test_remaining_gui_workers_use_shared_bounded_process_contract(self):
        required = {
            "rufusarm64.py": ("communicate_bounded(", "iter_bounded_utf8_lines(", "schedule_process_group_termination("),
            "rufusarm64_checksums.py": ("run_bounded(",),
            "rufusarm64_ffu_dialog.py": ("communicate_bounded(", "schedule_process_group_termination("),
            "rufusarm64_freedos_dialog.py": ("iter_bounded_process_utf8_lines(", "run_bounded("),
            "rufusarm64_nonbootable_dialog.py": ("communicate_bounded(", "run_bounded("),
            "rufusarm64_device_qualify_dialog.py": ("communicate_bounded(", "iter_bounded_process_utf8_lines(", "schedule_process_group_termination("),
            "rufusarm64_drive_backup_formats.py": ("iter_bounded_process_utf8_lines(", "run_bounded("),
            "rufusarm64_drive_backup_iso.py": ("iter_bounded_process_utf8_lines(", "run_bounded("),
        }
        forbidden = ("os.killpg(", "process.terminate()", "for line in process.stderr", "process.stdout.read()")
        for name, markers in required.items():
            with self.subTest(file=name):
                source = (GUI / name).read_text(encoding="utf-8")
                for marker in markers:
                    self.assertIn(marker, source)
                for marker in forbidden:
                    self.assertNotIn(marker, source)


if __name__ == "__main__":
    unittest.main()
'''
write(contract_path, contract)

# Remove the helper-process residual and add exact executable rows.
matrix_path = "docs/interruption-qualification.json"
matrix = json.loads(read(matrix_path))
old_gaps = matrix["residual_software_gaps"]
matrix["residual_software_gaps"] = [gap for gap in old_gaps if gap.get("id") != "gap-helper-process-cleanup"]
if len(matrix["residual_software_gaps"]) != len(old_gaps) - 1:
    raise SystemExit("helper-process residual row changed")
rows = [
    {
        "id": "remaining-gui-helper-worker-contract",
        "boundary": "helper-process-cleanup",
        "component": "primary acquisition, checksum, writer, formatter, qualification, backup, ISO, FreeDOS, and FFU GTK workers",
        "failure_mode": "a remaining GTK helper hangs, overproduces output, returns non-UTF-8 evidence, or ignores cancellation while both pipes are live",
        "phase": "process-interruption",
        "status": "automated",
        "test_file": "gui/test_remaining_process_workers.py",
        "test_name": "test_remaining_gui_workers_use_shared_bounded_process_contract",
        "platforms": ["linux-amd64", "linux-arm64"],
        "invariant": "Every remaining reviewed GTK helper uses package-owned bounded capture or concurrent streaming, owned process groups, forced escalation where cancellation signals are allowed, and workflow-specific final-evidence handling.",
    },
    {
        "id": "dual-pipe-progress-report-bounds",
        "boundary": "helper-process-cleanup",
        "component": "helpers that stream progress on stderr and publish final JSON on stdout",
        "failure_mode": "one pipe fills, a line or channel exceeds its bound, or a descendant ignores SIGTERM",
        "phase": "process-interruption",
        "status": "automated",
        "test_file": "gui/test_process_cleanup.py",
        "test_name": "test_two_pipe_streaming_is_concurrent_bounded_and_reaped",
        "platforms": ["linux-amd64", "linux-arm64"],
        "invariant": "Both pipes are drained concurrently with independent line and total limits, output remains strict UTF-8, and the owned group is reaped without accepting incomplete final evidence.",
    },
]
existing = {entry["id"] for entry in matrix["entries"]}
if existing.intersection(row["id"] for row in rows):
    raise SystemExit("remaining helper rows already exist")
physical_index = next((i for i, entry in enumerate(matrix["entries"]) if entry.get("status") == "physical-only"), len(matrix["entries"]))
matrix["entries"][physical_index:physical_index] = rows
write(matrix_path, json.dumps(matrix, indent=2, ensure_ascii=False) + "\n")

# Documentation and changelog.
docs = "docs/interruption-crash-consistency.md"
replace_once(
    docs,
    "The inventory deliberately keeps uncovered software cases visible. A missing general partition/filesystem mutation or remaining workflow-specific helper-process cleanup case may not disappear from review merely because persistence, FFU, or another component has a shared utility test.",
    "The inventory deliberately keeps uncovered software cases visible. The helper-process boundary is now represented by shared runtime and exact source-contract tests; the remaining software residual is destructive partition/filesystem mutation qualification.",
    "interruption documentation residual text",
)
changelog = "CHANGELOG.md"
anchor = "- Added package-owned bounded helper-process utilities and migrated FFU capture plus persistence analysis and creation to tested process-group escalation, bounded binary capture, bounded UTF-8 line streaming, pipe closure, and reaping.\n"
replace_once(
    changelog,
    anchor,
    anchor + "- Migrated the remaining GTK acquisition, checksum, writer, formatter, qualification, backup, ISO, FreeDOS, and FFU workers to shared bounded one-shot or concurrent two-pipe process contracts, closing the helper-process interruption residual.\n",
    "remaining helper changelog",
)

# Remove bootstrap files before focused/full qualification.
run("git", "rm", "-f", "--ignore-unmatch", ".github/remaining-process-once.py", ".github/workflows/remaining-process-once.yml")
run("python3", "-m", "py_compile",
    "gui/rufusarm64_process.py", "gui/rufusarm64.py", "gui/rufusarm64_checksums.py",
    "gui/rufusarm64_ffu_dialog.py", "gui/rufusarm64_freedos_dialog.py",
    "gui/rufusarm64_nonbootable_dialog.py", "gui/rufusarm64_device_qualify_dialog.py",
    "gui/rufusarm64_drive_backup_formats.py", "gui/rufusarm64_drive_backup_iso.py",
    "gui/test_process_cleanup.py", "gui/test_remaining_process_workers.py")
run("python3", "-m", "unittest", "gui.test_process_cleanup", "gui.test_remaining_process_workers")
run("python3", "-m", "unittest", "discover", "-s", "gui", "-p", "test_*.py")
run("go", "test", "./internal/qualification")
run("git", "add", "CHANGELOG.md", "docs/interruption-crash-consistency.md", "docs/interruption-qualification.json", "gui", "scripts/build-deb.sh")
run("git", "config", "user.name", "github-actions[bot]")
run("git", "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com")
run("git", "commit", "-m", "reliability: bound remaining GTK helper workers")
run("git", "push", "--force", "origin", "HEAD:feature/remaining-helper-process-workers")
