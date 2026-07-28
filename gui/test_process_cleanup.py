import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parent))
from rufusarm64_process import (  # noqa: E402
    OutputLimitError,
    communicate_bounded,
    iter_bounded_utf8_lines,
    schedule_process_group_termination,
    terminate_and_reap,
    terminate_process_group,
)


class OwnedProcessGroupTests(unittest.TestCase):
    def start(self, code, *, merged=False):
        return subprocess.Popen(
            [sys.executable, "-c", code],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT if merged else subprocess.PIPE,
            start_new_session=True,
        )

    def test_schedule_escalates_group_when_parent_and_descendant_ignore_sigterm(self):
        with tempfile.TemporaryDirectory() as directory:
            child_path = os.path.join(directory, "child.pid")
            code = (
                "import os, signal, subprocess, sys, time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "child=subprocess.Popen([sys.executable, '-c', "
                "'import signal,time,os; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)']); "
                f"open({child_path!r}, 'w').write(str(child.pid)); "
                "print('ready', flush=True); time.sleep(30)"
            )
            process = self.start(code)
            self.assertEqual(process.stdout.readline(), b"ready\n")
            thread = schedule_process_group_termination(process, grace_seconds=0.1)
            self.assertIsNotNone(thread)
            process.wait(timeout=5)
            thread.join(timeout=5)
            self.assertIsNotNone(process.returncode)
            child_pid = int(Path(child_path).read_text(encoding="utf-8"))
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    os.kill(child_pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.02)
            else:
                self.fail("descendant survived owned process-group SIGKILL escalation")
            process.stdout.close()
            process.stderr.close()

    def test_terminate_group_is_race_safe_for_already_exited_process(self):
        process = self.start("print('done')")
        process.communicate(timeout=5)
        self.assertFalse(terminate_process_group(process))
        self.assertIsNone(schedule_process_group_termination(process, grace_seconds=0.1))

    def test_terminate_and_reap_closes_pipes_and_forces_ignored_sigterm(self):
        process = self.start(
            "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); print('ready', flush=True); time.sleep(30)"
        )
        self.assertEqual(process.stdout.readline(), b"ready\n")
        returncode = terminate_and_reap(process, terminate_timeout=0.1, kill_timeout=2)
        self.assertEqual(returncode, process.returncode)
        self.assertIsNotNone(returncode)
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)


class BoundedCaptureTests(unittest.TestCase):
    def start(self, code):
        return subprocess.Popen(
            [sys.executable, "-c", code],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )

    def communicate(self, process, **kwargs):
        return communicate_bounded(
            process,
            stdout_limit=kwargs.pop("stdout_limit", 4096),
            stderr_limit=kwargs.pop("stderr_limit", 4096),
            terminate=lambda force: terminate_process_group(process, force=force),
            label="test helper",
            **kwargs,
        )

    def test_success_reaps_and_closes_both_pipes(self):
        process = self.start("import sys; print('ok'); print('diag', file=sys.stderr)")
        self.assertEqual(self.communicate(process), ("ok\n", "diag\n"))
        self.assertEqual(process.returncode, 0)
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)

    def test_stdout_and_stderr_limits_force_owned_group_shutdown(self):
        for channel in ("stdout", "stderr"):
            with self.subTest(channel=channel):
                destination = "sys.stdout" if channel == "stdout" else "sys.stderr"
                process = self.start(
                    f"import signal,sys,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); {destination}.write('x'*10000); {destination}.flush(); time.sleep(30)"
                )
                arguments = {f"{channel}_limit": 100, "termination_grace": 0.1}
                with self.assertRaises(OutputLimitError):
                    self.communicate(process, **arguments)
                self.assertIsNotNone(process.returncode)
                self.assertTrue(process.stdout.closed)
                self.assertTrue(process.stderr.closed)

    def test_timeout_forces_reaping(self):
        process = self.start(
            "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)"
        )
        with self.assertRaises(subprocess.TimeoutExpired):
            self.communicate(process, timeout=0.1, termination_grace=0.1)
        self.assertIsNotNone(process.returncode)
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)

    def test_non_utf8_output_is_rejected_after_reaping(self):
        process = self.start("import os; os.write(1, b'\\xff')")
        with self.assertRaisesRegex(ValueError, "non-UTF-8"):
            self.communicate(process)
        self.assertEqual(process.returncode, 0)
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)


class BoundedLineTests(unittest.TestCase):
    def start(self, code):
        return subprocess.Popen(
            [sys.executable, "-c", code],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

    def test_bounded_utf8_lines(self):
        process = self.start("print('one'); print('two')")
        lines = list(iter_bounded_utf8_lines(process.stdout, line_limit=16, total_limit=32))
        self.assertEqual(lines, ["one\n", "two\n"])
        self.assertEqual(process.wait(timeout=5), 0)
        process.stdout.close()

    def test_oversized_line_is_rejected_and_process_can_be_reaped(self):
        process = self.start(
            "import signal,sys,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); sys.stdout.write('x'*10000); sys.stdout.flush(); time.sleep(30)"
        )
        with self.assertRaises(OutputLimitError):
            list(iter_bounded_utf8_lines(process.stdout, line_limit=100, total_limit=200))
        terminate_and_reap(process, terminate_timeout=0.1, kill_timeout=2)
        self.assertIsNotNone(process.returncode)
        self.assertTrue(process.stdout.closed)

    def test_total_limit_and_non_utf8_are_rejected(self):
        process = self.start("print('12345678'); print('12345678')")
        with self.assertRaises(OutputLimitError):
            list(iter_bounded_utf8_lines(process.stdout, line_limit=16, total_limit=12))
        terminate_and_reap(process, terminate_timeout=0.1, kill_timeout=2)

        process = self.start("import os; os.write(1, b'\\xff\\n')")
        with self.assertRaisesRegex(ValueError, "non-UTF-8"):
            list(iter_bounded_utf8_lines(process.stdout, line_limit=16, total_limit=32))
        self.assertEqual(process.wait(timeout=5), 0)
        process.stdout.close()


if __name__ == "__main__":
    unittest.main()
