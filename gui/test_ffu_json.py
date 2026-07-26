import os
from pathlib import Path
import signal
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rufusarm64_ffu_json import (  # noqa: E402
    FFUOutputLimitError,
    communicate_bounded,
    strict_json_loads,
)


def group_terminate(process):
    def terminate(force):
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL if force else signal.SIGTERM)

    return terminate


class StrictJSONTests(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(strict_json_loads('{"a":{"b":1}}'), {"a": {"b": 1}})

    def test_duplicate(self):
        for data in ('{"a":1,"a":2}', '{"a":{"b":1,"b":2}}', '{"a":1,"\\u0061":2}'):
            with self.assertRaisesRegex(ValueError, "Duplicate JSON key"):
                strict_json_loads(data)

    def test_nonstandard_constant(self):
        with self.assertRaisesRegex(ValueError, "Unsupported JSON constant"):
            strict_json_loads('{"value":NaN}')


class BoundedProcessTests(unittest.TestCase):
    def run_process(self, code, **kwargs):
        process = subprocess.Popen(
            [sys.executable, "-c", code],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        return process, communicate_bounded(
            process,
            terminate=group_terminate(process),
            **kwargs,
        )

    def test_success(self):
        process, output = self.run_process(
            "import sys; print('ok'); print('diag', file=sys.stderr)"
        )
        self.assertEqual(process.returncode, 0)
        self.assertEqual(output, ("ok\n", "diag\n"))

    def test_stdout_limit(self):
        process = subprocess.Popen(
            [sys.executable, "-c", "import sys; sys.stdout.write('x'*10000); sys.stdout.flush()"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        with self.assertRaises(FFUOutputLimitError):
            communicate_bounded(
                process,
                stdout_limit=100,
                terminate=group_terminate(process),
            )
        self.assertIsNotNone(process.returncode)

    def test_stderr_limit(self):
        process = subprocess.Popen(
            [sys.executable, "-c", "import sys; sys.stderr.write('x'*10000); sys.stderr.flush()"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        with self.assertRaises(FFUOutputLimitError):
            communicate_bounded(
                process,
                stderr_limit=100,
                terminate=group_terminate(process),
            )
        self.assertIsNotNone(process.returncode)

    def test_timeout(self):
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        with self.assertRaises(subprocess.TimeoutExpired):
            communicate_bounded(
                process,
                timeout=0.1,
                terminate=group_terminate(process),
            )
        self.assertIsNotNone(process.returncode)

    def test_non_utf8_output(self):
        process = subprocess.Popen(
            [sys.executable, "-c", "import os; os.write(1, b'\\xff')"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        with self.assertRaisesRegex(ValueError, "non-UTF-8"):
            communicate_bounded(process, terminate=group_terminate(process))
        self.assertEqual(process.returncode, 0)


if __name__ == "__main__":
    unittest.main()
