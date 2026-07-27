import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from rufusarm64_freedos import PROGRESS_PREFIX, decode_progress_line, progress_summary


class FreeDOSProgressTests(unittest.TestCase):
    def record(self, **updates):
        value = {
            "schema": 1,
            "type": "progress",
            "phase": "write",
            "done": 50,
            "total": 100,
            "overall_done": 50,
            "overall_total": 200,
            "elapsed_ms": 1000,
            "bytes_per_second": 50,
            "eta_seconds": 3,
        }
        value.update(updates)
        return value

    def test_decodes_prefixed_progress_and_renders_phase(self):
        progress = decode_progress_line(PROGRESS_PREFIX + json.dumps(self.record()))
        self.assertEqual(progress["overall_done"], 50)
        summary = progress_summary(progress)
        self.assertIn("Writing required boot and filesystem regions", summary)
        self.assertIn("25.0%", summary)
        self.assertNotIn("full device", summary)

    def test_ignores_diagnostics_and_rejects_malformed_progress(self):
        self.assertIsNone(decode_progress_line("ordinary diagnostic"))
        with self.assertRaisesRegex(ValueError, "malformed progress JSON"):
            decode_progress_line(PROGRESS_PREFIX + "{")
        with self.assertRaisesRegex(ValueError, "exceeds"):
            decode_progress_line(PROGRESS_PREFIX + json.dumps(self.record(overall_done=201)))


if __name__ == "__main__":
    unittest.main()
