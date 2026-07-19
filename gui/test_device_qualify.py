import json
import unittest

from rufusarm64_device_qualify import (
    build_dry_run_command,
    build_run_command,
    decode_json_output,
    normalize_plan,
    normalize_report,
    plan_summary,
    report_summary,
)


class DeviceQualificationLogicTests(unittest.TestCase):
    def test_dry_run_command_is_unprivileged_and_identity_bound(self):
        self.assertEqual(
            build_dry_run_command("/usr/bin/rufusarm64-device-qualify", "/dev/sdb", "identity", "quick"),
            [
                "/usr/bin/rufusarm64-device-qualify",
                "--device",
                "/dev/sdb",
                "--expected-identity",
                "identity",
                "--profile",
                "quick",
                "--dry-run",
                "--json",
            ],
        )

    def test_run_command_requires_pkexec_and_explicit_identity(self):
        self.assertEqual(
            build_run_command("/usr/bin/pkexec", "/usr/bin/rufusarm64-device-qualify", "/dev/sdc", "token", "full"),
            [
                "/usr/bin/pkexec",
                "/usr/bin/rufusarm64-device-qualify",
                "--device",
                "/dev/sdc",
                "--expected-identity",
                "token",
                "--profile",
                "full",
                "--yes",
                "--json",
            ],
        )
        with self.assertRaises(ValueError):
            build_run_command("", "/usr/bin/tool", "/dev/sdc", "token", "quick")
        with self.assertRaises(ValueError):
            build_run_command("/usr/bin/pkexec", "/usr/bin/tool", "/dev/sdc", "", "quick")

    def test_plan_normalization_and_summary(self):
        payload = {
            "device": {"path": "/dev/sdb", "model": "USB Test"},
            "identity": "abc",
            "plan": {
                "profile": "quick",
                "planned_bytes": 8 * 1024 * 1024,
                "regions": [{"offset": 0, "length": 4}, {"offset": 8, "length": 4}],
            },
        }
        normalized = normalize_plan(payload)
        self.assertEqual(normalized["identity"], "abc")
        self.assertIn("Quick qualification", plan_summary(payload))
        self.assertIn("8.0 MiB", plan_summary(payload))
        with self.assertRaises(ValueError):
            normalize_plan({"device": {}, "identity": "abc", "plan": {"regions": []}})

    def test_report_normalization_and_user_summaries(self):
        passed = {"schema": 1, "status": "passed", "completed_bytes": 4096, "passes": []}
        self.assertEqual(normalize_report(passed)["status"], "passed")
        self.assertIn("passed", report_summary(passed))

        failed = {
            "schema": 1,
            "status": "failed",
            "completed_bytes": 8192,
            "passes": [],
            "aliasing_detected": True,
            "failure": {"message": "sentinel changed"},
        }
        summary = report_summary(failed)
        self.assertIn("failed", summary)
        self.assertIn("False-capacity", summary)
        self.assertIn("sentinel changed", summary)

        cancelled = {"schema": 1, "status": "cancelled", "completed_bytes": 10, "passes": []}
        self.assertIn("cancelled", report_summary(cancelled))

    def test_json_decode_and_schema_rejection(self):
        self.assertEqual(decode_json_output(json.dumps({"schema": 1}), "test"), {"schema": 1})
        with self.assertRaises(ValueError):
            decode_json_output("not-json", "test")
        with self.assertRaises(ValueError):
            normalize_report({"schema": 2, "status": "passed", "passes": []})


if __name__ == "__main__":
    unittest.main()
