import unittest

from rufusarm64_device_qualify import (
    build_qualification_command,
    normalize_qualification_event,
    normalize_qualification_profile,
    normalize_qualification_report,
    qualification_progress_fraction,
    qualification_progress_text,
    qualification_result_summary,
)


def human_bytes(value):
    return f"{int(value)} B"


class DeviceQualificationLogicTests(unittest.TestCase):
    def test_profiles_are_normalized(self):
        self.assertEqual(normalize_qualification_profile(" QUICK "), "quick")
        self.assertEqual(normalize_qualification_profile("full"), "full")
        with self.assertRaises(ValueError):
            normalize_qualification_profile("sample")

    def test_command_is_identity_bound_and_noninteractive(self):
        self.assertEqual(
            build_qualification_command(
                "/usr/bin/pkexec",
                "/usr/lib/rufusarm64/rufusarm64-device-qualify",
                "/dev/sdb",
                "identity-token",
                "full",
            ),
            [
                "/usr/bin/pkexec",
                "/usr/lib/rufusarm64/rufusarm64-device-qualify",
                "--device",
                "/dev/sdb",
                "--expected-identity",
                "identity-token",
                "--profile",
                "full",
                "--yes",
                "--json-progress",
            ],
        )

    def test_command_rejects_missing_safety_inputs(self):
        cases = [
            ("", "/helper", "/dev/sdb", "identity"),
            ("/pkexec", "", "/dev/sdb", "identity"),
            ("/pkexec", "/helper", "sdb", "identity"),
            ("/pkexec", "/helper", "/dev/sdb", ""),
        ]
        for values in cases:
            with self.subTest(values=values):
                with self.assertRaises(ValueError):
                    build_qualification_command(*values)

    def report(self, **overrides):
        payload = {
            "schema": 1,
            "profile": "quick",
            "capacity": 1000,
            "region_size": 100,
            "region_count": 10,
            "sentinel_count": 10,
            "pattern_count": 2,
            "planned_bytes": 2000,
            "completed_bytes": 2000,
            "status": "passed",
            "aliasing_detected": False,
            "passes": [],
        }
        payload.update(overrides)
        return payload

    def test_passed_report_is_normalized(self):
        report = normalize_qualification_report(self.report(profile=" FULL "))
        self.assertEqual(report["profile"], "full")
        self.assertEqual(report["status"], "passed")
        self.assertIsNone(report["failure"])

    def test_failed_report_requires_failure_details(self):
        with self.assertRaises(ValueError):
            normalize_qualification_report(self.report(status="failed"))
        report = normalize_qualification_report(
            self.report(
                status="failed",
                completed_bytes=500,
                failure={"kind": "mismatch", "byte_offset": 123, "message": "read-back mismatch"},
            )
        )
        self.assertEqual(report["failure"]["byte_offset"], 123)

    def test_report_rejects_invalid_contracts(self):
        invalid = [
            None,
            self.report(schema=2),
            self.report(status="unknown"),
            self.report(status="passed", failure={"kind": "mismatch"}),
            self.report(completed_bytes=2001),
            self.report(passes={}),
            self.report(capacity=-1),
        ]
        for payload in invalid:
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    normalize_qualification_report(payload)

    def test_progress_and_result_events_are_normalized(self):
        progress = normalize_qualification_event(
            {
                "event": "progress",
                "stage": "verify",
                "pass": 2,
                "pattern": "address-b",
                "done": 50,
                "total": 100,
                "offset": 4096,
            }
        )
        self.assertEqual(progress["stage"], "verify")
        self.assertEqual(progress["done"], 50)
        result = normalize_qualification_event({"event": "result", "report": self.report()})
        self.assertEqual(result["report"]["status"], "passed")

    def test_invalid_events_fail_closed(self):
        invalid = [
            None,
            {},
            {"event": "unknown"},
            {"event": "progress", "done": 101, "total": 100},
            {"event": "progress", "pass": -1},
            {"event": "result", "report": {"schema": 2}},
        ]
        for payload in invalid:
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    normalize_qualification_event(payload)

    def test_progress_is_bounded_and_readable(self):
        self.assertEqual(qualification_progress_fraction(50, 100), 0.5)
        self.assertEqual(qualification_progress_fraction(120, 100), 1.0)
        self.assertEqual(qualification_progress_fraction(1, 0), 0.0)
        self.assertEqual(
            qualification_progress_text("verify", 2, "address-b", 50, 100, human_bytes),
            "Verify (pass 2, address-b): 50.0% — 50 B of 100 B",
        )

    def test_result_summaries_distinguish_outcomes(self):
        self.assertIn("passed", qualification_result_summary(self.report(), human_bytes))
        self.assertIn(
            "cancelled",
            qualification_result_summary(self.report(status="cancelled", completed_bytes=500), human_bytes),
        )
        failed = self.report(
            status="failed",
            completed_bytes=500,
            aliasing_detected=True,
            failure={"kind": "alias", "byte_offset": 64, "message": "sentinel changed"},
        )
        summary = qualification_result_summary(failed, human_bytes)
        self.assertIn("failed", summary)
        self.assertIn("false-capacity", summary)
        self.assertIn("byte 64", summary)


if __name__ == "__main__":
    unittest.main()
