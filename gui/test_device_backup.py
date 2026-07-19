import json
import os
import tempfile
import unittest

from rufusarm64_device_backup import (
    build_dry_run_command,
    build_run_command,
    confirmation_phrase,
    decode_progress_line,
    normalize_plan,
    normalize_progress,
    normalize_report,
    plan_summary,
    progress_summary,
    report_summary,
)


class DeviceBackupLogicTests(unittest.TestCase):
    def test_dry_run_command_is_unprivileged_and_identity_bound(self):
        self.assertEqual(
            build_dry_run_command(
                "/usr/bin/rufusarm64-device-backup",
                "/dev/sdb",
                "identity",
                "/home/user/backup.img",
            ),
            [
                "/usr/bin/rufusarm64-device-backup",
                "--device",
                "/dev/sdb",
                "--output",
                "/home/user/backup.img",
                "--expected-identity",
                "identity",
                "--dry-run",
                "--json",
            ],
        )

    def test_run_command_uses_guarded_graphical_contract(self):
        self.assertEqual(
            build_run_command(
                "/usr/bin/pkexec",
                "/usr/bin/rufusarm64-device-backup",
                "/dev/sdc",
                "token",
                "/home/user/backup.img",
            ),
            [
                "/usr/bin/pkexec",
                "/usr/bin/rufusarm64-device-backup",
                "--device",
                "/dev/sdc",
                "--output",
                "/home/user/backup.img",
                "--expected-identity",
                "token",
                "--yes",
                "--json",
                "--progress-json",
            ],
        )
        with self.assertRaises(ValueError):
            build_run_command("", "/usr/bin/tool", "/dev/sdc", "token", "/tmp/out.img")
        with self.assertRaises(ValueError):
            build_run_command("/usr/bin/pkexec", "/usr/bin/tool", "/dev/sdc", "", "/tmp/out.img")
        with self.assertRaises(ValueError):
            build_run_command("/usr/bin/pkexec", "/usr/bin/tool", "/dev/sdc", "token", "relative.img")

    def test_existing_destination_and_links_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            existing = os.path.join(directory, "existing.img")
            with open(existing, "wb") as handle:
                handle.write(b"keep")
            with self.assertRaisesRegex(ValueError, "never replaced"):
                build_dry_run_command("/usr/bin/tool", "/dev/sdb", "identity", existing)

            link = os.path.join(directory, "link.img")
            os.symlink(existing, link)
            with self.assertRaisesRegex(ValueError, "never replaced"):
                build_run_command("/usr/bin/pkexec", "/usr/bin/tool", "/dev/sdb", "identity", link)

    def test_confirmation_phrase_binds_source_and_destination(self):
        self.assertEqual(
            confirmation_phrase("/dev/sdb", "/home/user/backup.img"),
            "SAVE /dev/sdb TO /home/user/backup.img",
        )
        with self.assertRaises(ValueError):
            confirmation_phrase("sdb", "/home/user/backup.img")
        with self.assertRaises(ValueError):
            confirmation_phrase("/dev/sdb", "backup.img")

    def test_plan_normalization_and_summary(self):
        payload = {
            "device": {
                "path": "/dev/sdb",
                "vendor": "USB",
                "model": "Test",
                "size": 8 * 1024 * 1024,
            },
            "identity": "abc",
            "destination": {
                "path": "/home/user/backup.img",
                "directory": "/home/user",
                "required_bytes": 8 * 1024 * 1024,
                "available_bytes": 32 * 1024 * 1024,
            },
        }
        normalized = normalize_plan(payload)
        self.assertEqual(normalized["identity"], "abc")
        summary = plan_summary(payload)
        self.assertIn("USB Test", summary)
        self.assertIn("8.0 MiB", summary)
        self.assertIn("Destination filesystem: /home/user", summary)
        with self.assertRaises(ValueError):
            normalize_plan({"device": {}, "identity": "abc", "destination": {}})
        with self.assertRaises(ValueError):
            normalize_plan(
                {
                    "device": {"path": "/dev/sdb", "size": 2},
                    "identity": "abc",
                    "destination": {
                        "path": "/tmp/out.img",
                        "directory": "/tmp",
                        "required_bytes": 2,
                        "available_bytes": 1,
                    },
                }
            )
        with self.assertRaises(ValueError):
            normalize_plan(
                {
                    **payload,
                    "device": {**payload["device"], "size": payload["device"]["size"] - 1},
                }
            )

    def test_progress_normalization_decode_and_summary(self):
        payload = {
            "schema": 1,
            "type": "progress",
            "done": 512,
            "total": 1024,
            "elapsed_ms": 2000,
            "bytes_per_second": 256,
            "eta_seconds": 2,
        }
        self.assertEqual(normalize_progress(payload)["done"], 512)
        self.assertEqual(decode_progress_line(json.dumps(payload))["eta_seconds"], 2)
        self.assertIsNone(decode_progress_line("authentication message"))
        self.assertIn("50.0%", progress_summary(payload))
        self.assertIn("256 B/s", progress_summary(payload))
        with self.assertRaises(ValueError):
            normalize_progress({**payload, "done": 2048})
        with self.assertRaises(ValueError):
            normalize_progress({**payload, "schema": 2})

    def test_report_normalization_and_user_summaries(self):
        digest = "a" * 64
        passed = {
            "schema": 1,
            "status": "passed",
            "planned_bytes": 4096,
            "completed_bytes": 4096,
            "sha256": digest,
        }
        self.assertEqual(normalize_report(passed)["status"], "passed")
        summary = report_summary(passed, "/tmp/backup.img")
        self.assertIn("/tmp/backup.img", summary)
        self.assertIn(digest, summary)

        failed = {
            "schema": 1,
            "status": "failed",
            "planned_bytes": 4096,
            "completed_bytes": 1024,
            "failure": {"message": "read failed"},
        }
        self.assertIn("read failed", report_summary(failed, "/tmp/backup.img"))

        cancelled = {
            "schema": 1,
            "status": "cancelled",
            "planned_bytes": 4096,
            "completed_bytes": 1024,
            "failure": {"message": "context canceled"},
        }
        self.assertIn("cancelled", report_summary(cancelled, "/tmp/backup.img"))

        with self.assertRaises(ValueError):
            normalize_report({**passed, "completed_bytes": 2048})
        with self.assertRaises(ValueError):
            normalize_report({**failed, "sha256": digest})
        with self.assertRaises(ValueError):
            normalize_report({**passed, "sha256": "not-a-digest"})


if __name__ == "__main__":
    unittest.main()
