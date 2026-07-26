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
                "/home/user/backup.vhdx",
                "vhdx",
            ),
            [
                "/usr/bin/rufusarm64-device-backup",
                "--device",
                "/dev/sdb",
                "--output",
                "/home/user/backup.vhdx",
                "--format",
                "vhdx",
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
                "/home/user/backup.vhd",
                "vhd",
            ),
            [
                "/usr/bin/pkexec",
                "/usr/bin/rufusarm64-device-backup",
                "--device",
                "/dev/sdc",
                "--output",
                "/home/user/backup.vhd",
                "--format",
                "vhd",
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
        with self.assertRaises(ValueError):
            build_run_command("/usr/bin/pkexec", "/usr/bin/tool", "/dev/sdc", "token", "/tmp/out.img", "qcow2")

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
                "path": "/home/user/backup.vhdx",
                "directory": "/home/user",
                "format": "vhdx",
                "source_bytes": 8 * 1024 * 1024,
                "required_bytes": 12 * 1024 * 1024,
                "container_minimum_bytes": 0,
                "available_bytes": 32 * 1024 * 1024,
            },
        }
        normalized = normalize_plan(payload)
        self.assertEqual(normalized["identity"], "abc")
        self.assertEqual(normalized["destination"]["format"], "vhdx")
        summary = plan_summary(payload)
        self.assertIn("USB Test", summary)
        self.assertIn("VHDX image", summary)
        self.assertIn("Destination filesystem: /home/user", summary)
        self.assertNotIn("Minimum container estimate", summary)
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
                        "format": "raw",
                        "source_bytes": 2,
                        "required_bytes": 2,
                        "available_bytes": 1,
                    },
                }
            )
        with self.assertRaises(ValueError):
            normalize_plan(
                {
                    **payload,
                    "destination": {**payload["destination"], "container_minimum_bytes": payload["destination"]["required_bytes"] + 1},
                }
            )

    def test_progress_normalization_decode_and_summary(self):
        payload = {
            "schema": 2,
            "type": "progress",
            "phase": "convert",
            "done": 512,
            "total": 1024,
            "elapsed_ms": 2000,
            "bytes_per_second": 256,
            "eta_seconds": 2,
        }
        self.assertEqual(normalize_progress(payload)["done"], 512)
        self.assertEqual(decode_progress_line(json.dumps(payload))["eta_seconds"], 2)
        self.assertIsNone(decode_progress_line("authentication message"))
        self.assertIn("Convert: 50.0%", progress_summary(payload))
        self.assertIn("256 B/s", progress_summary(payload))
        with self.assertRaises(ValueError):
            normalize_progress({**payload, "done": 2048})
        with self.assertRaises(ValueError):
            normalize_progress({**payload, "schema": 1})
        with self.assertRaises(ValueError):
            normalize_progress({**payload, "phase": "publish"})

    def test_report_normalization_and_user_summaries(self):
        source_digest = "a" * 64
        output_digest = "b" * 64
        passed = {
            "schema": 2,
            "status": "passed",
            "format": "vhdx",
            "planned_bytes": 4096,
            "completed_bytes": 4096,
            "sha256": source_digest,
            "source_sha256": source_digest,
            "output_sha256": output_digest,
            "output_bytes": 2048,
            "content_comparison": "passed",
            "consistency": "passed",
        }
        self.assertEqual(normalize_report(passed)["status"], "passed")
        summary = report_summary(passed, "/tmp/backup.vhdx")
        self.assertIn("/tmp/backup.vhdx", summary)
        self.assertIn(source_digest, summary)
        self.assertIn(output_digest, summary)

        raw = {
            **passed,
            "format": "raw",
            "output_sha256": source_digest,
            "output_bytes": 4096,
            "consistency": "not_applicable",
        }
        self.assertEqual(normalize_report(raw)["format"], "raw")

        vhd = {**passed, "format": "vhd", "consistency": "unsupported"}
        self.assertEqual(normalize_report(vhd)["consistency"], "unsupported")

        failed = {
            "schema": 2,
            "status": "failed",
            "format": "vhdx",
            "planned_bytes": 4096,
            "completed_bytes": 1024,
            "failure": {"kind": "source_read", "message": "read failed", "byte_offset": 1024},
        }
        self.assertIn("read failed", report_summary(failed, "/tmp/backup.vhdx"))

        cancelled = {
            "schema": 2,
            "status": "cancelled",
            "format": "vhd",
            "planned_bytes": 4096,
            "completed_bytes": 0,
            "failure": {"kind": "cancelled", "message": "context canceled", "byte_offset": 0},
        }
        self.assertIn("cancelled", report_summary(cancelled, "/tmp/backup.vhd"))

        with self.assertRaises(ValueError):
            normalize_report({**passed, "completed_bytes": 2048})
        with self.assertRaises(ValueError):
            normalize_report({**failed, "sha256": source_digest})
        with self.assertRaises(ValueError):
            normalize_report({**passed, "output_sha256": "not-a-digest"})
        with self.assertRaises(ValueError):
            normalize_report({**failed, "failure": None})
        with self.assertRaises(ValueError):
            normalize_report({**passed, "consistency": "unsupported"})
        with self.assertRaises(ValueError):
            normalize_report({**failed, "failure": {"kind": "source_read", "message": "bad", "byte_offset": 2048}})
        with self.assertRaises(ValueError):
            normalize_progress(
                {
                    "schema": 2,
                    "type": "progress",
                    "phase": "capture",
                    "done": 1.5,
                    "total": 2,
                    "elapsed_ms": 1,
                    "bytes_per_second": 1,
                }
            )


if __name__ == "__main__":
    unittest.main()
