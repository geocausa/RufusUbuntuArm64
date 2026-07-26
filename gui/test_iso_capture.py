import json
import os
import tempfile
import unittest

from rufusarm64_iso_capture import (
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


DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
LIMITATIONS = [
    "The ISO is a filesystem remaster, not a physical-disk image.",
    "Partition tables, hidden sectors, boot records and unallocated space are not captured.",
    "Bootability is not claimed or inferred from successful filesystem capture.",
    "Only the reviewed regular-file and directory subset is supported.",
]


def plan_payload(output="/tmp/capture.iso"):
    return {
        "device": {
            "path": "/dev/sdz",
            "size": 8 * 1024 * 1024,
            "vendor": "Test",
            "model": "USB",
        },
        "identity": "identity-token",
        "source_node": "/dev/sdz1",
        "destination": {
            "path": output,
            "directory": os.path.dirname(output),
            "format": "iso",
            "source_bytes": 4096,
            "required_bytes": 64 * 1024 * 1024,
            "available_bytes": 2 * 1024 * 1024 * 1024,
        },
        "filesystem_capture": {
            "schema": 1,
            "format": "iso",
            "profile": "iso9660-joliet-udf",
            "filesystem": "udf",
            "volume_id": "RUFUS_TEST",
            "provider": "/usr/bin/genisoimage",
            "source_device": "/dev/sdz",
            "source_mount": "/media/USB",
            "destination": output,
            "files": 2,
            "directories": 1,
            "source_bytes": 4096,
            "required_bytes": 64 * 1024 * 1024,
            "available_bytes": 2 * 1024 * 1024 * 1024,
            "source_binding_sha256": DIGEST_A,
            "source_content_sha256": DIGEST_B,
            "limitations": list(LIMITATIONS),
        },
    }


def passed_report(output="/tmp/capture.iso"):
    return {
        "schema": 1,
        "status": "passed",
        "profile": "iso9660-joliet-udf",
        "filesystem": "udf",
        "volume_id": "RUFUS_TEST",
        "source_device": "/dev/sdz",
        "source_node": "/dev/sdz1",
        "source_mount": "/media/USB",
        "destination": output,
        "files": 2,
        "directories": 1,
        "source_bytes": 4096,
        "required_bytes": 64 * 1024 * 1024,
        "output_bytes": 1024 * 1024,
        "source_binding_sha256": DIGEST_A,
        "source_content_sha256": DIGEST_B,
        "output_sha256": DIGEST_C,
        "content_comparison": "passed",
        "source_stable": True,
        "udf_validated": True,
        "published": True,
    }


class ISOCaptureContractsTest(unittest.TestCase):
    def test_plan_normalization_and_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            output = os.path.join(directory, "capture.iso")
            payload = plan_payload(output)
            value = normalize_plan(payload)
            self.assertEqual(value["destination"]["format"], "iso")
            self.assertEqual(value["source_node"], "/dev/sdz1")
            self.assertEqual(value["filesystem_capture"]["source_content_sha256"], DIGEST_B)
            self.assertIn("filesystem remaster", plan_summary(payload))
            self.assertEqual(
                build_dry_run_command("/usr/bin/helper", "/dev/sdz", "identity-token", output),
                [
                    "/usr/bin/helper",
                    "--device",
                    "/dev/sdz",
                    "--output",
                    output,
                    "--format",
                    "iso",
                    "--expected-identity",
                    "identity-token",
                    "--dry-run",
                    "--json",
                ],
            )
            command = build_run_command("/usr/bin/pkexec", "/usr/bin/helper", "/dev/sdz", "identity-token", output, payload)
            self.assertEqual(command[:2], ["/usr/bin/pkexec", "/usr/bin/helper"])
            self.assertIn("--expected-source-node", command)
            self.assertIn("/dev/sdz1", command)
            self.assertIn("--expected-source-mount", command)
            self.assertIn("/media/USB", command)
            binding_index = command.index("--expected-source-binding-sha256")
            content_index = command.index("--expected-source-content-sha256")
            self.assertEqual(command[binding_index + 1], DIGEST_A)
            self.assertEqual(command[content_index + 1], DIGEST_B)
            self.assertIn("--volume-id", command)

    def test_confirmation_binds_disk_node_mount_and_destination(self):
        self.assertEqual(
            confirmation_phrase(plan_payload()),
            "SAVE FILESYSTEM /dev/sdz1 AT /media/USB ON /dev/sdz TO /tmp/capture.iso",
        )

    def test_plan_rejects_missing_limits_and_inconsistent_evidence(self):
        mutations = []
        payload = plan_payload()
        payload["filesystem_capture"]["limitations"] = payload["filesystem_capture"]["limitations"][:-1]
        mutations.append(payload)
        payload = plan_payload()
        payload["destination"]["source_bytes"] = 1
        mutations.append(payload)
        payload = plan_payload()
        payload["filesystem_capture"]["source_device"] = "/dev/sdy"
        mutations.append(payload)
        payload = plan_payload()
        payload["filesystem_capture"]["provider"] = "genisoimage"
        mutations.append(payload)
        payload = plan_payload()
        payload["filesystem_capture"]["source_content_sha256"] = "bad"
        mutations.append(payload)
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaises(ValueError):
                    normalize_plan(mutation)

    def test_progress_accepts_indeterminate_and_bounded_phases(self):
        indeterminate = normalize_progress(
            {
                "schema": 2,
                "type": "progress",
                "phase": "source_view",
                "done": 0,
                "total": 0,
                "elapsed_ms": 10,
                "bytes_per_second": 0,
            }
        )
        self.assertEqual(indeterminate["total"], 0)
        self.assertIn("working", progress_summary(indeterminate))
        bounded = {
            "schema": 2,
            "type": "progress",
            "phase": "master",
            "done": 512,
            "total": 1024,
            "elapsed_ms": 2000,
            "bytes_per_second": 256,
            "eta_seconds": 2,
        }
        self.assertEqual(decode_progress_line(json.dumps(bounded))["done"], 512)
        self.assertIn("50.0%", progress_summary(bounded))
        self.assertIsNone(decode_progress_line("provider diagnostic"))
        with self.assertRaises(ValueError):
            normalize_progress({**bounded, "phase": "capture"})
        with self.assertRaises(ValueError):
            normalize_progress({**bounded, "done": 2048})

    def test_success_report_requires_complete_publication_evidence(self):
        value = normalize_report(passed_report())
        self.assertEqual(value["format"], "iso")
        self.assertEqual(value["source_node"], "/dev/sdz1")
        self.assertEqual(value["planned_bytes"], 4096)
        self.assertEqual(value["output_bytes"], 1024 * 1024)
        self.assertIn("No physical-disk", report_summary(value, "/tmp/capture.iso"))
        for key in ("source_stable", "udf_validated", "published"):
            payload = passed_report()
            payload[key] = False
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    normalize_report(payload)
        payload = passed_report()
        payload["source_node"] = "missing"
        with self.assertRaises(ValueError):
            normalize_report(payload)
        payload = passed_report()
        payload["output_sha256"] = "bad"
        with self.assertRaises(ValueError):
            normalize_report(payload)

    def test_failed_report_requires_failure_and_forbids_publication(self):
        payload = passed_report()
        payload.update(
            {
                "status": "failed",
                "published": False,
                "failure_kind": "mount_validation",
                "failure": "validation failed",
            }
        )
        value = normalize_report(payload)
        self.assertEqual(value["status"], "failed")
        self.assertIn("no final image", report_summary(value, "/tmp/capture.iso"))
        payload["published"] = True
        with self.assertRaises(ValueError):
            normalize_report(payload)


if __name__ == "__main__":
    unittest.main()
