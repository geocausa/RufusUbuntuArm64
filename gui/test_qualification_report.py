import json
import os
import stat
import tempfile
import unittest

from rufusarm64_qualification_report import (
    qualification_report_bytes,
    qualification_report_document,
    save_new_qualification_report,
)


PASSED_REPORT = {
    "schema": 1,
    "status": "passed",
    "profile": "full",
    "capacity": 16 * 1024 * 1024,
    "completed_bytes": 64 * 1024 * 1024,
    "aliasing_detected": False,
    "passes": [{"number": 1, "pattern": "address-a"}],
}


class QualificationReportExportTests(unittest.TestCase):
    def test_document_is_identity_bound_and_deterministic(self):
        first = qualification_report_bytes("/dev/sdb", "identity-token", PASSED_REPORT)
        second = qualification_report_bytes("/dev/sdb", "identity-token", dict(PASSED_REPORT))
        self.assertEqual(first, second)
        self.assertTrue(first.endswith(b"\n"))
        document = json.loads(first)
        self.assertEqual(document["schema"], 1)
        self.assertEqual(document["type"], "rufusarm64-device-qualification-report")
        self.assertEqual(document["device_path"], "/dev/sdb")
        self.assertEqual(document["device_identity"], "identity-token")
        self.assertEqual(document["report"]["status"], "passed")

    def test_export_creates_synchronized_private_file_without_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "qualification.json")
            self.assertEqual(
                save_new_qualification_report(path, "/dev/sdc", "identity", PASSED_REPORT),
                path,
            )
            info = os.stat(path, follow_symlinks=False)
            self.assertTrue(stat.S_ISREG(info.st_mode))
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
            with open(path, "rb") as handle:
                saved = json.load(handle)
            self.assertEqual(saved, qualification_report_document("/dev/sdc", "identity", PASSED_REPORT))
            with self.assertRaises(FileExistsError):
                save_new_qualification_report(path, "/dev/sdc", "identity", PASSED_REPORT)

    def test_existing_symlink_is_never_replaced_or_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "target.txt")
            report = os.path.join(directory, "qualification.json")
            with open(target, "w", encoding="utf-8") as handle:
                handle.write("unchanged")
            os.symlink(target, report)
            with self.assertRaises(FileExistsError):
                save_new_qualification_report(report, "/dev/sdd", "identity", PASSED_REPORT)
            with open(target, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "unchanged")
            self.assertTrue(os.path.islink(report))

    def test_invalid_export_inputs_fail_before_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "qualification.json")
            for device, identity, report in (
                ("sdb", "identity", PASSED_REPORT),
                ("/dev/sdb", "", PASSED_REPORT),
                ("/dev/sdb", "identity", {"schema": 2, "status": "passed", "passes": []}),
            ):
                with self.assertRaises(ValueError):
                    save_new_qualification_report(path, device, identity, report)
                self.assertFalse(os.path.lexists(path))
            with self.assertRaises(ValueError):
                save_new_qualification_report("relative.json", "/dev/sdb", "identity", PASSED_REPORT)


if __name__ == "__main__":
    unittest.main()
