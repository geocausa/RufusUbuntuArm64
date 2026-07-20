import ast
import pathlib
import unittest


class WindowsPayloadReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = pathlib.Path(__file__).with_name("rufusarm64_integrated.py")
        cls.source = path.read_text(encoding="utf-8")
        tree = ast.parse(cls.source)
        names = {"MAX_WINDOWS_EDITIONS", "MAX_WINDOWS_EDITION_NAME", "windows_payload_summary"}
        body = []
        for node in tree.body:
            if isinstance(node, ast.Assign):
                targets = {target.id for target in node.targets if isinstance(target, ast.Name)}
                if targets & names:
                    body.append(node)
            elif isinstance(node, ast.FunctionDef) and node.name in names:
                body.append(node)
        namespace = {}
        exec(compile(ast.Module(body=body, type_ignores=[]), str(path), "exec"), namespace)
        cls.summary = staticmethod(namespace["windows_payload_summary"])

    @staticmethod
    def analysis(kind="WIM", parts=1, count=2, names=None):
        return {
            "metadata": {
                "image_count": count,
                "edition_names": names if names is not None else ["Windows 11 Pro", "Windows 11 Home"],
            },
            "capabilities": {
                "recognized": True,
                "generation": "11",
                "family": "client",
                "architecture": "arm64",
            },
            "payload_kind": kind,
            "payload_parts": parts,
        }

    def test_multi_edition_wim_summary(self):
        summary = self.summary(self.analysis())
        self.assertIn("Windows 11 client", summary)
        self.assertIn("arm64", summary)
        self.assertIn("2 editions: Windows 11 Pro, Windows 11 Home", summary)
        self.assertIn("WIM payload", summary)

    def test_split_swm_summary_discloses_part_count(self):
        summary = self.summary(self.analysis(kind="SWM", parts=4))
        self.assertIn("4-part SWM payload", summary)

    def test_esd_summary(self):
        summary = self.summary(self.analysis(kind="ESD"))
        self.assertIn("ESD payload", summary)

    def test_long_edition_list_is_bounded_in_display(self):
        names = [f"Edition {index}" for index in range(1, 7)]
        summary = self.summary(self.analysis(count=6, names=names))
        self.assertIn("Edition 1, Edition 2, Edition 3, Edition 4 and 2 more", summary)
        self.assertNotIn("Edition 6", summary)

    def test_inconsistent_payload_or_counts_fail_closed(self):
        cases = [
            self.analysis(kind="ZIP"),
            self.analysis(kind="WIM", parts=2),
            self.analysis(kind="SWM", parts=0),
            self.analysis(count=0, names=[]),
            self.analysis(count=1, names=["One", "Two"]),
        ]
        for analysis in cases:
            with self.subTest(analysis=analysis):
                self.assertIn("unavailable", self.summary(analysis).lower())

    def test_unrecognized_media_preserves_helper_reason(self):
        analysis = self.analysis()
        analysis["capabilities"] = {"recognized": False, "reason": "conflicting edition metadata"}
        self.assertIn("conflicting edition metadata", self.summary(analysis))

    def test_composed_entry_point_installs_report_before_dialog_use(self):
        self.assertIn("install_windows_payload_reporting(WindowsOptionsDialog)", self.source)
        self.assertIn("dialog_class.capability_summary = capability_summary", self.source)
        self.assertIn("MAX_WINDOWS_EDITIONS = 256", self.source)
        self.assertNotIn("subprocess", self.source)
        self.assertNotIn("pkexec", self.source.lower())
        self.assertNotIn("--allow-fixed", self.source)
        self.assertNotIn("--no-unmount", self.source)


if __name__ == "__main__":
    unittest.main()
