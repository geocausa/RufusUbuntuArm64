import ast
import pathlib
import unittest


class WindowsOptionDisclosureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = pathlib.Path("gui/rufusarm64.py")
        cls.source = cls.path.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source, filename=str(cls.path))

    def method_source(self, class_name, method_name):
        for node in self.tree.body:
            if isinstance(node, ast.ClassDef) and node.name == class_name:
                for child in node.body:
                    if isinstance(child, ast.FunctionDef) and child.name == method_name:
                        return ast.get_source_segment(self.source, child) or ""
        self.fail(f"missing {class_name}.{method_name}")

    def test_final_confirmation_and_log_disclose_empty_or_selected_options(self):
        source = self.method_source("RufusWindow", "start")
        self.assertIn('else "none — standard Microsoft setup"', source)
        self.assertIn('Windows options: " + windows_options_text', source)
        self.assertIn('self.append_log(f"Windows options: {windows_options_text}")', source)

    def test_accepted_dialog_persists_only_safe_choices_immediately(self):
        source = self.method_source("RufusWindow", "choose_windows_options")
        self.assertIn("self.windows_options = normalize_persisted_windows_options(values)", source)
        self.assertIn('self.settings["windows_options"] = dict(self.windows_options)', source)
        self.assertIn("self.save_settings()", source)


if __name__ == "__main__":
    unittest.main()
