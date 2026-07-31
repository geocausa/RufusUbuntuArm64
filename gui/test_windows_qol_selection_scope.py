import ast
import pathlib
import unittest


class WindowsQualityOfLifeSelectionScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = pathlib.Path("gui/rufusarm64.py")
        cls.source = cls.path.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source, filename=str(cls.path))

    def method_source(self, class_name, method_name):
        for node in self.tree.body:
            if not isinstance(node, ast.ClassDef) or node.name != class_name:
                continue
            for child in node.body:
                if isinstance(child, ast.FunctionDef) and child.name == method_name:
                    return ast.get_source_segment(self.source, child) or ""
        self.fail(f"missing {class_name}.{method_name}")

    def test_checkbox_is_default_off(self):
        constructor = self.method_source("WindowsOptionsDialog", "__init__")
        self.assertIn('previous.get("quality_of_life", False)', constructor)

    def test_changing_images_retains_only_normalized_safe_preferences(self):
        image_changed = self.method_source("RufusWindow", "image_changed")
        self.assertIn(
            "self.windows_options = normalize_persisted_windows_options(self.windows_options)",
            image_changed,
        )
        self.assertNotIn("self.windows_options = {}", image_changed)

    def test_settings_writer_persists_only_the_normalized_template(self):
        save_settings = self.method_source("RufusWindow", "save_settings")
        self.assertIn('self.settings["windows_options"] = normalize_persisted_windows_options(', save_settings)
        self.assertNotIn('self.settings["windows_options"] = self.windows_options', save_settings)


if __name__ == "__main__":
    unittest.main()
