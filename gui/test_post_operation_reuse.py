import ast
import pathlib
import unittest


class PostOperationReuseStructureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = pathlib.Path(__file__).resolve().parents[1]
        cls.integrated_source = (root / "gui" / "rufusarm64_integrated.py").read_text(encoding="utf-8")
        cls.nonbootable_source = (root / "gui" / "rufusarm64_nonbootable_dialog.py").read_text(encoding="utf-8")
        cls.package_source = (root / "scripts" / "build-deb.sh").read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.integrated_source)
        cls.installer = next(
            node
            for node in cls.tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "install_post_operation_reuse"
        )
        cls.installer_source = ast.get_source_segment(cls.integrated_source, cls.installer)

    def test_integrated_entry_point_installs_reuse_after_all_destructive_extensions(self):
        ast.parse(self.integrated_source)
        calls = [
            "install_drive_backup(RufusWindow)",
            "install_nonbootable(RufusWindow)",
            "install_freedos(RufusWindow)",
            "install_post_operation_reuse(RufusWindow)",
        ]
        positions = [self.integrated_source.index(call) for call in calls]
        self.assertEqual(positions, sorted(positions))

    def test_main_action_explains_restoration_in_ordinary_language(self):
        self.assertIn('set_label("Restore / format…")', self.installer_source)
        self.assertIn("remove any boot layout", self.installer_source)
        self.assertIn("Restore drive for storage…", self.installer_source)
        self.assertIn("Create another USB", self.installer_source)

    def test_writer_captures_exact_target_and_only_offers_actions_after_finish(self):
        self.assertIn("window._post_operation_pending = _selected_target(window)", self.installer_source)
        self.assertIn('if window.active_job != "writer"', self.installer_source)
        self.assertIn("result = original_finish(window, return_code)", self.installer_source)
        self.assertLess(
            self.installer_source.index("result = original_finish(window, return_code)"),
            self.installer_source.index("window.show_post_operation_actions("),
        )
        self.assertIn("The selected drive may contain incomplete media", self.installer_source)

    def test_restore_delegates_to_existing_identity_bound_formatter(self):
        self.assertIn("NonBootableFormatDialog(window, device, identity)", self.installer_source)
        self.assertIn("window._post_operation_target", self.installer_source)
        self.assertNotIn("subprocess", self.integrated_source)
        self.assertNotIn("pkexec", self.integrated_source.lower())
        self.assertNotIn("--allow-fixed", self.integrated_source)
        self.assertNotIn("--no-unmount", self.integrated_source)
        self.assertIn("build_dry_run_command", self.nonbootable_source)
        self.assertIn("confirmation_phrase", self.nonbootable_source)

    def test_create_another_keeps_image_and_refreshes_only_the_target_side(self):
        self.assertIn("The image remains selected", self.installer_source)
        self.assertIn("window.refresh_devices()", self.installer_source)
        self.assertIn("window.target_combo.grab_focus()", self.installer_source)
        self.assertNotIn("image_chooser.unselect", self.installer_source)
        self.assertNotIn("image_chooser.set_filename", self.installer_source)

    def test_packaged_composed_entry_point_contains_the_feature(self):
        self.assertIn('gui/rufusarm64_integrated.py', self.package_source)
        self.assertIn("install_post_operation_reuse(RufusWindow)", self.integrated_source)


if __name__ == "__main__":
    unittest.main()
