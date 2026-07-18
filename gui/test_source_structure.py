#!/usr/bin/env python3
"""Structural source checks that do not require importing GTK."""

import ast
from pathlib import Path
import unittest


GUI_ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = GUI_ROOT.parent


def duplicate_definitions(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    duplicates = []

    def check_scope(nodes, scope):
        seen = {}
        for node in nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                kind = "class" if isinstance(node, ast.ClassDef) else "function"
                key = (kind, node.name)
                previous = seen.get(key)
                if previous is not None:
                    duplicates.append(
                        f"{path.name}:{node.lineno}: duplicate {kind} {scope}{node.name!r}; "
                        f"first defined at line {previous}"
                    )
                else:
                    seen[key] = node.lineno
            if isinstance(node, ast.ClassDef):
                check_scope(node.body, f"{scope}{node.name}.")

    check_scope(tree.body, "")
    return duplicates


class SourceStructureTests(unittest.TestCase):
    def test_python_sources_have_no_duplicate_definitions(self):
        failures = []
        for path in sorted(GUI_ROOT.glob("*.py")):
            if path.name.startswith("test_"):
                continue
            failures.extend(duplicate_definitions(path))
        self.assertEqual(failures, [], "\n" + "\n".join(failures))

    def test_no_temporary_source_rewrite_mechanisms_are_tracked(self):
        forbidden = []
        workflows = REPOSITORY_ROOT / ".github" / "workflows"
        scripts = REPOSITORY_ROOT / "scripts"
        for marker in ("cleanup", "autopatch", "repair", "rewrite"):
            forbidden.extend(workflows.glob(f"*{marker}*.yml"))
            forbidden.extend(workflows.glob(f"*{marker}*.yaml"))
        forbidden.extend(scripts.glob("*_patch.py"))
        forbidden.extend(scripts.glob("*_rewrite.py"))
        self.assertEqual(
            [str(path.relative_to(REPOSITORY_ROOT)) for path in sorted(set(forbidden))],
            [],
            "temporary source-rewrite machinery must not be part of a release branch",
        )

    def test_worker_process_references_are_ownership_guarded(self):
        workers = {
            "rufusarm64.py": ("run_download", "run_persistence_plan", "run_writer"),
            "rufusarm64_persistence.py": ("run_analysis", "run_create"),
        }
        failures = []
        for filename, method_names in workers.items():
            path = GUI_ROOT / filename
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
            methods = {
                node.name: ast.get_source_segment(source, node) or ""
                for class_node in tree.body
                if isinstance(class_node, ast.ClassDef)
                for node in class_node.body
                if isinstance(node, ast.FunctionDef)
            }
            for method_name in method_names:
                body = methods.get(method_name, "")
                if not body:
                    failures.append(f"{filename}: missing {method_name}")
                    continue
                for required in ("process = None", "self.process = process", "if self.process is process:"):
                    if required not in body:
                        failures.append(f"{filename}:{method_name} lacks {required!r}")
        main_source = (GUI_ROOT / "rufusarm64.py").read_text(encoding="utf-8")
        main_tree = ast.parse(main_source, filename="rufusarm64.py")
        download_source = next(
            ast.get_source_segment(main_source, node) or ""
            for class_node in main_tree.body
            if isinstance(class_node, ast.ClassDef)
            for node in class_node.body
            if isinstance(node, ast.FunctionDef) and node.name == "run_download"
        )
        if "if self.cancel_requested and process.poll() is None:" not in download_source:
            failures.append("rufusarm64.py:run_download does not honor early cancellation")
        self.assertEqual(failures, [], "\n" + "\n".join(failures))

    def test_slow_gui_subprocesses_use_workers_and_generation_guards(self):
        expected = {
            "rufusarm64.py": {
                "AcquisitionDialog": {
                    "verify_catalog": ("threading.Thread(",),
                    "_run_catalog_verify": ("subprocess.run(",),
                    "_finish_catalog_verify": ("generation != self.catalog_generation", "self.closed"),
                },
                "RufusWindow": {
                    "image_changed": ("threading.Thread(",),
                    "_run_image_inspection": ("subprocess.run(",),
                    "_finish_image_inspection": ("generation != self.inspection_generation", "self.closed"),
                    "refresh_devices": ("threading.Thread(",),
                    "_run_device_refresh": ("subprocess.run(",),
                    "_finish_device_refresh": ("generation != self.device_generation", "self.closed"),
                },
            },
            "rufusarm64_persistence.py": {
                "Window": {
                    "refresh_devices": ("threading.Thread(",),
                    "_run_device_refresh": ("subprocess.run(",),
                    "_finish_device_refresh": ("generation != self.device_generation", "self.closed"),
                },
            },
        }
        failures = []
        for filename, classes in expected.items():
            path = GUI_ROOT / filename
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
            class_methods = {
                class_node.name: {
                    node.name: ast.get_source_segment(source, node) or ""
                    for node in class_node.body
                    if isinstance(node, ast.FunctionDef)
                }
                for class_node in tree.body
                if isinstance(class_node, ast.ClassDef)
            }
            for class_name, methods_ in classes.items():
                for method_name, required_fragments in methods_.items():
                    body = class_methods.get(class_name, {}).get(method_name, "")
                    if not body:
                        failures.append(f"{filename}:{class_name}.{method_name} is missing")
                        continue
                    if method_name in {"verify_catalog", "image_changed", "refresh_devices"} and "subprocess.run(" in body:
                        failures.append(f"{filename}:{class_name}.{method_name} blocks the GTK thread")
                    for fragment in required_fragments:
                        if fragment not in body:
                            failures.append(f"{filename}:{class_name}.{method_name} lacks {fragment!r}")
        self.assertEqual(failures, [], "\n" + "\n".join(failures))

    def test_windows_capabilities_use_read_only_worker_and_dialog_gating(self):
        source = (GUI_ROOT / "rufusarm64.py").read_text(encoding="utf-8")
        tree = ast.parse(source, filename="rufusarm64.py")
        classes = {
            node.name: {
                child.name: ast.get_source_segment(source, child) or ""
                for child in node.body
                if isinstance(child, ast.FunctionDef)
            }
            for node in tree.body
            if isinstance(node, ast.ClassDef)
        }
        window = classes.get("RufusWindow", {})
        dialog = classes.get("WindowsOptionsDialog", {})
        failures = []
        for fragment in ("threading.Thread(", '"windows"', '"analyze"', "--expected-source-identity", "--json"):
            if fragment not in source:
                failures.append(f"rufusarm64.py lacks {fragment!r}")
        for fragment in ("normalize_windows_capability_analysis", "unavailable_windows_capability_analysis"):
            if fragment not in window.get("analyze_windows_capabilities", ""):
                failures.append(f"RufusWindow.analyze_windows_capabilities lacks {fragment!r}")
        for fragment in ("apply_option_capability", "bypass_hardware_checks", "bypass_online_account", "local_account"):
            if fragment not in dialog.get("apply_capabilities", ""):
                failures.append(f"WindowsOptionsDialog.apply_capabilities lacks {fragment!r}")
        self.assertEqual(failures, [], "\n" + "\n".join(failures))

    def test_audit_commands_and_package_assertions_are_not_duplicated(self):
        test_script = (REPOSITORY_ROOT / "scripts" / "test.sh").read_text(encoding="utf-8")
        unique_lines = (
            'shellcheck -x scripts/*.sh packaging/rufusarm64',
            'lintian --fail-on error "${PACKAGE}"',
            'grep -q \'^NoDisplay=true$\' "${extract_dir}/usr/share/applications/io.github.geocausa.RufusArm64.Persistence.desktop"',
            'grep -q \'^Actions=.*PersistentLiveUSB\' "${extract_dir}/usr/share/applications/io.github.geocausa.RufusArm64.desktop"',
            'grep -q \'Open Persistent USB Creator\' "${installed_gui}"',
        )
        duplicated = [line for line in unique_lines if test_script.count(line) != 1]
        self.assertEqual(duplicated, [], "audit/package commands must each occur exactly once")


if __name__ == "__main__":
    unittest.main()
