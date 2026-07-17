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
        for pattern in ("*cleanup*.yml", "*cleanup*.yaml", "*autopatch*.yml", "*autopatch*.yaml"):
            forbidden.extend(workflows.glob(pattern))
        forbidden.extend(scripts.glob("*_patch.py"))
        self.assertEqual(
            [str(path.relative_to(REPOSITORY_ROOT)) for path in sorted(forbidden)],
            [],
            "temporary source-rewrite machinery must not be part of a release branch",
        )

    def test_audit_commands_and_package_assertions_are_not_duplicated(self):
        test_script = (REPOSITORY_ROOT / "scripts" / "test.sh").read_text(encoding="utf-8")
        unique_lines = (
            'shellcheck -x scripts/*.sh packaging/rufusarm64',
            'lintian --fail-on error "${PACKAGE}"',
            'grep -q \'^NoDisplay=true$\' "${extract_dir}/usr/share/applications/io.github.geocausa.RufusArm64.Persistence.desktop"',
            'grep -q \'^Actions=.*Persistence\' "${extract_dir}/usr/share/applications/io.github.geocausa.RufusArm64.desktop"',
            'grep -q \'Open Persistent USB Creator\' "${installed_gui}"',
        )
        duplicated = [line for line in unique_lines if test_script.count(line) != 1]
        self.assertEqual(duplicated, [], "audit/package commands must each occur exactly once")


if __name__ == "__main__":
    unittest.main()
