#!/usr/bin/env python3
"""Structural source checks that do not require importing GTK."""

import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent


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
        for path in sorted(ROOT.glob("*.py")):
            if path.name.startswith("test_"):
                continue
            failures.extend(duplicate_definitions(path))
        self.assertEqual(failures, [], "\n" + "\n".join(failures))


if __name__ == "__main__":
    unittest.main()
