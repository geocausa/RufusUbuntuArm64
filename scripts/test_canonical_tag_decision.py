#!/usr/bin/env python3

from pathlib import Path
import unittest

from canonical_tag_decision import canonical_tag_decision


class CanonicalTagDecisionTests(unittest.TestCase):
    current = "1" * 40
    released = "2" * 40

    def test_missing_tag_is_created(self):
        self.assertEqual(canonical_tag_decision(self.current), "create")

    def test_idempotent_same_commit_is_noop(self):
        self.assertEqual(canonical_tag_decision(self.current, self.current), "already-current")

    def test_post_release_development_never_moves_tag(self):
        self.assertEqual(canonical_tag_decision(self.current, self.released), "already-released")

    def test_sha_inputs_are_strict(self):
        for current, existing in (("short", ""), (self.current, "not-a-sha"), ("", "")):
            with self.subTest(current=current, existing=existing):
                with self.assertRaisesRegex(ValueError, "40 hexadecimal"):
                    canonical_tag_decision(current, existing)

    def test_workflow_excludes_ordinary_changelog_development(self):
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github" / "workflows" / "version-tag.yml").read_text(encoding="utf-8")
        self.assertNotIn("\n      - CHANGELOG.md\n", workflow)
        self.assertIn("scripts/canonical_tag_decision.py", workflow)
        self.assertIn("already-released)", workflow)
        self.assertNotIn("Refusing to move existing", workflow)


if __name__ == "__main__":
    unittest.main()
