#!/usr/bin/env python3
from pathlib import Path

path = Path("gui/test_source_structure.py")
text = path.read_text(encoding="utf-8")
broken = '        self.assertEqual(failures, [], "' + "\n" + '" + "' + "\n" + '".join(failures))'
fixed = '        self.assertEqual(failures, [], "\\n" + "\\n".join(failures))'
if text.count(broken) != 1:
    raise SystemExit(f"expected one generated newline-escape defect, found {text.count(broken)}")
path.write_text(text.replace(broken, fixed, 1), encoding="utf-8")
