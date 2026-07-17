#!/usr/bin/env python3
"""Repair and validate the package GUI version-stamping heredoc."""

from pathlib import Path

path = Path(__file__).resolve().parents[1] / "scripts/build-deb.sh"
text = path.read_text(encoding="utf-8")
broken = '''if count != 1:
    raise SystemExit("could not stamp the canonical version into the installed GUI")

grep -Fxq "VERSION = \\"${VERSION}\\"" "${GUI_TARGET}"
'''
fixed = '''if count != 1:
    raise SystemExit("could not stamp the canonical version into the installed GUI")
path.write_text(text, encoding="utf-8")
PYVERSION
grep -Fxq "VERSION = \\"${VERSION}\\"" "${GUI_TARGET}"
'''
if broken in text:
    text = text.replace(broken, fixed, 1)
elif fixed not in text:
    raise SystemExit("scripts/build-deb.sh: version-stamping heredoc has an unexpected shape")
path.write_text(text, encoding="utf-8")
