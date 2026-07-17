#!/usr/bin/env python3
from pathlib import Path
path = Path("docs/pre-0.11-code-audit.md")
text = path.read_text(encoding="utf-8")
marker = "## Documentation and parity process\n"
addition = '''### A-031 — package reproducibility and Debian policy were not release gates

**Severity:** medium supply-chain and maintainability  
**Status:** fixed

CI builds the deterministic Debian package twice and requires byte-for-byte equality. Lintian, AppStream, desktop validation, machine-readable copyright, runtime dependencies, changelog, man pages, and narrow static-helper overrides are permanent gates.

'''
if text.count(marker) != 1:
    raise SystemExit("parity marker changed")
path.write_text(text.replace(marker, addition + marker, 1), encoding="utf-8")
