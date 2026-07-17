#!/usr/bin/env python3
from pathlib import Path
path = Path("docs/pre-0.11-code-audit.md")
text = path.read_text(encoding="utf-8")
marker = "## Windows customization semantics\n"
addition = '''### A-029 — GUI worker process ownership and early cancellation

**Severity:** medium concurrency and cancellation  
**Status:** fixed

Each graphical worker owns a local process reference and clears the shared reference only when it still points to that child. Verified downloads also honor cancellation immediately after `Popen`. A permanent source-structure test covers all five workers.

### A-030 — existing verified-download pathname race

**Severity:** medium trust semantics  
**Status:** fixed

Reused downloads are opened without following links, compared with the original inode before hashing, checked for mutation, and compared with the final pathname. Replacement and symlink-swap tests fail closed.

'''
if text.count(marker) != 1:
    raise SystemExit("Windows marker changed")
path.write_text(text.replace(marker, addition + marker, 1), encoding="utf-8")
