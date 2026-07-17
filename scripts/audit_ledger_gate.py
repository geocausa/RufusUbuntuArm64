#!/usr/bin/env python3
from pathlib import Path
path = Path("docs/pre-0.11-code-audit.md")
text = path.read_text(encoding="utf-8")
text += '''
## Final gate and accepted deferrals

One unchanged commit must pass Go 1.22 compatibility, formatting, race and shuffled tests, vet, coverage, Python and GUI-structure tests, Staticcheck, Govulncheck, Actionlint, ShellCheck, AppStream, desktop validation, Lintian, deterministic package comparison, package inspection, and native ARM64 execution.

Accepted deferrals are descriptor propagation to compatible external tools (A-007), stronger legacy-device topology identity (A-009), rebase of the stacked 0.11 validator and inventory (A-018 and A-027), Microsoft DBX signer verification before stronger authenticity claims (A-019), and newer Windows/Rufus parity work (A-016).

Persistent-live support remains experimental until physical boot and reboot qualification is published for each claimed image and hardware combination.
'''
counts = {name: text.count(f"**Status:** {name}") for name in ("fixed", "cleared", "deferred", "planned")}
if counts != {"fixed": 22, "cleared": 3, "deferred": 4, "planned": 2}:
    raise SystemExit(f"bad disposition counts: {counts}")
if "**Status:** fixing" in text or "**Status:** confirmed" in text:
    raise SystemExit("active unresolved status remains")
path.write_text(text, encoding="utf-8")
