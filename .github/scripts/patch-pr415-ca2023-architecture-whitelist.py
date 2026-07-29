#!/usr/bin/env python3
from pathlib import Path

path = Path("internal/windowsmedia/ca2023.go")
text = path.read_text(encoding="utf-8")
old = '''\tbootArchitecture := normalizeWIMArchitecture(metadata.Architecture)
\tif bootArchitecture == "" {
\t\treturn WindowsCA2023Capability{Reason: "boot.wim architecture is missing or unsupported"}, nil
\t}
\tindexes := make([]int, 0, 2)
'''
new = '''\tbootArchitecture := normalizeWIMArchitecture(metadata.Architecture)
\tswitch bootArchitecture {
\tcase "arm64", "amd64", "x86":
\tcase "":
\t\treturn WindowsCA2023Capability{Reason: "boot.wim architecture is missing"}, nil
\tdefault:
\t\treturn WindowsCA2023Capability{Reason: fmt.Sprintf("boot.wim architecture %q is unsupported for Windows UEFI CA 2023 replacement", bootArchitecture)}, nil
\t}
\tindexes := make([]int, 0, 2)
'''
if text.count(old) != 1:
    raise SystemExit(f"expected one CA 2023 architecture-validation anchor, found {text.count(old)}")
path.write_text(text.replace(old, new), encoding="utf-8")
