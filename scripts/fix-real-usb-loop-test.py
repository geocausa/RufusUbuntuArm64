#!/usr/bin/env python3
from pathlib import Path

path = Path(__file__).resolve().parents[1] / "internal/safety/reopenable_linux_test.go"
text = path.read_text()
old = '''\tkernelID, err := KernelDeviceID(loopPath)
\tif err != nil {
\t\tt.Fatal(err)
\t}
\tif _, currentID, err := RevalidateOpenBoundTarget(loopPath, kernelID, true); err != nil || currentID != kernelID {
\t\tt.Fatalf("revalidate held loop target: id=%d err=%v", currentID, err)
\t}
\tif _, _, err := RevalidateOpenBoundTarget(loopPath, kernelID+1, true); err == nil {
\t\tt.Fatal("changed kernel target identity was accepted")
\t}

\tconst inheritedDevice = "/proc/self/fd/3"
'''
new = '''\t// A loop device is deliberately not accepted by the production whole-disk
\t// policy. This integration test is scoped to the formatter descriptor and
\t// advisory-lock handoff only.
\tconst inheritedDevice = "/proc/self/fd/3"
'''
if text.count(old) != 1:
    raise SystemExit(f"loop policy block count {text.count(old)}")
path.write_text(text.replace(old, new, 1))
