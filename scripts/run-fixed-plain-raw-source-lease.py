#!/usr/bin/env python3
from pathlib import Path

patch_path = Path("scripts/apply-plain-raw-source-lease.py")
text = patch_path.read_text(encoding="utf-8")

first_start = text.index('replace_once(\n    "internal/imaging/imaging.go",\n    \'\'\'type WriteOptions struct {')
first_end = text.index('\n)\n\nreplace_once(', first_start) + 3
first_replacement = r"""replace_once(
    "internal/imaging/imaging.go",
    '''type WriteOptions struct {
\tBufferSize int
\tProgress   ProgressFunc
\t// SnapshotProgress reports the non-destructive source hashing pass that
\t// binds the bytes consumed by the later destructive write.
\tSnapshotProgress ProgressFunc
\tExpectedDeviceID uint64
\tExpectedSource   sourcefile.Identity
\tTargetSize       uint64
\t// ClearStaleSignatures zeroes bounded regions at the beginning and end of
\t// the already-open exclusive target before copying. This removes old GPT,
\t// RAID, filesystem, and boot signatures without reopening the device path.
\tClearStaleSignatures bool
''',
    '''type SourceHoldStatus struct {
\tHeld     bool
\tFallback bool
\tMessage  string
}

type WriteOptions struct {
\tBufferSize int
\tProgress   ProgressFunc
\t// SnapshotProgress reports the non-destructive source hashing pass that
\t// binds the bytes consumed by the later destructive write.
\tSnapshotProgress ProgressFunc
\tExpectedDeviceID uint64
\tExpectedSource   sourcefile.Identity
\tTargetSize       uint64
\t// ClearStaleSignatures zeroes bounded regions at the beginning and end of
\t// the already-open exclusive target before copying. This removes old GPT,
\t// RAID, filesystem, and boot signatures without reopening the device path.
\tClearStaleSignatures bool
\tHoldSource           bool
\tSourceHold           func(SourceHoldStatus)
''',
)"""
text = text[:first_start] + first_replacement + text[first_end:]

loop_start = text.index('replace_once(\n    "internal/imaging/imaging.go",\n    \'\'\'\\t\\tif n > 0 {')
loop_end = text.index('\n)\n\nreplace_once(', loop_start) + 3
loop_replacement = r"""replace_once(
    "internal/imaging/imaging.go",
    '''\t\tif n > 0 {
\t\t\t_, _ = writtenHash.Write(buf[:n])
\t\t\twn, writeErr := writeFull(dst, buf[:n])
\t\t\twritten += uint64(wn)
\t\t\tdone.Store(written)
''',
    '''\t\tif n > 0 {
\t\t\t_, _ = writtenHash.Write(buf[:n])
\t\t\twn, writeErr := writeFull(dst, buf[:n])
\t\t\tif wn > 0 {
\t\t\t\ttargetChanged = true
\t\t\t}
\t\t\twritten += uint64(wn)
\t\t\tif wn > 0 && opts.afterWriteChunk != nil {
\t\t\t\topts.afterWriteChunk(written)
\t\t\t}
\t\t\tdone.Store(written)
''',
)"""
text = text[:loop_start] + loop_replacement + text[loop_end:]

namespace = {"__name__": "__main__", "__file__": str(patch_path)}
exec(compile(text, str(patch_path), "exec"), namespace)
