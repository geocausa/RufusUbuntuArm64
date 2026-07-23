#!/usr/bin/env python3
from pathlib import Path

patch_path = Path("scripts/apply-plain-raw-source-lease.py")
text = patch_path.read_text(encoding="utf-8")

first_start = text.index('replace_once(\n    "internal/imaging/imaging.go",\n    \'\'\'type WriteOptions struct {')
first_end = text.index('\n)\n\nreplace_once(', first_start) + 3
first_replacement = r'''replace_once(
    "internal/imaging/imaging.go",
    '''type WriteOptions struct {
	BufferSize int
	Progress   ProgressFunc
	// SnapshotProgress reports the non-destructive source hashing pass that
	// binds the bytes consumed by the later destructive write.
	SnapshotProgress ProgressFunc
	ExpectedDeviceID uint64
	ExpectedSource   sourcefile.Identity
	TargetSize       uint64
	// ClearStaleSignatures zeroes bounded regions at the beginning and end of
	// the already-open exclusive target before copying. This removes old GPT,
	// RAID, filesystem, and boot signatures without reopening the device path.
	ClearStaleSignatures bool
''',
    '''type SourceHoldStatus struct {
	Held     bool
	Fallback bool
	Message  string
}

type WriteOptions struct {
	BufferSize int
	Progress   ProgressFunc
	// SnapshotProgress reports the non-destructive source hashing pass that
	// binds the bytes consumed by the later destructive write.
	SnapshotProgress ProgressFunc
	ExpectedDeviceID uint64
	ExpectedSource   sourcefile.Identity
	TargetSize       uint64
	// ClearStaleSignatures zeroes bounded regions at the beginning and end of
	// the already-open exclusive target before copying. This removes old GPT,
	// RAID, filesystem, and boot signatures without reopening the device path.
	ClearStaleSignatures bool
	HoldSource           bool
	SourceHold           func(SourceHoldStatus)
''',
)'''
text = text[:first_start] + first_replacement + text[first_end:]

loop_start = text.index('replace_once(\n    "internal/imaging/imaging.go",\n    \'\'\'\\t\\tif n > 0 {')
loop_end = text.index('\n)\n\nreplace_once(', loop_start) + 3
loop_replacement = r'''replace_once(
    "internal/imaging/imaging.go",
    '''		if n > 0 {
			_, _ = writtenHash.Write(buf[:n])
			wn, writeErr := writeFull(dst, buf[:n])
			written += uint64(wn)
			done.Store(written)
''',
    '''		if n > 0 {
			_, _ = writtenHash.Write(buf[:n])
			wn, writeErr := writeFull(dst, buf[:n])
			if wn > 0 {
				targetChanged = true
			}
			written += uint64(wn)
			if wn > 0 && opts.afterWriteChunk != nil {
				opts.afterWriteChunk(written)
			}
			done.Store(written)
''',
)'''
text = text[:loop_start] + loop_replacement + text[loop_end:]

namespace = {"__name__": "__main__", "__file__": str(patch_path)}
exec(compile(text, str(patch_path), "exec"), namespace)
