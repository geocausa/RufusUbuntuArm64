#!/usr/bin/env python3
from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one replacement, found {count}")
    file_path.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_once(
    "internal/imaging/imaging.go",
    '''type WriteOptions struct {
\tBufferSize           int
\tExpectedDeviceID     uint64
\tExpectedSource       sourcefile.Identity
\tTargetSize           uint64
\tClearStaleSignatures bool
\tProgress             ProgressFunc
\tSnapshotProgress     ProgressFunc
''',
    '''type SourceHoldStatus struct {
\tHeld     bool
\tFallback bool
\tMessage  string
}

type WriteOptions struct {
\tBufferSize           int
\tExpectedDeviceID     uint64
\tExpectedSource       sourcefile.Identity
\tTargetSize           uint64
\tClearStaleSignatures bool
\tHoldSource           bool
\tSourceHold           func(SourceHoldStatus)
\tProgress             ProgressFunc
\tSnapshotProgress     ProgressFunc
''',
)

replace_once(
    "internal/imaging/imaging.go",
    '''\ttrustedSnapshot         [sha256.Size]byte
\ttrustedSnapshotSet      bool
\ttrustedSnapshotIdentity sourcefile.Identity
}''',
    '''\ttrustedSnapshot         [sha256.Size]byte
\ttrustedSnapshotSet      bool
\ttrustedSnapshotIdentity sourcefile.Identity
\tbeforeMutation          func()
\tafterWriteChunk         func(uint64)
}''',
)

replace_once(
    "internal/imaging/imaging.go",
    '''func writeOpenImage(ctx context.Context, src *os.File, devicePath string, opts WriteOptions) (writeResult WriteResult, resultErr error) {
\tif opts.BufferSize <= 0 {
\t\topts.BufferSize = DefaultBufferSize
\t}
\tif err := sourcefile.VerifyPinned(src, opts.ExpectedSource); err != nil {
''',
    '''func writeOpenImage(ctx context.Context, src *os.File, devicePath string, opts WriteOptions) (writeResult WriteResult, resultErr error) {
\tif opts.BufferSize <= 0 {
\t\topts.BufferSize = DefaultBufferSize
\t}
\tvar sourceLease *sourcefile.ReadLease
\ttargetChanged := false
\tif opts.HoldSource {
\t\tlease, leaseErr := sourcefile.AcquireReadLease(ctx, src, opts.ExpectedSource)
\t\tswitch {
\t\tcase leaseErr == nil:
\t\t\tsourceLease = lease
\t\t\tctx = lease.Context()
\t\t\tif opts.SourceHold != nil {
\t\t\t\topts.SourceHold(SourceHoldStatus{Held: true, Message: "Holding the selected raw image read-only with a Linux kernel lease during destructive writing."})
\t\t\t}
\t\t\tdefer func() {
\t\t\t\theldErr := sourceLease.Check()
\t\t\t\tif errors.Is(heldErr, sourcefile.ErrReadLeaseBroken) {
\t\t\t\t\tmessage := "the selected raw image was opened for writing before target mutation; nothing was erased"
\t\t\t\t\tif targetChanged {
\t\t\t\t\t\tmessage = "the selected raw image was opened for writing during the destructive write; the USB is incomplete and must be recreated"
\t\t\t\t\t}
\t\t\t\t\theldErr = fmt.Errorf("%s: %w", message, heldErr)
\t\t\t\t}
\t\t\t\tcloseErr := sourceLease.Close()
\t\t\t\tresultErr = errors.Join(resultErr, heldErr, closeErr)
\t\t\t}()
\t\tcase errors.Is(leaseErr, sourcefile.ErrReadLeaseUnavailable), errors.Is(leaseErr, sourcefile.ErrReadLeaseConflict):
\t\t\tif opts.SourceHold != nil {
\t\t\t\topts.SourceHold(SourceHoldStatus{Fallback: true, Message: fmt.Sprintf("Kernel raw-source hold unavailable (%v); retaining conservative pre-write and write-time digest comparison.", leaseErr)})
\t\t\t}
\t\tdefault:
\t\t\treturn writeResult, fmt.Errorf("hold selected raw image stable: %w", leaseErr)
\t\t}
\t}
\tif err := sourcefile.VerifyPinned(src, opts.ExpectedSource); err != nil {
''',
)

replace_once(
    "internal/imaging/imaging.go",
    '''\t// Re-check immediately before the first target write in case the source was
\t// modified in place while administrator authentication was displayed.
\tif err := sourcefile.VerifyPinned(src, opts.ExpectedSource); err != nil {
\t\treturn writeResult, err
\t}
\tif opts.ClearStaleSignatures {
''',
    '''\t// Re-check immediately before the first target write in case the source was
\t// modified in place while administrator authentication was displayed.
\tif err := sourcefile.VerifyPinned(src, opts.ExpectedSource); err != nil {
\t\treturn writeResult, err
\t}
\tif opts.beforeMutation != nil {
\t\topts.beforeMutation()
\t}
\tif sourceLease != nil {
\t\tif err := sourceLease.Check(); err != nil {
\t\t\treturn writeResult, err
\t\t}
\t}
\tif err := ctx.Err(); err != nil {
\t\treturn writeResult, context.Cause(ctx)
\t}
\tif opts.ClearStaleSignatures {
\t\ttargetChanged = true
''',
)

replace_once(
    "internal/imaging/imaging.go",
    '''\t\tif n > 0 {
\t\t\twn, writeErr := writeFull(dst, buf[:n])
\t\t\tif wn > 0 {
\t\t\t\t_, _ = writtenHash.Write(buf[:wn])
\t\t\t}
\t\t\twritten += uint64(wn)
''',
    '''\t\tif n > 0 {
\t\t\twn, writeErr := writeFull(dst, buf[:n])
\t\t\tif wn > 0 {
\t\t\t\ttargetChanged = true
\t\t\t\t_, _ = writtenHash.Write(buf[:wn])
\t\t\t}
\t\t\twritten += uint64(wn)
\t\t\tif wn > 0 && opts.afterWriteChunk != nil {
\t\t\t\topts.afterWriteChunk(written)
\t\t\t}
''',
)

replace_once(
    "cmd/rufus-linux/main.go",
    '''\twriteResult, err := imaging.WritePreparedOpenImageWithResult(ctx, prepared, rawSource, resolved, imaging.WriteOptions{
\t\tExpectedDeviceID:     kernelDeviceID,
\t\tExpectedSource:       sourceIdentity,
\t\tTargetSize:           dev.Size,
\t\tClearStaleSignatures: true,
''',
    '''\twriteResult, err := imaging.WritePreparedOpenImageWithResult(ctx, prepared, rawSource, resolved, imaging.WriteOptions{
\t\tExpectedDeviceID:     kernelDeviceID,
\t\tExpectedSource:       sourceIdentity,
\t\tTargetSize:           dev.Size,
\t\tClearStaleSignatures: true,
\t\tHoldSource:           prepared.Kind == imaging.InputPlain,
\t\tSourceHold: func(status imaging.SourceHoldStatus) {
\t\t\tout.event(jsonEvent{Event: "stage", Stage: "source_hold", Message: status.Message})
\t\t},
''',
)

Path("internal/imaging/source_hold_linux_test.go").write_text(r'''//go:build linux

package imaging

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

type rawSourceHoldFixture struct {
	sourcePath string
	targetPath string
	source     *os.File
	identity   sourcefile.Identity
	payload    []byte
}

func newRawSourceHoldFixture(t *testing.T, payloadSize int) rawSourceHoldFixture {
	t.Helper()
	payload := make([]byte, payloadSize)
	for index := range payload {
		payload[index] = byte((index*29 + 11) % 251)
	}
	sourcePath := filepath.Join(t.TempDir(), "image.raw")
	if err := os.WriteFile(sourcePath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := sourcefile.IdentityOf(source)
	if err != nil {
		source.Close()
		t.Fatal(err)
	}
	targetPath := filepath.Join(t.TempDir(), "target.raw")
	if err := os.WriteFile(targetPath, bytes.Repeat([]byte{0xa5}, payloadSize+4096), 0o600); err != nil {
		source.Close()
		t.Fatal(err)
	}
	return rawSourceHoldFixture{sourcePath: sourcePath, targetPath: targetPath, source: source, identity: identity, payload: payload}
}

func TestWriteOpenImageHoldsPlainSource(t *testing.T) {
	fixture := newRawSourceHoldFixture(t, 2*1024*1024+37)
	defer fixture.source.Close()
	var status SourceHoldStatus
	result, err := WriteOpenImageWithResult(context.Background(), fixture.source, fixture.targetPath, WriteOptions{
		ExpectedSource: fixture.identity,
		TargetSize:     uint64(len(fixture.payload) + 4096),
		HoldSource:     true,
		SourceHold: func(current SourceHoldStatus) {
			status = current
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !status.Held || status.Fallback {
		t.Fatalf("source hold status=%#v", status)
	}
	if result.BytesWritten != uint64(len(fixture.payload)) {
		t.Fatalf("bytes written=%d", result.BytesWritten)
	}
}

func TestWriteOpenImageFallsBackWithExistingWriter(t *testing.T) {
	fixture := newRawSourceHoldFixture(t, 1024*1024+19)
	defer fixture.source.Close()
	writer, err := os.OpenFile(fixture.sourcePath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	var status SourceHoldStatus
	_, err = WriteOpenImageWithResult(context.Background(), fixture.source, fixture.targetPath, WriteOptions{
		ExpectedSource: fixture.identity,
		TargetSize:     uint64(len(fixture.payload) + 4096),
		HoldSource:     true,
		SourceHold: func(current SourceHoldStatus) {
			status = current
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !status.Fallback || status.Held || !strings.Contains(status.Message, "digest comparison") {
		t.Fatalf("fallback status=%#v", status)
	}
}

func TestWriteOpenImageLeaseBreakBeforeMutationLeavesTargetUntouched(t *testing.T) {
	fixture := newRawSourceHoldFixture(t, 2*1024*1024+61)
	defer fixture.source.Close()
	originalTarget, err := os.ReadFile(fixture.targetPath)
	if err != nil {
		t.Fatal(err)
	}
	atBoundary := make(chan struct{})
	releaseBoundary := make(chan struct{})
	resultDone := make(chan error, 1)
	go func() {
		_, writeErr := WriteOpenImageWithResult(context.Background(), fixture.source, fixture.targetPath, WriteOptions{
			ExpectedSource:       fixture.identity,
			TargetSize:           uint64(len(fixture.payload) + 4096),
			ClearStaleSignatures: true,
			HoldSource:           true,
			beforeMutation: func() {
				close(atBoundary)
				<-releaseBoundary
			},
		})
		resultDone <- writeErr
	}()
	select {
	case <-atBoundary:
	case <-time.After(3 * time.Second):
		t.Fatal("writer never reached the pre-mutation boundary")
	}
	probe, triggerErr := os.OpenFile(fixture.sourcePath, os.O_WRONLY|syscall.O_NONBLOCK, 0)
	if probe != nil {
		_ = probe.Close()
	}
	if !errors.Is(triggerErr, syscall.EAGAIN) {
		t.Fatalf("conflicting writer trigger error=%v", triggerErr)
	}
	time.Sleep(50 * time.Millisecond)
	close(releaseBoundary)
	writeErr := <-resultDone
	if !errors.Is(writeErr, sourcefile.ErrReadLeaseBroken) || !strings.Contains(writeErr.Error(), "nothing was erased") {
		t.Fatalf("pre-mutation lease-break error=%v", writeErr)
	}
	currentTarget, err := os.ReadFile(fixture.targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(originalTarget, currentTarget) {
		t.Fatal("target changed after a pre-mutation source break")
	}
	writer, err := os.OpenFile(fixture.sourcePath, os.O_WRONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatalf("writer remained blocked after cleanup: %v", err)
	}
	_ = writer.Close()
}

func TestWriteOpenImageLeaseBreakDuringWriteReportsIncompleteAndReleasesWriter(t *testing.T) {
	fixture := newRawSourceHoldFixture(t, 16*1024*1024+123)
	defer fixture.source.Close()
	var once sync.Once
	var triggerErr error
	writerDone := make(chan error, 1)
	_, err := WriteOpenImageWithResult(context.Background(), fixture.source, fixture.targetPath, WriteOptions{
		ExpectedSource: fixture.identity,
		TargetSize:     uint64(len(fixture.payload) + 4096),
		HoldSource:     true,
		afterWriteChunk: func(uint64) {
			once.Do(func() {
				probe, openErr := os.OpenFile(fixture.sourcePath, os.O_WRONLY|syscall.O_NONBLOCK, 0)
				if probe != nil {
					_ = probe.Close()
				}
				triggerErr = openErr
				go func() {
					writer, writerErr := os.OpenFile(fixture.sourcePath, os.O_WRONLY, 0)
					if writer != nil {
						_ = writer.Close()
					}
					writerDone <- writerErr
				}()
			})
		},
	})
	if !errors.Is(triggerErr, syscall.EAGAIN) {
		t.Fatalf("conflicting writer trigger error=%v", triggerErr)
	}
	if !errors.Is(err, sourcefile.ErrReadLeaseBroken) || !strings.Contains(err.Error(), "USB is incomplete") {
		t.Fatalf("mid-write lease-break error=%v", err)
	}
	select {
	case writerErr := <-writerDone:
		if writerErr != nil {
			t.Fatalf("blocked writer after cleanup=%v", writerErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("blocked source writer was not released after target cleanup")
	}
}
''', encoding="utf-8")

replace_once(
    "docs/operation-cost-contract.json",
    '''      "intentional_linux_divergence": "RufusArm64 hashes the complete source before writing and again while writing so same-size source mutation fails closed; optional physical verification hashes only the target and compares it with the authenticated write digest.",''',
    '''      "intentional_linux_divergence": "RufusArm64 hashes the complete source before writing and again while writing so same-size source mutation fails closed; plain sources are held under a Linux read lease when available, and optional physical verification hashes only the target.",''',
)

replace_once(
    "docs/upstream-operation-parity.md",
    '''| Raw/ISOHybrid writing | One pre-write source hash plus the source read that writes the image | Optional physical target hash compared with the authenticated write digest; no third source read | Conformant plain-source path after #254; prepared-input hand-off remains in #253 |''',
    '''| Raw/ISOHybrid writing | One pre-write source hash plus the source read that writes the image, with a Linux read lease excluding concurrent mutation when available | Optional physical target hash compared with the authenticated write digest; no third source read | Conformant after #257 |''',
)

replace_once(
    "CHANGELOG.md",
    '''- Reduced sequential compressed-image preparation to one lease-held container read that authenticates while decompressing, removed the post-preparation container rehash on held ZIP/virtual inputs, and passed package-owned expanded digests to the raw writer so private prepared images are read only once during target writing.
''',
    '''- Reduced sequential compressed-image preparation to one lease-held container read that authenticates while decompressing, removed the post-preparation container rehash on held ZIP/virtual inputs, and passed package-owned expanded digests to the raw writer so private prepared images are read only once during target writing.
- Held plain raw/ISOHybrid sources under the identity-bound Linux read lease through destructive writing, while retaining the complete pre-write and write-time digest comparison and the conservative fallback for unsupported or already-writable sources.
''',
)
