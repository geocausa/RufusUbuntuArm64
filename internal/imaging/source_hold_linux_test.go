//go:build linux

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
