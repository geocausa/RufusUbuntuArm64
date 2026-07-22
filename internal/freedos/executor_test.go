package freedos

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestExecuteDevicePlanSuccess(t *testing.T) {
	plan := testFreeDOSDevicePlan(t)
	backend := &memoryExecutionBackend{}
	moment := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	lastProgress := uint64(0)
	report, err := ExecuteDevicePlan(context.Background(), plan, backend, ExecutionOptions{
		Now: func() time.Time { return moment },
		Progress: func(completed uint64) error {
			if completed <= lastProgress {
				t.Fatalf("non-monotonic progress %d after %d", completed, lastProgress)
			}
			lastProgress = completed
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Schema != ExecutionReportSchema || report.Status != ExecutionStatusSucceeded || report.Phase != ExecutionPhaseComplete {
		t.Fatalf("unexpected success report: %+v", report)
	}
	if !report.MediaChanged || !report.Verified || !report.Reusable || report.BytesWritten != plan.DeviceSizeBytes || report.SHA256 == "" {
		t.Fatalf("incomplete success report: %+v", report)
	}
	if report.StartedAt != moment || report.CompletedAt != moment || report.FailureReason != "" {
		t.Fatalf("unexpected report timing or failure: %+v", report)
	}
	if lastProgress != plan.DeviceSizeBytes || backend.prepareCalls != 1 || backend.beforeCalls != 1 ||
		backend.flushCalls != 1 || backend.finishCalls != 1 || backend.closeCalls != 1 {
		t.Fatalf("unexpected backend calls: %+v progress=%d", backend, lastProgress)
	}
	if err := VerifyMediaImage(backend.buffer.Bytes(), plan.Media); err != nil {
		t.Fatalf("successful executor produced invalid media: %v", err)
	}
}

func TestExecuteDevicePlanReportsWriteAndReadbackProgress(t *testing.T) {
	plan := testFreeDOSDevicePlan(t)
	backend := &memoryExecutionBackend{}
	var records []ExecutionProgress
	if _, err := ExecuteDevicePlan(context.Background(), plan, backend, ExecutionOptions{
		PhaseProgress: func(progress ExecutionProgress) error {
			records = append(records, progress)
			return nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	seen := make(map[ExecutionPhase]bool)
	last := make(map[ExecutionPhase]uint64)
	for _, progress := range records {
		seen[progress.Phase] = true
		if progress.Processed < last[progress.Phase] || (progress.Total != 0 && progress.Processed > progress.Total) {
			t.Fatalf("invalid phase progress: %+v after %d", progress, last[progress.Phase])
		}
		last[progress.Phase] = progress.Processed
	}
	for _, phase := range []ExecutionPhase{ExecutionPhasePrepare, ExecutionPhaseWrite, ExecutionPhaseFlush, ExecutionPhaseReadback, ExecutionPhaseFinish} {
		if !seen[phase] {
			t.Fatalf("missing progress phase %q in %+v", phase, records)
		}
	}
	if last[ExecutionPhaseWrite] != plan.DeviceSizeBytes || last[ExecutionPhaseReadback] != plan.DeviceSizeBytes {
		t.Fatalf("incomplete full-device progress: write=%d readback=%d want=%d", last[ExecutionPhaseWrite], last[ExecutionPhaseReadback], plan.DeviceSizeBytes)
	}
}

func TestExecuteDevicePlanRejectsBeforeDestructiveWithoutChangedMedia(t *testing.T) {
	plan := testFreeDOSDevicePlan(t)
	backend := &memoryExecutionBackend{beforeErr: errors.New("identity changed")}
	report, err := ExecuteDevicePlan(context.Background(), plan, backend, ExecutionOptions{})
	if err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("unexpected error %v", err)
	}
	if report.MediaChanged || report.BytesWritten != 0 || report.Verified || report.Reusable || report.Phase != ExecutionPhasePrepare {
		t.Fatalf("pre-destructive failure claimed changed media: %+v", report)
	}
	if backend.closeCalls != 1 {
		t.Fatalf("backend close calls = %d; want 1", backend.closeCalls)
	}
}

func TestExecuteDevicePlanConservativelyMarksWriterFailure(t *testing.T) {
	plan := testFreeDOSDevicePlan(t)
	backend := &memoryExecutionBackend{writer: shortExecutorWriter{}}
	report, err := ExecuteDevicePlan(context.Background(), plan, backend, ExecutionOptions{})
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("writer error = %v; want short write", err)
	}
	if !report.MediaChanged || report.BytesWritten != 1 || report.Verified || report.Reusable || report.Status != ExecutionStatusFailed {
		t.Fatalf("unsafe writer-failure report: %+v", report)
	}
	if backend.flushCalls != 0 || backend.finishCalls != 0 || backend.closeCalls != 1 {
		t.Fatalf("unexpected calls after writer failure: %+v", backend)
	}
}

func TestExecuteDevicePlanCancellationAfterWriteBegins(t *testing.T) {
	plan := testFreeDOSDevicePlan(t)
	ctx, cancel := context.WithCancel(context.Background())
	backend := &memoryExecutionBackend{}
	backend.writer = &cancelExecutorWriter{buffer: &backend.buffer, cancel: cancel}
	report, err := ExecuteDevicePlan(ctx, plan, backend, ExecutionOptions{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
	if report.Status != ExecutionStatusCancelled || !report.MediaChanged || report.BytesWritten != mediaStreamBufferSize || report.Reusable {
		t.Fatalf("unsafe cancellation report: %+v", report)
	}
	if backend.flushCalls != 0 || backend.closeCalls != 1 {
		t.Fatalf("unexpected calls after cancellation: %+v", backend)
	}
}

func TestExecuteDevicePlanRejectsReadbackTampering(t *testing.T) {
	plan := testFreeDOSDevicePlan(t)
	backend := &memoryExecutionBackend{tamperOnFlush: true}
	report, err := ExecuteDevicePlan(context.Background(), plan, backend, ExecutionOptions{})
	if err == nil || !strings.Contains(err.Error(), "readback differs") {
		t.Fatalf("tampered readback error = %v", err)
	}
	if !report.MediaChanged || report.BytesWritten != plan.DeviceSizeBytes || report.Verified || report.Reusable || report.Phase != ExecutionPhaseReadback {
		t.Fatalf("unsafe readback failure report: %+v", report)
	}
	if backend.finishCalls != 0 || backend.closeCalls != 1 {
		t.Fatalf("unexpected calls after readback failure: %+v", backend)
	}
}

func TestExecuteDevicePlanFinalizationAndCloseFailuresAreNotReusable(t *testing.T) {
	plan := testFreeDOSDevicePlan(t)
	for _, test := range []struct {
		name    string
		backend *memoryExecutionBackend
		want    string
	}{
		{"finish", &memoryExecutionBackend{finishErr: errors.New("final identity failed")}, "final identity failed"},
		{"close", &memoryExecutionBackend{closeErr: errors.New("close failed")}, "close failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			report, err := ExecuteDevicePlan(context.Background(), plan, test.backend, ExecutionOptions{})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v; want %q", err, test.want)
			}
			if !report.MediaChanged || !report.Verified || report.Reusable || report.Status != ExecutionStatusFailed {
				t.Fatalf("unsafe final failure report: %+v", report)
			}
		})
	}
}

func TestExecuteDevicePlanRejectsAlteredPlanBeforeBackend(t *testing.T) {
	plan := testFreeDOSDevicePlan(t)
	plan.TargetCPU = "arm64"
	backend := &memoryExecutionBackend{}
	report, err := ExecuteDevicePlan(context.Background(), plan, backend, ExecutionOptions{})
	if err == nil || report.Phase != ExecutionPhasePlan || report.MediaChanged || backend.prepareCalls != 0 || backend.closeCalls != 0 {
		t.Fatalf("altered plan reached backend: report=%+v backend=%+v err=%v", report, backend, err)
	}
}

func testFreeDOSDevicePlan(t *testing.T) DevicePlan {
	t.Helper()
	plan, err := BuildDevicePlan(DeviceRequest{
		DevicePath:        "/dev/sdz",
		ExpectedIdentity:  "usb:vendor:model:serial",
		DeviceSizeBytes:   testMediaSize,
		LogicalSectorSize: 512,
		Label:             "FREEDOS",
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

type memoryExecutionBackend struct {
	buffer        bytes.Buffer
	writer        io.Writer
	prepareErr    error
	beforeErr     error
	flushErr      error
	finishErr     error
	closeErr      error
	tamperOnFlush bool
	prepareCalls  int
	beforeCalls   int
	flushCalls    int
	finishCalls   int
	closeCalls    int
}

func (backend *memoryExecutionBackend) Prepare(context.Context, DevicePlan) error {
	backend.prepareCalls++
	return backend.prepareErr
}

func (backend *memoryExecutionBackend) BeforeDestructive(context.Context, DevicePlan) error {
	backend.beforeCalls++
	return backend.beforeErr
}

func (backend *memoryExecutionBackend) TargetWriter() io.Writer {
	if backend.writer != nil {
		return backend.writer
	}
	return &backend.buffer
}

func (backend *memoryExecutionBackend) Flush(context.Context, DevicePlan) error {
	backend.flushCalls++
	if backend.tamperOnFlush && backend.buffer.Len() > 0 {
		backend.buffer.Bytes()[backend.buffer.Len()-4096] ^= 0x7f
	}
	return backend.flushErr
}

func (backend *memoryExecutionBackend) TargetReaderAt() io.ReaderAt {
	return bytes.NewReader(backend.buffer.Bytes())
}

func (backend *memoryExecutionBackend) Finish(context.Context, DevicePlan) error {
	backend.finishCalls++
	return backend.finishErr
}

func (backend *memoryExecutionBackend) Close() error {
	backend.closeCalls++
	return backend.closeErr
}

type shortExecutorWriter struct{}

func (shortExecutorWriter) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	return 1, nil
}

type cancelExecutorWriter struct {
	buffer *bytes.Buffer
	cancel context.CancelFunc
	calls  int
}

func (writer *cancelExecutorWriter) Write(data []byte) (int, error) {
	writer.calls++
	count, err := writer.buffer.Write(data)
	if writer.calls == 1 {
		writer.cancel()
	}
	return count, err
}
