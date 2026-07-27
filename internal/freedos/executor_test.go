package freedos

import (
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
	if !report.MediaChanged || !report.Verified || !report.Reusable ||
		report.BytesWritten != plan.MutationBytes || report.BytesVerified != plan.VerificationBytes ||
		report.VerificationScope != MediaVerificationScope || report.SHA256 == "" {
		t.Fatalf("incomplete success report: %+v", report)
	}
	if report.StartedAt != moment || report.CompletedAt != moment || report.FailureReason != "" {
		t.Fatalf("unexpected report timing or failure: %+v", report)
	}
	if lastProgress != plan.MutationBytes || backend.prepareCalls != 1 || backend.beforeCalls != 1 ||
		backend.flushCalls != 1 || backend.finishCalls != 1 || backend.closeCalls != 1 {
		t.Fatalf("unexpected backend calls: %+v progress=%d", backend, lastProgress)
	}
	if backend.device == nil {
		t.Fatal("successful executor did not create a target device")
	}
	if err := VerifyMediaImage(backend.device.data, plan.Media); err != nil {
		t.Fatalf("successful executor produced invalid media: %v", err)
	}
}

func TestExecuteDevicePlanReportsRequiredExtentProgress(t *testing.T) {
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
	totals := make(map[ExecutionPhase]uint64)
	for _, progress := range records {
		seen[progress.Phase] = true
		if progress.Processed < last[progress.Phase] || (progress.Total != 0 && progress.Processed > progress.Total) {
			t.Fatalf("invalid phase progress: %+v after %d", progress, last[progress.Phase])
		}
		last[progress.Phase] = progress.Processed
		if progress.Total != 0 {
			totals[progress.Phase] = progress.Total
		}
	}
	for _, phase := range []ExecutionPhase{ExecutionPhasePrepare, ExecutionPhaseWrite, ExecutionPhaseFlush, ExecutionPhaseReadback, ExecutionPhaseFinish} {
		if !seen[phase] {
			t.Fatalf("missing progress phase %q in %+v", phase, records)
		}
	}
	if last[ExecutionPhaseWrite] != plan.MutationBytes || totals[ExecutionPhaseWrite] != plan.MutationBytes ||
		last[ExecutionPhaseReadback] != plan.VerificationBytes || totals[ExecutionPhaseReadback] != plan.VerificationBytes {
		t.Fatalf("incomplete required-extent progress: write=%d/%d readback=%d/%d plan=%+v",
			last[ExecutionPhaseWrite], totals[ExecutionPhaseWrite], last[ExecutionPhaseReadback], totals[ExecutionPhaseReadback], plan)
	}
	if plan.MutationBytes >= plan.DeviceSizeBytes || plan.VerificationBytes >= plan.DeviceSizeBytes {
		t.Fatalf("required-extent progress still scales as whole-device I/O: %+v", plan)
	}
}

func TestExecuteDevicePlanRejectsBeforeDestructiveWithoutChangedMedia(t *testing.T) {
	plan := testFreeDOSDevicePlan(t)
	backend := &memoryExecutionBackend{beforeErr: errors.New("identity changed")}
	report, err := ExecuteDevicePlan(context.Background(), plan, backend, ExecutionOptions{})
	if err == nil || !strings.Contains(err.Error(), "identity changed") {
		t.Fatalf("unexpected error %v", err)
	}
	if report.MediaChanged || report.BytesWritten != 0 || report.BytesVerified != 0 || report.Verified || report.Reusable || report.Phase != ExecutionPhasePrepare {
		t.Fatalf("pre-destructive failure claimed changed media: %+v", report)
	}
	if backend.closeCalls != 1 {
		t.Fatalf("backend close calls = %d; want 1", backend.closeCalls)
	}
}

func TestExecuteDevicePlanConservativelyMarksWriterFailure(t *testing.T) {
	plan := testFreeDOSDevicePlan(t)
	backend := &memoryExecutionBackend{writer: shortExecutorWriterAt{}}
	report, err := ExecuteDevicePlan(context.Background(), plan, backend, ExecutionOptions{})
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("writer error = %v; want short write", err)
	}
	if !report.MediaChanged || report.BytesWritten != 1 || report.BytesVerified != 0 || report.Verified || report.Reusable || report.Status != ExecutionStatusFailed {
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
	backend.writerFactory = func(device *extentMemoryDevice) io.WriterAt {
		return &cancelExecutorWriterAt{device: device, cancel: cancel}
	}
	report, err := ExecuteDevicePlan(ctx, plan, backend, ExecutionOptions{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v; want context cancellation", err)
	}
	if report.Status != ExecutionStatusCancelled || !report.MediaChanged || report.BytesWritten == 0 ||
		report.BytesWritten >= plan.MutationBytes || report.BytesVerified != 0 || report.Reusable {
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
	if !report.MediaChanged || report.BytesWritten != plan.MutationBytes || report.BytesVerified >= plan.VerificationBytes ||
		report.Verified || report.Reusable || report.Phase != ExecutionPhaseReadback {
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
			if !report.MediaChanged || !report.Verified || report.BytesVerified != plan.VerificationBytes ||
				report.Reusable || report.Status != ExecutionStatusFailed {
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
	device        *extentMemoryDevice
	writer        io.WriterAt
	writerFactory func(*extentMemoryDevice) io.WriterAt
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

func (backend *memoryExecutionBackend) Prepare(_ context.Context, plan DevicePlan) error {
	backend.prepareCalls++
	if backend.prepareErr != nil {
		return backend.prepareErr
	}
	backend.device = &extentMemoryDevice{data: make([]byte, int(plan.DeviceSizeBytes))}
	if backend.writerFactory != nil {
		backend.writer = backend.writerFactory(backend.device)
	}
	return nil
}

func (backend *memoryExecutionBackend) BeforeDestructive(context.Context, DevicePlan) error {
	backend.beforeCalls++
	return backend.beforeErr
}

func (backend *memoryExecutionBackend) TargetWriterAt() io.WriterAt {
	if backend.writer != nil {
		return backend.writer
	}
	return backend.device
}

func (backend *memoryExecutionBackend) Flush(context.Context, DevicePlan) error {
	backend.flushCalls++
	if backend.tamperOnFlush && backend.device != nil && len(backend.device.data) > 510 {
		backend.device.data[510] ^= 0x7f
	}
	return backend.flushErr
}

func (backend *memoryExecutionBackend) TargetReaderAt() io.ReaderAt {
	if backend.device == nil {
		return nil
	}
	return backend.device
}

func (backend *memoryExecutionBackend) Finish(context.Context, DevicePlan) error {
	backend.finishCalls++
	return backend.finishErr
}

func (backend *memoryExecutionBackend) Close() error {
	backend.closeCalls++
	return backend.closeErr
}

type shortExecutorWriterAt struct{}

func (shortExecutorWriterAt) WriteAt(data []byte, _ int64) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	return 1, nil
}

type cancelExecutorWriterAt struct {
	device *extentMemoryDevice
	cancel context.CancelFunc
	calls  int
}

func (writer *cancelExecutorWriterAt) WriteAt(data []byte, offset int64) (int, error) {
	writer.calls++
	count, err := writer.device.WriteAt(data, offset)
	if writer.calls == 1 {
		writer.cancel()
	}
	return count, err
}
