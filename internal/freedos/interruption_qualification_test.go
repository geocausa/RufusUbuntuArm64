package freedos

import (
	"context"
	"errors"
	"io"
	"testing"
)

func TestExecuteDevicePlanInterruptionQualification(t *testing.T) {
	plan := testFreeDOSDevicePlan(t)
	tests := []struct {
		name    string
		backend *memoryExecutionBackend
		changed bool
		phase   ExecutionPhase
	}{
		{"before destructive", &memoryExecutionBackend{beforeErr: errors.New("identity changed")}, false, ExecutionPhasePrepare},
		{"short target write", &memoryExecutionBackend{writer: shortExecutorWriterAt{}}, true, ExecutionPhaseWrite},
		{"target flush", &memoryExecutionBackend{flushErr: errors.New("flush failed")}, true, ExecutionPhaseFlush},
		{"readback mismatch", &memoryExecutionBackend{tamperOnFlush: true}, true, ExecutionPhaseReadback},
		{"final identity", &memoryExecutionBackend{finishErr: errors.New("finish failed")}, true, ExecutionPhaseFinish},
		{"close", &memoryExecutionBackend{closeErr: errors.New("close failed")}, true, ExecutionPhaseFinish},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report, err := ExecuteDevicePlan(context.Background(), plan, test.backend, ExecutionOptions{})
			if err == nil {
				t.Fatal("injected interruption was reported as success")
			}
			if errors.Is(err, io.EOF) {
				t.Fatalf("unexpected truncated error classification: %v", err)
			}
			if report.MediaChanged != test.changed || report.Reusable || report.Status == ExecutionStatusSucceeded || report.Phase != test.phase {
				t.Fatalf("unsafe interruption report: %+v", report)
			}
			if !test.changed && (report.BytesWritten != 0 || report.BytesVerified != 0) {
				t.Fatalf("pre-mutation failure claimed I/O: %+v", report)
			}
		})
	}
}
