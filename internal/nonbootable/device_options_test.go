//go:build linux

package nonbootable

import (
	"context"
	"strings"
	"testing"
)

func TestExecuteDeviceRequiresBoundKernelIdentity(t *testing.T) {
	plan := executorPlan(t)
	_, err := ExecuteDevice(context.Background(), plan, DeviceOptions{
		BeforeDestructive: func(*os.File) error { return nil },
	})
	if err == nil || !strings.Contains(err.Error(), "bound kernel device identity") {
		t.Fatalf("missing identity error=%v", err)
	}
}

func TestExecuteDeviceRequiresFinalSafetyCallback(t *testing.T) {
	plan := executorPlan(t)
	_, err := ExecuteDevice(context.Background(), plan, DeviceOptions{ExpectedDeviceID: 1})
	if err == nil || !strings.Contains(err.Error(), "final pre-destructive safety callback") {
		t.Fatalf("missing callback error=%v", err)
	}
}
