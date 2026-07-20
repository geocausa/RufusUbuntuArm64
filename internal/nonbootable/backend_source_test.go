//go:build linux

package nonbootable

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFormatterUsesAuditedReopenableWholeDiskContract(t *testing.T) {
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate formatter source")
	}
	content, err := os.ReadFile(filepath.Join(filepath.Dir(current), "backend_linux.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	openIndex := strings.Index(text, "safety.OpenReopenableDevice(plan.DevicePath)")
	lockIndex := strings.Index(text, "safety.AcquireExclusiveFlock(ctx, file)")
	verifyIndex := strings.Index(text, "safety.VerifyOpenDevice(file, backend.options.ExpectedDeviceID, plan.DeviceSizeBytes)")
	callbackIndex := strings.Index(text, "backend.options.BeforeDestructive(file)")
	if openIndex < 0 || lockIndex < openIndex || verifyIndex < lockIndex || callbackIndex < verifyIndex {
		t.Fatalf("formatter target sequence is not open -> lock -> verify -> final callback")
	}
	if strings.Contains(text, "os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_EXCL") {
		t.Fatal("formatter must not hold O_EXCL while trusted filesystem tools reopen partitions")
	}
	if !strings.Contains(text, "syscall.Flock(int(backend.target.Fd()), syscall.LOCK_UN)") {
		t.Fatal("formatter does not release its whole-disk advisory lock during cleanup")
	}
}
