//go:build linux

package windowsmedia

import (
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

type windowsSourceLeaseFixture struct {
	iso       string
	target    string
	logPath   string
	partition string
}

func newWindowsSourceLeaseFixture(t *testing.T, largeCopy bool) windowsSourceLeaseFixture {
	t.Helper()
	fixture := t.TempDir()
	writeTestFile(t, filepath.Join(fixture, "sources", "boot.wim"), []byte("boot"))
	writeTestFile(t, filepath.Join(fixture, "sources", "install.wim"), []byte("install"))
	writeTestFile(t, filepath.Join(fixture, "efi", "boot", "bootaa64.efi"), []byte("efi"))
	setup := []byte("setup")
	if largeCopy {
		setup = make([]byte, 8*1024*1024+123)
	}
	writeTestFile(t, filepath.Join(fixture, "setup.exe"), setup)

	fakeBin := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "commands.log")
	partition := filepath.Join(t.TempDir(), "fake-partition")
	writeTestFile(t, partition, make([]byte, 1024))
	installFakeTools(t, fakeBin)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("RUFUS_TEST_ISO", fixture)
	t.Setenv("RUFUS_TEST_LOG", logPath)
	t.Setenv("RUFUS_TEST_PARTITION", partition)

	iso := fakeISOFile(t)
	target := filepath.Join(t.TempDir(), "fake-device")
	writeTestFile(t, target, make([]byte, 1024))
	return windowsSourceLeaseFixture{iso: iso, target: target, logPath: logPath, partition: partition}
}

func TestCreateUsesOneHashUnderKernelSourceHold(t *testing.T) {
	fixture := newWindowsSourceLeaseFixture(t, false)
	var events []Event
	err := Create(context.Background(), fixture.iso, fixture.target, Options{
		TargetSize:   8 * 1024 * 1024 * 1024,
		RequireARM64: true,
		Verify:       true,
	}, func(event Event) { events = append(events, event) })
	if err != nil {
		t.Fatal(err)
	}
	if got := completedWindowsISOHashPasses(events); got != 1 {
		t.Fatalf("complete ISO hash passes = %d, events=%#v", got, events)
	}
	if !eventMessagesContain(events, "Linux kernel lease") {
		t.Fatalf("kernel source-hold message missing: %#v", events)
	}
}

func TestCreateRetainsThreeHashFallbackWithExistingWriter(t *testing.T) {
	fixture := newWindowsSourceLeaseFixture(t, false)
	writer, err := os.OpenFile(fixture.iso, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()

	var events []Event
	err = Create(context.Background(), fixture.iso, fixture.target, Options{
		TargetSize:   8 * 1024 * 1024 * 1024,
		RequireARM64: true,
	}, func(event Event) { events = append(events, event) })
	if err != nil {
		t.Fatal(err)
	}
	if got := completedWindowsISOHashPasses(events); got != 3 {
		t.Fatalf("fallback complete ISO hash passes = %d, events=%#v", got, events)
	}
	if !eventMessagesContain(events, "conservative three-pass") {
		t.Fatalf("fallback source-verification message missing: %#v", events)
	}
}

func TestCreateLeaseBreakBeforeErasureLeavesTargetUntouched(t *testing.T) {
	fixture := newWindowsSourceLeaseFixture(t, false)
	var once sync.Once
	var triggerErr error
	err := Create(context.Background(), fixture.iso, fixture.target, Options{
		TargetSize:   8 * 1024 * 1024 * 1024,
		RequireARM64: true,
	}, func(event Event) {
		if event.Stage == "hash_source" && event.Total > 0 && event.Done == event.Total {
			once.Do(func() {
				writer, openErr := os.OpenFile(fixture.iso, os.O_WRONLY|syscall.O_NONBLOCK, 0)
				if writer != nil {
					_ = writer.Close()
				}
				triggerErr = openErr
			})
		}
	})
	if !errors.Is(triggerErr, syscall.EAGAIN) {
		t.Fatalf("conflicting writer trigger error = %v", triggerErr)
	}
	if !errors.Is(err, sourcefile.ErrReadLeaseBroken) || !strings.Contains(err.Error(), "nothing was erased") {
		t.Fatalf("pre-erasure lease-break error = %v", err)
	}
	if strings.Contains(readOptionalLog(t, fixture.logPath), "wipefs") {
		t.Fatalf("target was touched after pre-erasure source break")
	}
	writer, openErr := os.OpenFile(fixture.iso, os.O_WRONLY|syscall.O_NONBLOCK, 0)
	if openErr != nil {
		t.Fatalf("writer remained blocked after cleanup: %v", openErr)
	}
	_ = writer.Close()
}

func TestCreateLeaseBreakDuringCopyReportsIncompleteAndReleasesWriter(t *testing.T) {
	fixture := newWindowsSourceLeaseFixture(t, true)
	var once sync.Once
	var triggerErr error
	writerDone := make(chan error, 1)
	err := Create(context.Background(), fixture.iso, fixture.target, Options{
		TargetSize:   8 * 1024 * 1024 * 1024,
		RequireARM64: true,
	}, func(event Event) {
		if event.Stage != "copy" || event.Done == 0 {
			return
		}
		once.Do(func() {
			probe, openErr := os.OpenFile(fixture.iso, os.O_WRONLY|syscall.O_NONBLOCK, 0)
			if probe != nil {
				_ = probe.Close()
			}
			triggerErr = openErr
			go func() {
				writer, writerErr := os.OpenFile(fixture.iso, os.O_WRONLY, 0)
				if writer != nil {
					_ = writer.Close()
				}
				writerDone <- writerErr
			}()
		})
	})
	if !errors.Is(triggerErr, syscall.EAGAIN) {
		t.Fatalf("conflicting writer trigger error = %v", triggerErr)
	}
	if !errors.Is(err, sourcefile.ErrReadLeaseBroken) || !strings.Contains(err.Error(), "USB is incomplete") {
		t.Fatalf("post-erasure lease-break error = %v", err)
	}
	if !strings.Contains(readOptionalLog(t, fixture.logPath), "wipefs") {
		t.Fatalf("copy-break test never reached destructive work")
	}
	select {
	case writerErr := <-writerDone:
		if writerErr != nil {
			t.Fatalf("blocked writer after cleanup = %v", writerErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("blocked writer was not released during operation cleanup")
	}
}

func completedWindowsISOHashPasses(events []Event) int {
	count := 0
	for _, event := range events {
		if (event.Stage == "hash_source" || event.Stage == "verify_source") && event.Total > 0 && event.Done == event.Total {
			count++
		}
	}
	return count
}

func eventMessagesContain(events []Event, text string) bool {
	for _, event := range events {
		if strings.Contains(event.Message, text) {
			return true
		}
	}
	return false
}

func readOptionalLog(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
