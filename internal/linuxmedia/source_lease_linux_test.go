//go:build linux

package linuxmedia

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

type persistentSourceLeaseFixture struct {
	isoPath    string
	targetPath string
	logPath    string
	identity   sourcefile.Identity
	options    PersistentCreateOptions
}

func newPersistentSourceLeaseFixture(t *testing.T, largeCopy bool) persistentSourceLeaseFixture {
	t.Helper()
	isoRoot := t.TempDir()
	writeLinuxTestFile(t, filepath.Join(isoRoot, ".disk", "info"), "Ubuntu 24.04.2 LTS arm64\n")
	writeLinuxTestFile(t, filepath.Join(isoRoot, "casper", "vmlinuz"), "kernel")
	writeLinuxTestFile(t, filepath.Join(isoRoot, "casper", "initrd"), "initrd")
	payload := []byte("squashfs")
	if largeCopy {
		payload = make([]byte, 8*1024*1024+123)
	}
	writeLinuxTestBytes(t, filepath.Join(isoRoot, "casper", "filesystem.squashfs"), payload)
	writeLinuxTestBytes(t, filepath.Join(isoRoot, "EFI", "BOOT", "BOOTAA64.EFI"), linuxTestARM64EFI(0x44))
	writeLinuxTestFile(t, filepath.Join(isoRoot, "boot", "grub", "grub.cfg"), "linux /casper/vmlinuz boot=casper --- quiet\n")

	manifest, err := Inspect(context.Background(), isoRoot, Options{Architecture: "arm64", RequireUEFI: true, RequireFAT32: true})
	if err != nil {
		t.Fatal(err)
	}
	const targetSize = uint64(4 * 1024 * 1024 * 1024)
	layout, err := PlanPersistentLayout(targetSize, 512, manifest.TotalBytes, minimumPersistence, readyUbuntuDetection())
	if err != nil {
		t.Fatal(err)
	}

	isoPath := filepath.Join(t.TempDir(), "ubuntu.iso")
	writeLinuxTestFile(t, isoPath, "identity-bound source image")
	_, identity, err := sourcefile.Inspect(isoPath)
	if err != nil {
		t.Fatal(err)
	}
	targetPath := filepath.Join(t.TempDir(), "target.img")
	truncateLinuxTestFile(t, targetPath, targetSize)
	bootPartition := filepath.Join(t.TempDir(), "boot-partition.img")
	truncateLinuxTestFile(t, bootPartition, layout.Boot.SizeBytes)
	persistencePartition := filepath.Join(t.TempDir(), "persistence-partition.img")
	truncateLinuxTestFile(t, persistencePartition, layout.Persistence.SizeBytes)
	bootRoot := t.TempDir()
	fakeBin := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "commands.log")
	installPersistentFakeTools(t, fakeBin)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("RUFUS_TEST_ISO_ROOT", isoRoot)
	t.Setenv("RUFUS_TEST_BOOT_ROOT", bootRoot)
	t.Setenv("RUFUS_TEST_BOOT_PARTITION", bootPartition)
	t.Setenv("RUFUS_TEST_PERSIST_PARTITION", persistencePartition)
	t.Setenv("RUFUS_TEST_PARTITION", persistencePartition)
	t.Setenv("RUFUS_TEST_LOG", logPath)

	return persistentSourceLeaseFixture{
		isoPath:    isoPath,
		targetPath: targetPath,
		logPath:    logPath,
		identity:   identity,
		options: PersistentCreateOptions{
			TargetSize:      targetSize,
			ExpectedSource:  identity,
			Architecture:    "arm64",
			PersistenceSize: minimumPersistence,
			VolumeLabel:     "RUFUS-LIVE",
			WorkDirectory:   t.TempDir(),
			CreatorVersion:  "RufusArm64 source-lease test",
		},
	}
}

func TestCreatePersistentUsesOneHashUnderKernelSourceHold(t *testing.T) {
	fixture := newPersistentSourceLeaseFixture(t, false)
	var events []PersistentEvent
	_, err := CreatePersistent(context.Background(), fixture.isoPath, fixture.targetPath, fixture.options, func(event PersistentEvent) {
		events = append(events, event)
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := completedPersistentSourceHashPasses(events); got != 1 {
		t.Fatalf("complete source-image hash passes = %d, events=%#v", got, events)
	}
	if !persistentEventMessagesContain(events, "Linux kernel lease") {
		t.Fatalf("kernel source-hold message missing: %#v", events)
	}
	if !containsPersistentEventStage(events, "complete") {
		t.Fatalf("successful creation did not report completion: %#v", events)
	}
}

func TestCreatePersistentRetainsThreeHashFallbackWithExistingWriter(t *testing.T) {
	fixture := newPersistentSourceLeaseFixture(t, false)
	writer, err := os.OpenFile(fixture.isoPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()

	var events []PersistentEvent
	_, err = CreatePersistent(context.Background(), fixture.isoPath, fixture.targetPath, fixture.options, func(event PersistentEvent) {
		events = append(events, event)
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := completedPersistentSourceHashPasses(events); got != 3 {
		t.Fatalf("fallback complete source-image hash passes = %d, events=%#v", got, events)
	}
	if !persistentEventMessagesContain(events, "conservative three-pass") {
		t.Fatalf("fallback source-verification message missing: %#v", events)
	}
}

func TestCreatePersistentLeaseBreakBeforeErasureLeavesTargetUntouched(t *testing.T) {
	fixture := newPersistentSourceLeaseFixture(t, false)
	var once sync.Once
	var triggerErr error
	var events []PersistentEvent
	_, err := CreatePersistent(context.Background(), fixture.isoPath, fixture.targetPath, fixture.options, func(event PersistentEvent) {
		events = append(events, event)
		if event.Stage == "hash_source" && event.Total > 0 && event.Done == event.Total {
			once.Do(func() {
				writer, openErr := os.OpenFile(fixture.isoPath, os.O_WRONLY|syscall.O_NONBLOCK, 0)
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
	if strings.Contains(readPersistentOptionalLog(t, fixture.logPath), "wipefs") {
		t.Fatal("target was touched after pre-erasure source break")
	}
	if containsPersistentEventStage(events, "complete") {
		t.Fatalf("failed source hold reported completion: %#v", events)
	}
	writer, openErr := os.OpenFile(fixture.isoPath, os.O_WRONLY|syscall.O_NONBLOCK, 0)
	if openErr != nil {
		t.Fatalf("writer remained blocked after cleanup: %v", openErr)
	}
	_ = writer.Close()
}

func TestCreatePersistentLeaseBreakDuringCopyReportsIncompleteAndReleasesWriter(t *testing.T) {
	fixture := newPersistentSourceLeaseFixture(t, true)
	var once sync.Once
	var triggerErr error
	writerDone := make(chan error, 1)
	var events []PersistentEvent
	_, err := CreatePersistent(context.Background(), fixture.isoPath, fixture.targetPath, fixture.options, func(event PersistentEvent) {
		events = append(events, event)
		if event.Stage != "copy" || event.Done == 0 {
			return
		}
		once.Do(func() {
			probe, openErr := os.OpenFile(fixture.isoPath, os.O_WRONLY|syscall.O_NONBLOCK, 0)
			if probe != nil {
				_ = probe.Close()
			}
			triggerErr = openErr
			go func() {
				writer, writerErr := os.OpenFile(fixture.isoPath, os.O_WRONLY, 0)
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
	if !strings.Contains(readPersistentOptionalLog(t, fixture.logPath), "wipefs") {
		t.Fatal("copy-break test never reached destructive work")
	}
	if containsPersistentEventStage(events, "complete") {
		t.Fatalf("incomplete media reported completion: %#v", events)
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

func completedPersistentSourceHashPasses(events []PersistentEvent) int {
	count := 0
	for _, event := range events {
		if (event.Stage == "hash_source" || event.Stage == "verify_source") && event.Total > 0 && event.Done == event.Total {
			count++
		}
	}
	return count
}

func persistentEventMessagesContain(events []PersistentEvent, text string) bool {
	for _, event := range events {
		if strings.Contains(event.Message, text) {
			return true
		}
	}
	return false
}

func containsPersistentEventStage(events []PersistentEvent, wanted string) bool {
	for _, event := range events {
		if event.Stage == wanted {
			return true
		}
	}
	return false
}

func readPersistentOptionalLog(t *testing.T, path string) string {
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
