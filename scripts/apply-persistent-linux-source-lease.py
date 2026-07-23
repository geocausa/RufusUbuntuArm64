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
    "internal/linuxmedia/create.go",
    '''\tstableISOPath := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), isoFile.Fd())

\tsourceDigest, err := hashPersistentSource(ctx, isoFile, opts.ExpectedSource, emit, "hash_source", "Hashing the selected Linux image…")
''',
    '''\tstableISOPath := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), isoFile.Fd())
\ttargetChanged := false

\tsourceLease, leaseErr := sourcefile.AcquireReadLease(ctx, isoFile, opts.ExpectedSource)
\tswitch {
\tcase leaseErr == nil:
\t\tctx = sourceLease.Context()
\t\tsendPersistent(emit, PersistentEvent{Stage: "source_hold", Message: "Holding the selected Linux image read-only with a Linux kernel lease; one complete SHA-256 pass will authenticate the held bytes."})
\t\tdefer func() {
\t\t\theldErr := sourceLease.Check()
\t\t\tif errors.Is(heldErr, sourcefile.ErrReadLeaseBroken) {
\t\t\t\tmessage := "the selected Linux image was opened for writing while media preparation was in progress; nothing was erased"
\t\t\t\tif targetChanged {
\t\t\t\t\tmessage = "the selected Linux image was opened for writing while USB creation was in progress; the USB is incomplete and must be recreated"
\t\t\t\t}
\t\t\t\theldErr = fmt.Errorf("%s: %w", message, heldErr)
\t\t\t}
\t\t\tcloseErr := sourceLease.Close()
\t\t\tif heldErr != nil || closeErr != nil {
\t\t\t\tcompleted = false
\t\t\t}
\t\t\treturnErr = errors.Join(returnErr, heldErr, closeErr)
\t\t}()
\tcase errors.Is(leaseErr, sourcefile.ErrReadLeaseUnavailable), errors.Is(leaseErr, sourcefile.ErrReadLeaseConflict):
\t\tsourceLease = nil
\t\tsendPersistent(emit, PersistentEvent{Stage: "source_hold", Message: fmt.Sprintf("Kernel source hold unavailable (%v); using conservative three-pass SHA-256 source verification.", leaseErr)})
\tdefault:
\t\treturn result, fmt.Errorf("hold selected Linux image stable: %w", leaseErr)
\t}

\tinitialHashMessage := "Hashing the selected Linux image once under the kernel source hold…"
\tif sourceLease == nil {
\t\tinitialHashMessage = "Hashing the selected Linux image (conservative pass 1 of 3)…"
\t}
\tsourceDigest, err := hashPersistentSource(ctx, isoFile, opts.ExpectedSource, emit, "hash_source", initialHashMessage)
''',
)

replace_once(
    "internal/linuxmedia/create.go",
    '''\tpreDestructiveDigest, err := hashPersistentSource(ctx, isoFile, opts.ExpectedSource, emit, "verify_source", "Rechecking the Linux image before erasing the USB…")
\tif err != nil {
\t\treturn result, err
\t}
\tif !bytes.Equal(sourceDigest[:], preDestructiveDigest[:]) {
\t\treturn result, errors.New("the selected Linux image changed during inspection; nothing was erased")
\t}
\tcheckTarget := func() error {
\t\tif err := sourcefile.VerifyPinned(isoFile, opts.ExpectedSource); err != nil {
''',
    '''\tif sourceLease != nil {
\t\tif err := sourceLease.Check(); err != nil {
\t\t\treturn result, fmt.Errorf("confirm held Linux image before erasing the USB: %w", err)
\t\t}
\t} else {
\t\tpreDestructiveDigest, err := hashPersistentSource(ctx, isoFile, opts.ExpectedSource, emit, "verify_source", "Rechecking the Linux image before erasing the USB (conservative pass 2 of 3)…")
\t\tif err != nil {
\t\t\treturn result, err
\t\t}
\t\tif !bytes.Equal(sourceDigest[:], preDestructiveDigest[:]) {
\t\t\treturn result, errors.New("the selected Linux image changed during inspection; nothing was erased")
\t\t}
\t}
\tcheckTarget := func() error {
\t\tif sourceLease != nil {
\t\t\tif err := sourceLease.Check(); err != nil {
\t\t\t\treturn err
\t\t\t}
\t\t}
\t\tif err := sourcefile.VerifyPinned(isoFile, opts.ExpectedSource); err != nil {
''',
)

replace_once(
    "internal/linuxmedia/create.go",
    '''\tif opts.BeforeDestructive != nil {
\t\tif err := opts.BeforeDestructive(isoFile); err != nil {
\t\t\treturn result, fmt.Errorf("target safety check: %w", err)
\t\t}
\t}

\tsendPersistent(emit, PersistentEvent{Stage: "partition", Message: "Creating a fresh GPT layout for writable Linux boot files and persistence…"})
''',
    '''\tif opts.BeforeDestructive != nil {
\t\tif err := opts.BeforeDestructive(isoFile); err != nil {
\t\t\treturn result, fmt.Errorf("target safety check: %w", err)
\t\t}
\t}

\ttargetChanged = true
\tsendPersistent(emit, PersistentEvent{Stage: "partition", Message: "Creating a fresh GPT layout for writable Linux boot files and persistence…"})
''',
)

replace_once(
    "internal/linuxmedia/create.go",
    '''\tpostDigest, err := hashPersistentSource(ctx, isoFile, opts.ExpectedSource, emit, "verify_source", "Checking that the Linux image stayed unchanged…")
\tif err != nil {
\t\treturn result, err
\t}
\tif !bytes.Equal(sourceDigest[:], postDigest[:]) {
\t\treturn result, errors.New("the selected Linux image changed while the USB was being created; recreate the USB")
\t}
''',
    '''\tif sourceLease != nil {
\t\tif err := sourceLease.Check(); err != nil {
\t\t\treturn result, fmt.Errorf("confirm held Linux image after copying: %w", err)
\t\t}
\t} else {
\t\tpostDigest, err := hashPersistentSource(ctx, isoFile, opts.ExpectedSource, emit, "verify_source", "Checking that the Linux image stayed unchanged (conservative pass 3 of 3)…")
\t\tif err != nil {
\t\t\treturn result, err
\t\t}
\t\tif !bytes.Equal(sourceDigest[:], postDigest[:]) {
\t\t\treturn result, errors.New("the selected Linux image changed while the USB was being created; recreate the USB")
\t\t}
\t}
''',
)

replace_once(
    "docs/operation-cost-contract.json",
    '''      "id": "linux_persistent_create",
      "surface": "Create persistent Linux media",
      "classification": "ordinary_creation",
      "status": "audit",
      "tracking_issue": 242,
      "upstream_operation": "Create a writable boot filesystem and persistence partition, copy the supported live-media tree, and patch boot configuration.",
      "intentional_linux_divergence": "The Linux-native path currently performs three complete source-image hashes in addition to manifest-bound copy and destination verification.",
      "phases": [
        {
          "name": "complete_source_hashes",
          "direction": "source_read",
          "scaling": "source_size",
          "multiplier": 3,
          "enabled_by_default": true
        },
''',
    '''      "id": "linux_persistent_create",
      "surface": "Create persistent Linux media",
      "classification": "ordinary_creation",
      "status": "conformant",
      "tracking_issue": 251,
      "upstream_operation": "Create a writable boot filesystem and persistence partition, copy the supported live-media tree, and patch boot configuration.",
      "intentional_linux_divergence": "RufusArm64 authenticates one complete source-image hash while a Linux read lease excludes mutation; unsupported or contended sources retain two conditional fallback hashes and the original three-pass comparison.",
      "phases": [
        {
          "name": "authenticate_held_source_image",
          "direction": "source_read",
          "scaling": "source_size",
          "multiplier": 1,
          "enabled_by_default": true
        },
        {
          "name": "conservative_fallback_hashes",
          "direction": "source_read",
          "scaling": "source_size",
          "multiplier": 2,
          "enabled_by_default": false
        },
''',
)

replace_once(
    "docs/upstream-operation-parity.md",
    '''| Persistent Linux media | Copied media tree, but currently three complete ISO hashes | Manifest-bound destination verification | Audit in #242 |''',
    '''| Persistent Linux media | Copied media tree plus one complete source-image hash under a kernel read lease; two extra hashes only on conservative fallback | Manifest-bound destination verification | Conformant software path after #251 |''',
)

replace_once(
    "internal/operationcost/contract.go",
    '''\tif err := requirePhase(operations["windows_install"], "target_write", "copied_payload", true); err != nil {
\t\treturn err
\t}
\tif err := requirePhase(operations["raw_image_write"], "target_write", "source_size", true); err != nil {
''',
    '''\tif err := requirePhase(operations["windows_install"], "target_write", "copied_payload", true); err != nil {
\t\treturn err
\t}
\tif err := requireExactPhase(operations["linux_persistent_create"], "authenticate_held_source_image", "source_read", "source_size", 1, true); err != nil {
\t\treturn err
\t}
\tif err := requireExactPhase(operations["linux_persistent_create"], "conservative_fallback_hashes", "source_read", "source_size", 2, false); err != nil {
\t\treturn err
\t}
\tif err := requirePhase(operations["raw_image_write"], "target_write", "source_size", true); err != nil {
''',
)

replace_once(
    "internal/operationcost/contract_test.go",
    '''func TestDecodeRejectsUnknownFieldsAndTrailingJSON(t *testing.T) {''',
    '''func TestValidateRequiresOneDefaultPersistentLinuxSourceHash(t *testing.T) {
\tcontract := loadRepositoryContract(t)
\toperation := findOperationIndex(t, contract, "linux_persistent_create")
\tcontract.Operations[operation].Phases[0].Multiplier = 3
\tif err := Validate(contract); err == nil || !strings.Contains(err.Error(), "authenticate_held_source_image") {
\t\tt.Fatalf("persistent Linux default source-hash boundary error = %v", err)
\t}
}

func TestDecodeRejectsUnknownFieldsAndTrailingJSON(t *testing.T) {''',
)

replace_once(
    "CHANGELOG.md",
    '''- Reduced ordinary Windows-media source verification from three complete ISO hashes to one authenticated pass when Linux can hold the selected ISO under a read lease; unsupported or already-writable sources retain the original conservative three-pass comparison.
''',
    '''- Reduced ordinary Windows-media source verification from three complete ISO hashes to one authenticated pass when Linux can hold the selected ISO under a read lease; unsupported or already-writable sources retain the original conservative three-pass comparison.
- Reduced persistent Linux source verification from three complete image hashes to one authenticated pass under the same identity-bound Linux read lease, while retaining manifest-bound copy verification and the conservative three-pass fallback.
''',
)

Path("internal/linuxmedia/source_lease_linux_test.go").write_text(r'''//go:build linux

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
''', encoding="utf-8")
