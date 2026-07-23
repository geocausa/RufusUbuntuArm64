#!/usr/bin/env python3
"""Apply the reviewed Windows ISO source-lease integration exactly once."""

from __future__ import annotations

import json
from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    target = Path(path)
    data = target.read_text(encoding="utf-8")
    count = data.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one replacement match, found {count}")
    target.write_text(data.replace(old, new), encoding="utf-8")


replace_once(
    "internal/windowsmedia/windowsmedia.go",
    '''\tstableISOPath := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), isoFile.Fd())

\thashPinnedISO := func(stage, message string) ([sha256.Size]byte, error) {
\t\tlastEmit := time.Time{}
\t\tdigest, hashErr := sourcefile.SHA256Open(ctx, isoFile, func(done, total uint64) {
\t\t\tnow := time.Now()
\t\t\tif done == total || now.Sub(lastEmit) >= 200*time.Millisecond {
\t\t\t\tlastEmit = now
\t\t\t\tsend(emit, Event{Stage: stage, Message: message, Done: done, Total: total})
\t\t\t}
\t\t})
\t\tif hashErr != nil {
\t\t\treturn digest, hashErr
\t\t}
\t\tif err := sourcefile.VerifyPinned(isoFile, opts.ExpectedSource); err != nil {
\t\t\treturn digest, err
\t\t}
\t\treturn digest, nil
\t}

\t// Bind the exact ISO bytes before mounting or preparing WIM data. Later
\t// hashes must match this snapshot before destructive work and again after
\t// copying, preventing same-size edits with restored timestamps from creating
\t// mixed Windows media.
\tsourceDigest, err := hashPinnedISO("hash_source", "Hashing the selected Windows ISO…")
\tif err != nil {
\t\treturn fmt.Errorf("hash selected Windows ISO: %w", err)
\t}
''',
    '''\tstableISOPath := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), isoFile.Fd())
\ttargetChanged := false

\tsourceLease, leaseErr := sourcefile.AcquireReadLease(ctx, isoFile, opts.ExpectedSource)
\tswitch {
\tcase leaseErr == nil:
\t\tctx = sourceLease.Context()
\t\tsend(emit, Event{Stage: "source_hold", Message: "Holding the selected Windows ISO read-only with a Linux kernel lease; one complete SHA-256 pass will authenticate the held bytes."})
\t\tdefer func() {
\t\t\theldErr := sourceLease.Check()
\t\t\tif errors.Is(heldErr, sourcefile.ErrReadLeaseBroken) {
\t\t\t\tmessage := "the selected Windows ISO was opened for writing while media preparation was in progress; nothing was erased"
\t\t\t\tif targetChanged {
\t\t\t\t\tmessage = "the selected Windows ISO was opened for writing while USB creation was in progress; the USB is incomplete and must be recreated"
\t\t\t\t}
\t\t\t\theldErr = fmt.Errorf("%s: %w", message, heldErr)
\t\t\t}
\t\t\treturnErr = errors.Join(returnErr, heldErr, sourceLease.Close())
\t\t}()
\tcase errors.Is(leaseErr, sourcefile.ErrReadLeaseUnavailable), errors.Is(leaseErr, sourcefile.ErrReadLeaseConflict):
\t\tsourceLease = nil
\t\tsend(emit, Event{Stage: "source_hold", Message: fmt.Sprintf("Kernel source hold unavailable (%v); using conservative three-pass SHA-256 source verification.", leaseErr)})
\tdefault:
\t\treturn fmt.Errorf("hold selected Windows ISO stable: %w", leaseErr)
\t}

\thashPinnedISO := func(stage, message string) ([sha256.Size]byte, error) {
\t\tlastEmit := time.Time{}
\t\tdigest, hashErr := sourcefile.SHA256Open(ctx, isoFile, func(done, total uint64) {
\t\t\tnow := time.Now()
\t\t\tif done == total || now.Sub(lastEmit) >= 200*time.Millisecond {
\t\t\t\tlastEmit = now
\t\t\t\tsend(emit, Event{Stage: stage, Message: message, Done: done, Total: total})
\t\t\t}
\t\t})
\t\tif hashErr != nil {
\t\t\treturn digest, hashErr
\t\t}
\t\tif err := sourcefile.VerifyPinned(isoFile, opts.ExpectedSource); err != nil {
\t\t\treturn digest, err
\t\t}
\t\treturn digest, nil
\t}

\t// Authenticate the exact ISO bytes once. A held Linux read lease excludes
\t// conflicting writers for the rest of the operation. Filesystems that cannot
\t// provide that hold retain the existing three-pass digest comparison.
\tinitialHashMessage := "Hashing the selected Windows ISO once under the kernel source hold…"
\tif sourceLease == nil {
\t\tinitialHashMessage = "Hashing the selected Windows ISO (conservative pass 1 of 3)…"
\t}
\tsourceDigest, err := hashPinnedISO("hash_source", initialHashMessage)
\tif err != nil {
\t\treturn fmt.Errorf("hash selected Windows ISO: %w", err)
\t}
''',
)

replace_once(
    "internal/windowsmedia/windowsmedia.go",
    '''\tpreDestructiveDigest, err := hashPinnedISO("verify_source", "Rechecking the Windows ISO before erasing the USB…")
\tif err != nil {
\t\treturn fmt.Errorf("recheck selected Windows ISO: %w", err)
\t}
\tif !bytes.Equal(sourceDigest[:], preDestructiveDigest[:]) {
\t\treturn errors.New("the selected Windows ISO changed while it was being prepared; nothing was erased")
\t}
\tsend(emit, Event{Stage: "inspect", Message: fmt.Sprintf("Windows %s installation media detected; %s/%s selected; approximately %s will be written.", plan.Architecture, strings.ToUpper(targetSystem), strings.ToUpper(filesystem), humanBytes(plan.CopyBytes))})

\tcheckTarget := func() error {
\t\tif err := sourcefile.VerifyPinned(isoFile, opts.ExpectedSource); err != nil {
\t\t\treturn err
\t\t}
\t\treturn safety.VerifyOpenDevice(lock, opts.ExpectedDeviceID, opts.TargetSize)
\t}
''',
    '''\tif sourceLease != nil {
\t\tif err := sourceLease.Check(); err != nil {
\t\t\treturn fmt.Errorf("confirm held Windows ISO before erasing the USB: %w", err)
\t\t}
\t} else {
\t\tpreDestructiveDigest, err := hashPinnedISO("verify_source", "Rechecking the Windows ISO before erasing the USB (conservative pass 2 of 3)…")
\t\tif err != nil {
\t\t\treturn fmt.Errorf("recheck selected Windows ISO: %w", err)
\t\t}
\t\tif !bytes.Equal(sourceDigest[:], preDestructiveDigest[:]) {
\t\t\treturn errors.New("the selected Windows ISO changed while it was being prepared; nothing was erased")
\t\t}
\t}
\tsend(emit, Event{Stage: "inspect", Message: fmt.Sprintf("Windows %s installation media detected; %s/%s selected; approximately %s will be written.", plan.Architecture, strings.ToUpper(targetSystem), strings.ToUpper(filesystem), humanBytes(plan.CopyBytes))})

\tcheckTarget := func() error {
\t\tif sourceLease != nil {
\t\t\tif err := sourceLease.Check(); err != nil {
\t\t\t\treturn err
\t\t\t}
\t\t}
\t\tif err := sourcefile.VerifyPinned(isoFile, opts.ExpectedSource); err != nil {
\t\t\treturn err
\t\t}
\t\treturn safety.VerifyOpenDevice(lock, opts.ExpectedDeviceID, opts.TargetSize)
\t}
''',
)

replace_once(
    "internal/windowsmedia/windowsmedia.go",
    '''\tsend(emit, Event{Stage: "partition", Message: fmt.Sprintf("Creating a %s partition table…", strings.ToUpper(scheme))})
\tif err := runOnTarget("wipefs", "--all", "--force", "--", devicePath); err != nil {
''',
    '''\ttargetChanged = true
\tsend(emit, Event{Stage: "partition", Message: fmt.Sprintf("Creating a %s partition table…", strings.ToUpper(scheme))})
\tif err := runOnTarget("wipefs", "--all", "--force", "--", devicePath); err != nil {
''',
)

replace_once(
    "internal/windowsmedia/windowsmedia.go",
    '''\tpostCopyDigest, err := hashPinnedISO("verify_source", "Checking that the source ISO stayed unchanged…")
\tif err != nil {
\t\treturn fmt.Errorf("recheck Windows ISO after copying: %w", err)
\t}
\tif !bytes.Equal(sourceDigest[:], postCopyDigest[:]) {
\t\treturn errors.New("the selected Windows ISO changed while files were being copied; the USB is incomplete and must be recreated")
\t}
''',
    '''\tif sourceLease != nil {
\t\tif err := sourceLease.Check(); err != nil {
\t\t\treturn fmt.Errorf("confirm held Windows ISO after copying: %w", err)
\t\t}
\t} else {
\t\tpostCopyDigest, err := hashPinnedISO("verify_source", "Checking that the source ISO stayed unchanged (conservative pass 3 of 3)…")
\t\tif err != nil {
\t\t\treturn fmt.Errorf("recheck Windows ISO after copying: %w", err)
\t\t}
\t\tif !bytes.Equal(sourceDigest[:], postCopyDigest[:]) {
\t\t\treturn errors.New("the selected Windows ISO changed while files were being copied; the USB is incomplete and must be recreated")
\t\t}
\t}
''',
)

Path("internal/windowsmedia/source_lease_linux_test.go").write_text(
    '''//go:build linux

package windowsmedia

import (
\t"context"
\t"errors"
\t"os"
\t"path/filepath"
\t"strings"
\t"sync"
\t"syscall"
\t"testing"
\t"time"

\t"github.com/geocausa/RufusArm64/internal/sourcefile"
)

type windowsSourceLeaseFixture struct {
\tiso       string
\ttarget    string
\tlogPath   string
\tpartition string
}

func newWindowsSourceLeaseFixture(t *testing.T, largeCopy bool) windowsSourceLeaseFixture {
\tt.Helper()
\tfixture := t.TempDir()
\twriteTestFile(t, filepath.Join(fixture, "sources", "boot.wim"), []byte("boot"))
\twriteTestFile(t, filepath.Join(fixture, "sources", "install.wim"), []byte("install"))
\twriteTestFile(t, filepath.Join(fixture, "efi", "boot", "bootaa64.efi"), []byte("efi"))
\tsetup := []byte("setup")
\tif largeCopy {
\t\tsetup = make([]byte, 8*1024*1024+123)
\t}
\twriteTestFile(t, filepath.Join(fixture, "setup.exe"), setup)

\tfakeBin := t.TempDir()
\tlogPath := filepath.Join(t.TempDir(), "commands.log")
\tpartition := filepath.Join(t.TempDir(), "fake-partition")
\twriteTestFile(t, partition, make([]byte, 1024))
\tinstallFakeTools(t, fakeBin)
\tt.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
\tt.Setenv("RUFUS_TEST_ISO", fixture)
\tt.Setenv("RUFUS_TEST_LOG", logPath)
\tt.Setenv("RUFUS_TEST_PARTITION", partition)

\tiso := fakeISOFile(t)
\ttarget := filepath.Join(t.TempDir(), "fake-device")
\twriteTestFile(t, target, make([]byte, 1024))
\treturn windowsSourceLeaseFixture{iso: iso, target: target, logPath: logPath, partition: partition}
}

func TestCreateUsesOneHashUnderKernelSourceHold(t *testing.T) {
\tfixture := newWindowsSourceLeaseFixture(t, false)
\tvar events []Event
\terr := Create(context.Background(), fixture.iso, fixture.target, Options{
\t\tTargetSize:   8 * 1024 * 1024 * 1024,
\t\tRequireARM64: true,
\t\tVerify:       true,
\t}, func(event Event) { events = append(events, event) })
\tif err != nil {
\t\tt.Fatal(err)
\t}
\tif got := completedWindowsISOHashPasses(events); got != 1 {
\t\tt.Fatalf("complete ISO hash passes = %d, events=%#v", got, events)
\t}
\tif !eventMessagesContain(events, "Linux kernel lease") {
\t\tt.Fatalf("kernel source-hold message missing: %#v", events)
\t}
}

func TestCreateRetainsThreeHashFallbackWithExistingWriter(t *testing.T) {
\tfixture := newWindowsSourceLeaseFixture(t, false)
\twriter, err := os.OpenFile(fixture.iso, os.O_RDWR, 0)
\tif err != nil {
\t\tt.Fatal(err)
\t}
\tdefer writer.Close()

\tvar events []Event
\terr = Create(context.Background(), fixture.iso, fixture.target, Options{
\t\tTargetSize:   8 * 1024 * 1024 * 1024,
\t\tRequireARM64: true,
\t}, func(event Event) { events = append(events, event) })
\tif err != nil {
\t\tt.Fatal(err)
\t}
\tif got := completedWindowsISOHashPasses(events); got != 3 {
\t\tt.Fatalf("fallback complete ISO hash passes = %d, events=%#v", got, events)
\t}
\tif !eventMessagesContain(events, "conservative three-pass") {
\t\tt.Fatalf("fallback source-verification message missing: %#v", events)
\t}
}

func TestCreateLeaseBreakBeforeErasureLeavesTargetUntouched(t *testing.T) {
\tfixture := newWindowsSourceLeaseFixture(t, false)
\tvar once sync.Once
\tvar triggerErr error
\terr := Create(context.Background(), fixture.iso, fixture.target, Options{
\t\tTargetSize:   8 * 1024 * 1024 * 1024,
\t\tRequireARM64: true,
\t}, func(event Event) {
\t\tif event.Stage == "hash_source" && event.Total > 0 && event.Done == event.Total {
\t\t\tonce.Do(func() {
\t\t\t\twriter, openErr := os.OpenFile(fixture.iso, os.O_WRONLY|syscall.O_NONBLOCK, 0)
\t\t\t\tif writer != nil {
\t\t\t\t\t_ = writer.Close()
\t\t\t\t}
\t\t\t\ttriggerErr = openErr
\t\t\t})
\t\t}
\t})
\tif !errors.Is(triggerErr, syscall.EAGAIN) {
\t\tt.Fatalf("conflicting writer trigger error = %v", triggerErr)
\t}
\tif !errors.Is(err, sourcefile.ErrReadLeaseBroken) || !strings.Contains(err.Error(), "nothing was erased") {
\t\tt.Fatalf("pre-erasure lease-break error = %v", err)
\t}
\tif strings.Contains(readOptionalLog(t, fixture.logPath), "wipefs") {
\t\tt.Fatalf("target was touched after pre-erasure source break")
\t}
\twriter, openErr := os.OpenFile(fixture.iso, os.O_WRONLY|syscall.O_NONBLOCK, 0)
\tif openErr != nil {
\t\tt.Fatalf("writer remained blocked after cleanup: %v", openErr)
\t}
\t_ = writer.Close()
}

func TestCreateLeaseBreakDuringCopyReportsIncompleteAndReleasesWriter(t *testing.T) {
\tfixture := newWindowsSourceLeaseFixture(t, true)
\tvar once sync.Once
\tvar triggerErr error
\twriterDone := make(chan error, 1)
\terr := Create(context.Background(), fixture.iso, fixture.target, Options{
\t\tTargetSize:   8 * 1024 * 1024 * 1024,
\t\tRequireARM64: true,
\t}, func(event Event) {
\t\tif event.Stage != "copy" || event.Done == 0 {
\t\t\treturn
\t\t}
\t\tonce.Do(func() {
\t\t\tprobe, openErr := os.OpenFile(fixture.iso, os.O_WRONLY|syscall.O_NONBLOCK, 0)
\t\t\tif probe != nil {
\t\t\t\t_ = probe.Close()
\t\t\t}
\t\t\ttriggerErr = openErr
\t\t\tgo func() {
\t\t\t\twriter, writerErr := os.OpenFile(fixture.iso, os.O_WRONLY, 0)
\t\t\t\tif writer != nil {
\t\t\t\t\t_ = writer.Close()
\t\t\t\t}
\t\t\t\twriterDone <- writerErr
\t\t\t}()
\t\t})
\t})
\tif !errors.Is(triggerErr, syscall.EAGAIN) {
\t\tt.Fatalf("conflicting writer trigger error = %v", triggerErr)
\t}
\tif !errors.Is(err, sourcefile.ErrReadLeaseBroken) || !strings.Contains(err.Error(), "USB is incomplete") {
\t\tt.Fatalf("post-erasure lease-break error = %v", err)
\t}
\tif !strings.Contains(readOptionalLog(t, fixture.logPath), "wipefs") {
\t\tt.Fatalf("copy-break test never reached destructive work")
\t}
\tselect {
\tcase writerErr := <-writerDone:
\t\tif writerErr != nil {
\t\t\tt.Fatalf("blocked writer after cleanup = %v", writerErr)
\t\t}
\tcase <-time.After(3 * time.Second):
\t\tt.Fatal("blocked writer was not released during operation cleanup")
\t}
}

func completedWindowsISOHashPasses(events []Event) int {
\tcount := 0
\tfor _, event := range events {
\t\tif (event.Stage == "hash_source" || event.Stage == "verify_source") && event.Total > 0 && event.Done == event.Total {
\t\t\tcount++
\t\t}
\t}
\treturn count
}

func eventMessagesContain(events []Event, text string) bool {
\tfor _, event := range events {
\t\tif strings.Contains(event.Message, text) {
\t\t\treturn true
\t\t}
\t}
\treturn false
}

func readOptionalLog(t *testing.T, path string) string {
\tt.Helper()
\tdata, err := os.ReadFile(path)
\tif os.IsNotExist(err) {
\t\treturn ""
\t}
\tif err != nil {
\t\tt.Fatal(err)
\t}
\treturn string(data)
}
''',
    encoding="utf-8",
)

contract_path = Path("docs/operation-cost-contract.json")
contract = json.loads(contract_path.read_text(encoding="utf-8"))
windows = next(operation for operation in contract["operations"] if operation["id"] == "windows_install")
windows["status"] = "conformant"
windows["intentional_linux_divergence"] = (
    "RufusArm64 authenticates one complete ISO hash while a Linux read lease excludes source mutation; "
    "unsupported or contended sources retain two conditional fallback hashes and the original three-pass comparison."
)
windows["phases"] = [
    {
        "name": "authenticate_held_iso",
        "direction": "source_read",
        "scaling": "source_size",
        "multiplier": 1,
        "enabled_by_default": True,
    },
    {
        "name": "conservative_fallback_hashes",
        "direction": "source_read",
        "scaling": "source_size",
        "multiplier": 2,
        "enabled_by_default": False,
    },
    {
        "name": "copy_setup_files",
        "direction": "source_read",
        "scaling": "copied_payload",
        "multiplier": 1,
        "enabled_by_default": True,
    },
    {
        "name": "write_filesystem_and_setup_files",
        "direction": "target_write",
        "scaling": "copied_payload",
        "multiplier": 1,
        "enabled_by_default": True,
    },
    {
        "name": "verify_copied_files",
        "direction": "target_read",
        "scaling": "copied_payload",
        "multiplier": 1,
        "enabled_by_default": False,
    },
]
contract_path.write_text(json.dumps(contract, indent=2) + "\n", encoding="utf-8")

replace_once(
    "internal/operationcost/contract.go",
    '''\tif err := requirePhase(operations["windows_install"], "target_write", "copied_payload", true); err != nil {
\t\treturn err
\t}
''',
    '''\tif err := requireExactPhase(operations["windows_install"], "authenticate_held_iso", "source_read", "source_size", 1, true); err != nil {
\t\treturn err
\t}
\tif err := requireExactPhase(operations["windows_install"], "conservative_fallback_hashes", "source_read", "source_size", 2, false); err != nil {
\t\treturn err
\t}
\tif err := requirePhase(operations["windows_install"], "target_write", "copied_payload", true); err != nil {
\t\treturn err
\t}
''',
)

replace_once(
    "internal/operationcost/contract.go",
    '''func requirePhase(operation Operation, direction, scaling string, enabled bool) error {
''',
    '''func requireExactPhase(operation Operation, name, direction, scaling string, multiplier int, enabled bool) error {
\tfor _, phase := range operation.Phases {
\t\tif phase.Name == name && phase.Direction == direction && phase.Scaling == scaling && phase.Multiplier == multiplier && phase.EnabledByDefault == enabled {
\t\t\treturn nil
\t\t}
\t}
\treturn fmt.Errorf("operation %s must contain phase %s as %s/%s multiplier=%d enabled_by_default=%t", operation.ID, name, direction, scaling, multiplier, enabled)
}

func requirePhase(operation Operation, direction, scaling string, enabled bool) error {
''',
)

replace_once(
    "internal/operationcost/contract_test.go",
    '''func TestDecodeRejectsUnknownFieldsAndTrailingJSON(t *testing.T) {
''',
    '''func TestValidateRequiresOneDefaultWindowsISOHash(t *testing.T) {
\tcontract := loadRepositoryContract(t)
\toperation := findOperationIndex(t, contract, "windows_install")
\tcontract.Operations[operation].Phases[0].Multiplier = 3
\tif err := Validate(contract); err == nil || !strings.Contains(err.Error(), "authenticate_held_iso") {
\t\tt.Fatalf("Windows default source-hash boundary error = %v", err)
\t}
}

func TestDecodeRejectsUnknownFieldsAndTrailingJSON(t *testing.T) {
''',
)

replace_once(
    "docs/upstream-operation-parity.md",
    '''| Windows installation media | Copied setup payload, but currently three complete ISO hashes | Optional copied-file verification | Audit in #243 |
''',
    '''| Windows installation media | Copied setup payload plus one complete ISO hash under a kernel read lease; two extra hashes only on conservative fallback | Optional copied-file verification | Conformant software path after #243 |
''',
)

replace_once(
    "CHANGELOG.md",
    '''- Strengthened Windows setup analysis with bounded multi-edition metadata and WIM, ESD, or validated split-SWM payload reporting, while rejecting conflicting edition classes, payload families, part sequences, and inconsistent graphical reports.
''',
    '''- Strengthened Windows setup analysis with bounded multi-edition metadata and WIM, ESD, or validated split-SWM payload reporting, while rejecting conflicting edition classes, payload families, part sequences, and inconsistent graphical reports.
- Reduced ordinary Windows-media source verification from three complete ISO hashes to one authenticated pass when Linux can hold the selected ISO under a read lease; unsupported or already-writable sources retain the original conservative three-pass comparison.
''',
)

print("Windows source-lease integration applied")
