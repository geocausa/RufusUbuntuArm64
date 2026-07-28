#!/usr/bin/env python3
"""Apply the final #376 software interruption tranche once."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, text: str) -> None:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def replace_once(path: str, old: str, new: str, label: str) -> None:
    text = read(path)
    if text.count(old) != 1:
        raise SystemExit(f"{label} changed: found {text.count(old)}")
    write(path, text.replace(old, new, 1))


def run(*args: str) -> None:
    subprocess.run(args, cwd=ROOT, check=True)


# Raw imaging: inject only the package-private fsync operation and qualify
# cancellation after mutation plus final-sync failure.
imaging = "internal/imaging/imaging.go"
replace_once(
    imaging,
    "\tbeforeMutation          func()\n\tafterWriteChunk         func(uint64)\n",
    "\tbeforeMutation          func()\n\tafterWriteChunk         func(uint64)\n\tsyncTarget              func(*os.File) error\n",
    "imaging test seam fields",
)
replace_once(
    imaging,
    "\tif opts.BufferSize <= 0 {\n\t\topts.BufferSize = DefaultBufferSize\n\t}\n",
    "\tif opts.BufferSize <= 0 {\n\t\topts.BufferSize = DefaultBufferSize\n\t}\n\tsyncTarget := opts.syncTarget\n\tif syncTarget == nil {\n\t\tsyncTarget = func(target *os.File) error { return target.Sync() }\n\t}\n",
    "imaging sync seam initialization",
)
text = read(imaging)
if text.count("dst.Sync()") != 4:
    raise SystemExit(f"imaging sync call count changed: {text.count('dst.Sync()')}")
write(imaging, text.replace("dst.Sync()", "syncTarget(dst)"))
write(
    "internal/imaging/interruption_test.go",
    r'''package imaging

import (
    "bytes"
    "context"
    "errors"
    "os"
    "path/filepath"
    "strings"
    "testing"
)

func TestWriteImageInterruptionQualification(t *testing.T) {
    makeFixture := func(t *testing.T) (*os.File, string, []byte) {
        t.Helper()
        directory := t.TempDir()
        sourcePath := filepath.Join(directory, "source.img")
        targetPath := filepath.Join(directory, "target.img")
        source := bytes.Repeat([]byte("RUFUS-INTERRUPTION-"), 1024)
        target := bytes.Repeat([]byte{0x5a}, len(source))
        if err := os.WriteFile(sourcePath, source, 0o600); err != nil {
            t.Fatal(err)
        }
        if err := os.WriteFile(targetPath, target, 0o600); err != nil {
            t.Fatal(err)
        }
        sourceFile, err := os.Open(sourcePath)
        if err != nil {
            t.Fatal(err)
        }
        t.Cleanup(func() { _ = sourceFile.Close() })
        return sourceFile, targetPath, target
    }

    t.Run("cancellation after first chunk", func(t *testing.T) {
        source, targetPath, original := makeFixture(t)
        ctx, cancel := context.WithCancel(context.Background())
        calls := 0
        result, err := WriteOpenImageWithResult(ctx, source, targetPath, WriteOptions{
            BufferSize: 1024,
            TargetSize: uint64(len(original)),
            afterWriteChunk: func(uint64) {
                calls++
                if calls == 1 {
                    cancel()
                }
            },
        })
        if !errors.Is(err, context.Canceled) {
            t.Fatalf("error=%v, want context cancellation", err)
        }
        if result.BytesWritten == 0 || result.BytesWritten >= uint64(len(original)) || result.SHA256 != "" {
            t.Fatalf("unsafe cancellation result: %+v", result)
        }
        target, readErr := os.ReadFile(targetPath)
        if readErr != nil {
            t.Fatal(readErr)
        }
        if bytes.Equal(target, original) {
            t.Fatal("post-write cancellation left no inspectable target mutation")
        }
    })

    t.Run("final synchronization failure", func(t *testing.T) {
        source, targetPath, original := makeFixture(t)
        syncFailure := errors.New("injected final sync failure")
        result, err := WriteOpenImageWithResult(context.Background(), source, targetPath, WriteOptions{
            BufferSize: 1024,
            TargetSize: uint64(len(original)),
            syncTarget: func(*os.File) error { return syncFailure },
        })
        if !errors.Is(err, syncFailure) || !strings.Contains(err.Error(), "sync target") {
            t.Fatalf("error=%v, want injected target sync failure", err)
        }
        if result.BytesWritten != uint64(len(original)) || result.SHA256 != "" {
            t.Fatalf("sync failure fabricated successful evidence: %+v", result)
        }
        target, readErr := os.ReadFile(targetPath)
        if readErr != nil {
            t.Fatal(readErr)
        }
        if bytes.Equal(target, original) {
            t.Fatal("sync failure test did not reach target mutation")
        }
    })
}
''',
)

# Windows media: package-private hooks after each durable destructive boundary.
windows = "internal/windowsmedia/windowsmedia.go"
replace_once(
    windows,
    "\tBeforeDestructive func(source *os.File) error\n}\n",
    "\tBeforeDestructive func(source *os.File) error\n\n\tfaults *mutationFaults\n}\n\ntype mutationFaults struct {\n\tafterPartition func() error\n\tafterFormat    func() error\n\tafterCopy      func() error\n\tafterSync      func() error\n}\n\nfunc runMutationFault(stage string, fault func() error) error {\n\tif fault == nil {\n\t\treturn nil\n\t}\n\tif err := fault(); err != nil {\n\t\treturn fmt.Errorf(\"interrupted after %s: %w\", stage, err)\n\t}\n\treturn nil\n}\n",
    "Windows mutation fault type",
)
replace_once(
    windows,
    "\tif layout.Boot != nil {\n\t\tif err := writeUEFINTFSPartitionImage(lock, uefiNTFSImage, *layout.Boot); err != nil {\n\t\t\treturn err\n\t\t}\n\t}\n\tif err := checkTarget(); err != nil {\n",
    "\tif layout.Boot != nil {\n\t\tif err := writeUEFINTFSPartitionImage(lock, uefiNTFSImage, *layout.Boot); err != nil {\n\t\t\treturn err\n\t\t}\n\t}\n\tif opts.faults != nil {\n\t\tif err := runMutationFault(\"partition-table publication\", opts.faults.afterPartition); err != nil {\n\t\t\treturn err\n\t\t}\n\t}\n\tif err := checkTarget(); err != nil {\n",
    "Windows partition fault boundary",
)
replace_once(
    windows,
    "\tif targetSystem == \"bios\" {\n\t\tif err := installLegacyBIOSBoot(lock, partition, filesystem, layout.Data, sectorSize); err != nil {\n\t\t\treturn fmt.Errorf(\"install legacy BIOS boot code: %w\", err)\n\t\t}\n\t\tsend(emit, Event{Stage: \"boot\", Message: \"Installed Windows legacy BIOS/CSM MBR and partition boot code.\"})\n\t}\n\tif err := unmountDeviceMounts(ctx, partition); err != nil {\n",
    "\tif targetSystem == \"bios\" {\n\t\tif err := installLegacyBIOSBoot(lock, partition, filesystem, layout.Data, sectorSize); err != nil {\n\t\t\treturn fmt.Errorf(\"install legacy BIOS boot code: %w\", err)\n\t\t}\n\t\tsend(emit, Event{Stage: \"boot\", Message: \"Installed Windows legacy BIOS/CSM MBR and partition boot code.\"})\n\t}\n\tif opts.faults != nil {\n\t\tif err := runMutationFault(\"filesystem creation\", opts.faults.afterFormat); err != nil {\n\t\t\treturn err\n\t\t}\n\t}\n\tif err := unmountDeviceMounts(ctx, partition); err != nil {\n",
    "Windows format fault boundary",
)
replace_once(
    windows,
    "\t}); err != nil {\n\t\treturn err\n\t}\n\n\tsend(emit, Event{Stage: \"sync\", Message: \"Flushing pending USB writes safely…\"})\n",
    "\t}); err != nil {\n\t\treturn err\n\t}\n\tif opts.faults != nil {\n\t\tif err := runMutationFault(\"payload copy\", opts.faults.afterCopy); err != nil {\n\t\t\treturn err\n\t\t}\n\t}\n\n\tsend(emit, Event{Stage: \"sync\", Message: \"Flushing pending USB writes safely…\"})\n",
    "Windows copy fault boundary",
)
replace_once(
    windows,
    "\tif err := run(ctx, emit, \"blockdev\", \"--flushbufs\", partition); err != nil {\n\t\treturn fmt.Errorf(\"flush USB buffers: %w\", err)\n\t}\n\n\tif opts.Verify {\n",
    "\tif err := run(ctx, emit, \"blockdev\", \"--flushbufs\", partition); err != nil {\n\t\treturn fmt.Errorf(\"flush USB buffers: %w\", err)\n\t}\n\tif opts.faults != nil {\n\t\tif err := runMutationFault(\"final synchronization\", opts.faults.afterSync); err != nil {\n\t\t\treturn err\n\t\t}\n\t}\n\n\tif opts.Verify {\n",
    "Windows sync fault boundary",
)
write(
    "internal/windowsmedia/interruption_test.go",
    r'''//go:build linux

package windowsmedia

import (
    "bytes"
    "context"
    "errors"
    "io"
    "os"
    "path/filepath"
    "testing"
)

func TestCreateInterruptionAfterEachDestructiveBoundary(t *testing.T) {
    makeFixture := func(t *testing.T) (string, string, []byte, Options) {
        t.Helper()
        fixture := t.TempDir()
        writeTestFile(t, filepath.Join(fixture, "sources", "boot.wim"), []byte("boot"))
        writeTestFile(t, filepath.Join(fixture, "sources", "install.wim"), []byte("install"))
        writeTestFile(t, filepath.Join(fixture, "efi", "boot", "bootaa64.efi"), []byte("efi"))
        writeTestFile(t, filepath.Join(fixture, "setup.exe"), []byte("setup"))
        fakeBin := t.TempDir()
        logPath := filepath.Join(t.TempDir(), "commands.log")
        partition := filepath.Join(t.TempDir(), "fake-partition")
        writeTestFile(t, partition, []byte("partition"))
        installFakeTools(t, fakeBin)
        t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
        t.Setenv("RUFUS_TEST_ISO", fixture)
        t.Setenv("RUFUS_TEST_LOG", logPath)
        t.Setenv("RUFUS_TEST_PARTITION", partition)
        iso := fakeISOFile(t)
        target := filepath.Join(t.TempDir(), "fake-device")
        original := bytes.Repeat([]byte{0x5a}, 1024)
        writeTestFile(t, target, original)
        return iso, target, original, Options{
            TargetSize: 8 * 1024 * 1024 * 1024,
            RequireARM64: true,
            PartitionScheme: "gpt",
            TargetSystem: "uefi",
            Filesystem: "fat32",
        }
    }
    targetChanged := func(t *testing.T, path string, original []byte) bool {
        t.Helper()
        info, err := os.Stat(path)
        if err != nil {
            t.Fatal(err)
        }
        if info.Size() != int64(len(original)) {
            return true
        }
        file, err := os.Open(path)
        if err != nil {
            t.Fatal(err)
        }
        defer file.Close()
        prefix := make([]byte, len(original))
        _, err = io.ReadFull(file, prefix)
        if err != nil {
            t.Fatal(err)
        }
        return !bytes.Equal(prefix, original)
    }

    t.Run("pre-destructive refusal leaves target unchanged", func(t *testing.T) {
        iso, target, original, options := makeFixture(t)
        injected := errors.New("injected pre-destructive refusal")
        options.BeforeDestructive = func(*os.File) error { return injected }
        err := Create(context.Background(), iso, target, options, nil)
        if !errors.Is(err, injected) {
            t.Fatalf("error=%v, want injected pre-destructive refusal", err)
        }
        if targetChanged(t, target, original) {
            t.Fatal("pre-destructive refusal changed the target")
        }
    })

    tests := []struct {
        name string
        configure func(*mutationFaults, error)
    }{
        {"partition", func(faults *mutationFaults, err error) { faults.afterPartition = func() error { return err } }},
        {"format", func(faults *mutationFaults, err error) { faults.afterFormat = func() error { return err } }},
        {"copy", func(faults *mutationFaults, err error) { faults.afterCopy = func() error { return err } }},
        {"sync", func(faults *mutationFaults, err error) { faults.afterSync = func() error { return err } }},
    }
    for _, test := range tests {
        t.Run(test.name, func(t *testing.T) {
            iso, target, original, options := makeFixture(t)
            injected := errors.New("injected " + test.name + " interruption")
            faults := &mutationFaults{}
            test.configure(faults, injected)
            options.faults = faults
            var events []Event
            err := Create(context.Background(), iso, target, options, func(event Event) { events = append(events, event) })
            if !errors.Is(err, injected) {
                t.Fatalf("error=%v, want injected %s interruption", err, test.name)
            }
            if !targetChanged(t, target, original) {
                t.Fatalf("%s interruption did not reach target mutation", test.name)
            }
            for _, event := range events {
                if event.Stage == "complete" {
                    t.Fatalf("%s interruption emitted successful completion: %+v", test.name, event)
                }
            }
        })
    }
}
''',
)

# FreeDOS and non-bootable state machines already expose the correct package
# interfaces; add comprehensive exact regressions across all mutation phases.
write(
    "internal/freedos/interruption_qualification_test.go",
    r'''package freedos

import (
    "context"
    "errors"
    "io"
    "testing"
)

func TestExecuteDevicePlanInterruptionQualification(t *testing.T) {
    plan := testFreeDOSDevicePlan(t)
    tests := []struct {
        name string
        backend *memoryExecutionBackend
        changed bool
        phase ExecutionPhase
    }{
        {"before destructive", &memoryExecutionBackend{beforeErr: errors.New("identity changed")}, false, ExecutionPhasePrepare},
        {"short target write", &memoryExecutionBackend{writer: shortExecutorWriterAt{}}, true, ExecutionPhaseWrite},
        {"target flush", &memoryExecutionBackend{flushErr: errors.New("flush failed")}, true, ExecutionPhaseFlush},
        {"readback mismatch", &memoryExecutionBackend{tamperOnFlush: true}, true, ExecutionPhaseReadback},
        {"final identity", &memoryExecutionBackend{finishErr: errors.New("finish failed")}, true, ExecutionPhaseFinish},
        {"close", &memoryExecutionBackend{closeErr: errors.New("close failed")}, true, ExecutionPhaseComplete},
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
''',
)
write(
    "internal/nonbootable/interruption_qualification_test.go",
    r'''//go:build linux

package nonbootable

import (
    "context"
    "testing"
)

func TestExecuteInterruptionQualificationEveryMutationPhase(t *testing.T) {
    plan := executorPlan(t)
    tests := []struct {
        phase string
        changed bool
    }{
        {PhasePreflight, false},
        {PhaseErase, true},
        {PhasePartition, true},
        {PhaseFormat, true},
        {PhaseVerify, true},
        {PhaseComplete, true},
    }
    for _, test := range tests {
        t.Run(test.phase, func(t *testing.T) {
            backend := successfulBackend(plan)
            backend.failPhase = test.phase
            report, err := Execute(context.Background(), plan, backend, fixedClock())
            if err == nil {
                t.Fatal("injected formatter failure was reported as success")
            }
            if report.Status == StatusPassed || report.MediaChanged != test.changed || report.Reusable || report.Filesystem != nil {
                t.Fatalf("unsafe formatter interruption report: %+v", report)
            }
            if report.Failure == nil || report.Failure.Phase != test.phase || report.Failure.MediaChanged != test.changed {
                t.Fatalf("incorrect failure evidence: %+v", report.Failure)
            }
        })
    }
}
''',
)
write(
    "internal/nonbootable/interruption_loop_test.go",
    r'''//go:build linux

package nonbootable

import (
    "context"
    "errors"
    "os"
    "os/exec"
    "path/filepath"
    "strconv"
    "strings"
    "testing"
    "time"

    "github.com/geocausa/RufusArm64/internal/safety"
)

type cancelAfterPartitionBackend struct {
    *linuxBackend
    cancel context.CancelFunc
}

func (backend *cancelAfterPartitionBackend) Partition(ctx context.Context, plan Plan, table PartitionTable, script string) (string, error) {
    path, err := backend.linuxBackend.Partition(ctx, plan, table, script)
    if err == nil {
        backend.cancel()
    }
    return path, err
}

func TestExecuteDeviceInterruptionAfterPartitionOnRealLoop(t *testing.T) {
    if os.Getenv("RUFUS_REAL_BLOCK_TEST") != "1" {
        t.Skip("set RUFUS_REAL_BLOCK_TEST=1 to exercise real loop devices")
    }
    if os.Geteuid() != 0 {
        t.Skip("real formatter loop tests require root")
    }
    for _, tool := range []string{"losetup", "blockdev", "sfdisk", "wipefs", "blkid", "mkfs.vfat", "fsck.vfat"} {
        if _, err := exec.LookPath(tool); err != nil {
            t.Fatalf("required loop-test tool %q is unavailable: %v", tool, err)
        }
    }
    const capacity = 256 * 1024 * 1024
    backing := filepath.Join(t.TempDir(), "interrupted.img")
    file, err := os.OpenFile(backing, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
    if err != nil {
        t.Fatal(err)
    }
    if err := file.Truncate(capacity); err != nil {
        _ = file.Close()
        t.Fatal(err)
    }
    if err := file.Close(); err != nil {
        t.Fatal(err)
    }
    output, err := exec.Command("losetup", "--find", "--show", "--partscan", backing).CombinedOutput()
    if err != nil {
        t.Fatalf("attach loop device: %v: %s", err, strings.TrimSpace(string(output)))
    }
    loopPath := strings.TrimSpace(string(output))
    t.Cleanup(func() { _, _ = exec.Command("losetup", "--detach", loopPath).CombinedOutput() })
    waitForFormatterLoopLock(t, loopPath)
    deviceID, err := safety.KernelDeviceID(loopPath)
    if err != nil {
        t.Fatal(err)
    }
    sectorOutput, err := exec.Command("blockdev", "--getss", loopPath).CombinedOutput()
    if err != nil {
        t.Fatalf("read logical sector size: %v: %s", err, strings.TrimSpace(string(sectorOutput)))
    }
    sectorSize, err := strconv.ParseUint(strings.TrimSpace(string(sectorOutput)), 10, 64)
    if err != nil {
        t.Fatal(err)
    }
    plan, err := BuildPlan(Request{
        DevicePath: loopPath,
        ExpectedIdentity: strings.Repeat("b", 64),
        DeviceSizeBytes: capacity,
        LogicalSectorSize: sectorSize,
        Scheme: SchemeGPT,
        Filesystem: FilesystemFAT32,
        Label: "INTERRUPT",
    })
    if err != nil {
        t.Fatal(err)
    }
    ctx, cancel := context.WithCancel(context.Background())
    backend := &linuxBackend{options: DeviceOptions{
        ExpectedDeviceID: deviceID,
        ExpectedSize: capacity,
        PartitionTimeout: 30 * time.Second,
        BeforeDestructive: func(open *os.File) error {
            return safety.VerifyOpenDevice(open, deviceID, capacity)
        },
    }}
    wrapper := &cancelAfterPartitionBackend{linuxBackend: backend, cancel: cancel}
    report, runErr := Execute(ctx, plan, wrapper, time.Now)
    report, runErr = finishDeviceExecution(report, runErr, backend.Close(), time.Now)
    if !errors.Is(runErr, context.Canceled) {
        t.Fatalf("error=%v, want context cancellation; report=%+v", runErr, report)
    }
    if report.Status != StatusCancelled || !report.MediaChanged || report.Reusable || report.Filesystem != nil || report.Failure == nil || report.Failure.Phase != PhaseFormat {
        t.Fatalf("unsafe post-partition cancellation report: %+v", report)
    }
    if backend.partitionPath == "" {
        t.Fatal("real loop interruption did not publish a partition node")
    }
    filesystem, _ := exec.Command("blkid", "-o", "value", "-s", "TYPE", backend.partitionPath).CombinedOutput()
    if strings.TrimSpace(string(filesystem)) != "" {
        t.Fatalf("post-partition cancellation unexpectedly created a filesystem: %q", strings.TrimSpace(string(filesystem)))
    }
}
''',
)

# Replace the final residual with exact executable rows.
matrix_path = "docs/interruption-qualification.json"
matrix = json.loads(read(matrix_path))
old_gaps = matrix["residual_software_gaps"]
matrix["residual_software_gaps"] = [gap for gap in old_gaps if gap.get("id") != "gap-partition-filesystem-mutation"]
if len(matrix["residual_software_gaps"]) != len(old_gaps) - 1:
    raise SystemExit("partition/filesystem residual row changed")
rows = [
    {
        "id": "raw-imaging-mutation-interruption",
        "boundary": "partition-filesystem-mutation",
        "component": "raw and ISOHybrid target writing",
        "failure_mode": "cancellation follows the first target chunk or final target synchronization fails after all bytes are written",
        "phase": "post-mutation",
        "status": "automated",
        "test_file": "internal/imaging/interruption_test.go",
        "test_name": "TestWriteImageInterruptionQualification",
        "platforms": ["linux-amd64", "linux-arm64"],
        "invariant": "The write returns failure with a conservative byte count and no authenticated success digest; post-mutation target state remains inspectable and is never reported complete.",
    },
    {
        "id": "windows-media-mutation-interruption",
        "boundary": "partition-filesystem-mutation",
        "component": "Windows installation media creation",
        "failure_mode": "execution stops before mutation or immediately after partition publication, filesystem creation, payload copy, or final synchronization",
        "phase": "pre-and-post-mutation",
        "status": "automated",
        "test_file": "internal/windowsmedia/interruption_test.go",
        "test_name": "TestCreateInterruptionAfterEachDestructiveBoundary",
        "platforms": ["linux-amd64", "linux-arm64"],
        "invariant": "Pre-destructive refusal leaves the target unchanged; every later injected failure returns error after observable target mutation and never emits completion.",
    },
    {
        "id": "freedos-mutation-interruption",
        "boundary": "partition-filesystem-mutation",
        "component": "FreeDOS required-extent media creation",
        "failure_mode": "identity, target write, flush, readback, finish, or close fails",
        "phase": "pre-and-post-mutation",
        "status": "automated",
        "test_file": "internal/freedos/interruption_qualification_test.go",
        "test_name": "TestExecuteDevicePlanInterruptionQualification",
        "platforms": ["linux-amd64", "linux-arm64"],
        "invariant": "Every injected failure retains exact phase and changed-media evidence, never marks media reusable, and pre-destructive refusal claims no I/O.",
    },
    {
        "id": "nonbootable-mutation-interruption",
        "boundary": "partition-filesystem-mutation",
        "component": "data-only partitioning and filesystem creation",
        "failure_mode": "preflight, erase, partition, format, verification, or completion fails",
        "phase": "pre-and-post-mutation",
        "status": "automated",
        "test_file": "internal/nonbootable/interruption_qualification_test.go",
        "test_name": "TestExecuteInterruptionQualificationEveryMutationPhase",
        "platforms": ["linux-amd64", "linux-arm64"],
        "invariant": "Every phase failure produces a validated non-success report; only preflight is unchanged, and no failed path publishes reusable filesystem evidence.",
    },
    {
        "id": "nonbootable-real-loop-post-partition-cancel",
        "boundary": "partition-filesystem-mutation",
        "component": "Linux kernel loop-device partition publication",
        "failure_mode": "context cancellation occurs after the real partition table and node are published but before filesystem creation",
        "phase": "post-mutation",
        "status": "automated",
        "test_file": "internal/nonbootable/interruption_loop_test.go",
        "test_name": "TestExecuteDeviceInterruptionAfterPartitionOnRealLoop",
        "platforms": ["linux-amd64-privileged-loop", "linux-arm64-privileged-loop"],
        "invariant": "The real loop target is reported changed and cancelled, the partition node remains inspectable, and no filesystem or reusable success evidence is published.",
    },
]
existing = {entry["id"] for entry in matrix["entries"]}
if existing.intersection(row["id"] for row in rows):
    raise SystemExit("partition/filesystem interruption rows already exist")
physical_index = next((i for i, entry in enumerate(matrix["entries"]) if entry.get("status") == "physical-only"), len(matrix["entries"]))
matrix["entries"][physical_index:physical_index] = rows
write(matrix_path, json.dumps(matrix, indent=2, ensure_ascii=False) + "\n")

replace_once(
    "docs/interruption-crash-consistency.md",
    "- owned helper-process SIGTERM/SIGKILL escalation, bounded capture and line streaming, FFU evidence handling, and persistence worker reaping.\n",
    "- owned helper-process SIGTERM/SIGKILL escalation, bounded capture and line streaming, and workflow-specific evidence handling;\n- raw imaging, Windows media, FreeDOS, and data-only formatting interruption before and after every admitted destructive boundary, including a real loop-device post-partition cancellation.\n",
    "interruption documentation coverage list",
)
replace_once(
    "docs/interruption-crash-consistency.md",
    "The inventory deliberately keeps uncovered software cases visible. The helper-process boundary is now represented by shared runtime and exact source-contract tests; the remaining software residual is destructive partition/filesystem mutation qualification.",
    "The software interruption inventory has no residual gap: every admitted boundary is represented by executable regression coverage, while electrical power removal and firmware boot remain explicitly physical-only.",
    "interruption documentation closeout",
)
replace_once(
    "CHANGELOG.md",
    "- Migrated the remaining GTK acquisition, checksum, writer, formatter, qualification, backup, ISO, FreeDOS, and FFU workers to shared bounded one-shot or concurrent two-pipe contracts with strict UTF-8 evidence limits, closing the helper-process interruption residual.\n",
    "- Migrated the remaining GTK acquisition, checksum, writer, formatter, qualification, backup, ISO, FreeDOS, and FFU workers to shared bounded one-shot or concurrent two-pipe contracts with strict UTF-8 evidence limits, closing the helper-process interruption residual.\n- Qualified raw imaging, Windows media, FreeDOS, and data-only partition/filesystem interruption at each admitted destructive boundary, including real loop-device cancellation after partition publication, closing the final software interruption residual.\n",
    "partition interruption changelog",
)

run("git", "rm", "-f", "--ignore-unmatch", ".github/partition-interruption-once.py", ".github/workflows/partition-interruption-once.yml")
run("gofmt", "-w",
    "internal/imaging/imaging.go", "internal/imaging/interruption_test.go",
    "internal/windowsmedia/windowsmedia.go", "internal/windowsmedia/interruption_test.go",
    "internal/freedos/interruption_qualification_test.go",
    "internal/nonbootable/interruption_qualification_test.go", "internal/nonbootable/interruption_loop_test.go")
run("go", "test", "./internal/imaging", "./internal/windowsmedia", "./internal/freedos", "./internal/nonbootable", "./internal/qualification")
run("git", "add", "CHANGELOG.md", "docs/interruption-crash-consistency.md", "docs/interruption-qualification.json", "internal/imaging", "internal/windowsmedia", "internal/freedos", "internal/nonbootable")
run("git", "config", "user.name", "github-actions[bot]")
run("git", "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com")
run("git", "commit", "-m", "reliability: qualify partition and filesystem interruption")
run("git", "push", "--force", "origin", "HEAD:feature/partition-filesystem-interruption")
