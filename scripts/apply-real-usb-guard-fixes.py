#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: str, old: str, new: str) -> None:
    target = ROOT / path
    text = target.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one anchor, found {count}")
    target.write_text(text.replace(old, new, 1))


replace_once(
    "internal/safety/reopenable_linux.go",
    '''import (\n\t"os"\n\t"syscall"\n)''',
    '''import (\n\t"errors"\n\t"fmt"\n\t"os"\n\t"syscall"\n)''',
)
replace_once(
    "internal/safety/reopenable_linux.go",
    '''func OpenReopenableDevice(path string) (*os.File, error) {\n\treturn os.OpenFile(path, reopenableDeviceOpenFlags, 0)\n}\n''',
    '''func OpenReopenableDevice(path string) (*os.File, error) {\n\treturn os.OpenFile(path, reopenableDeviceOpenFlags, 0)\n}\n\n// WithTemporarilyReleasedFlock lets a trusted filesystem formatter reopen an\n// inherited block-device descriptor with its own exclusive policy. The caller\n// must retain the independently locked whole-disk descriptor for the complete\n// operation. The partition lock is restored before this function returns.\nfunc WithTemporarilyReleasedFlock(file *os.File, operation func() error) (returnErr error) {\n\tif file == nil {\n\t\treturn errors.New("device file is nil")\n\t}\n\tif operation == nil {\n\t\treturn errors.New("device operation is nil")\n\t}\n\tfd := int(file.Fd())\n\tif err := syscall.Flock(fd, syscall.LOCK_UN); err != nil {\n\t\treturn fmt.Errorf("release device lock for trusted formatter: %w", err)\n\t}\n\tdefer func() {\n\t\tif err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {\n\t\t\treturnErr = errors.Join(returnErr, fmt.Errorf("restore device lock after trusted formatter: %w", err))\n\t\t}\n\t}()\n\treturn operation()\n}\n''',
)

replace_once(
    "internal/safety/safety_linux.go",
    '''func RevalidateTarget(path, expectedIdentity string, allowFixed bool) (device.BlockDevice, uint64, error) {\n\tdev, err := device.Find(path)\n\tif err != nil {\n\t\treturn device.BlockDevice{}, 0, err\n\t}\n\tif err := ValidateExpectedIdentity(dev, expectedIdentity); err != nil {\n\t\treturn device.BlockDevice{}, 0, err\n\t}\n\tif err := ValidateTarget(path, dev, allowFixed); err != nil {\n\t\treturn device.BlockDevice{}, 0, err\n\t}\n\tkernelID, err := KernelDeviceID(path)\n\tif err != nil {\n\t\treturn device.BlockDevice{}, 0, err\n\t}\n\treturn dev, kernelID, nil\n}\n''',
    '''func RevalidateTarget(path, expectedIdentity string, allowFixed bool) (device.BlockDevice, uint64, error) {\n\tdev, err := device.Find(path)\n\tif err != nil {\n\t\treturn device.BlockDevice{}, 0, err\n\t}\n\tif err := ValidateExpectedIdentity(dev, expectedIdentity); err != nil {\n\t\treturn device.BlockDevice{}, 0, err\n\t}\n\tif err := ValidateTarget(path, dev, allowFixed); err != nil {\n\t\treturn device.BlockDevice{}, 0, err\n\t}\n\tkernelID, err := KernelDeviceID(path)\n\tif err != nil {\n\t\treturn device.BlockDevice{}, 0, err\n\t}\n\treturn dev, kernelID, nil\n}\n\n// RevalidateOpenBoundTarget is used only after the selected whole disk has been\n// opened and identity-bound. The pre-erase GUI snapshot is intentionally not\n// recomputed after RufusArm64 changes the disk layout. The live /dev path must\n// still resolve to the same kernel block device and pass the complete target\n// policy, while the writer independently verifies its held descriptor.\nfunc RevalidateOpenBoundTarget(path string, expectedKernelID uint64, allowFixed bool) (device.BlockDevice, uint64, error) {\n\tdev, err := device.Find(path)\n\tif err != nil {\n\t\treturn device.BlockDevice{}, 0, err\n\t}\n\tif err := ValidateTarget(path, dev, allowFixed); err != nil {\n\t\treturn device.BlockDevice{}, 0, err\n\t}\n\tkernelID, err := KernelDeviceID(path)\n\tif err != nil {\n\t\treturn device.BlockDevice{}, 0, err\n\t}\n\tif expectedKernelID != 0 && kernelID != expectedKernelID {\n\t\treturn device.BlockDevice{}, 0, errors.New("the selected kernel device changed after confirmation")\n\t}\n\treturn dev, kernelID, nil\n}\n''',
)

replace_once(
    "cmd/rufus-linux/main.go",
    '''\ttargetCheck := func(source *os.File, expectedIdentity string) error {\n\t\tfresh, currentID, err := safety.RevalidateTarget(resolved, expectedIdentity, *allowFixed)\n\t\tif err != nil {\n\t\t\treturn err\n\t\t}\n\t\tif currentID != kernelDeviceID {\n\t\t\treturn errors.New("the selected kernel device changed after confirmation")\n\t\t}\n\t\tif err := safety.EnsureOpenFileNotOnTarget(source, fresh); err != nil {\n\t\t\treturn err\n\t\t}\n\t\tif !*noUnmount {\n\t\t\tif err := safety.UnmountDescendants(fresh); err != nil {\n\t\t\t\treturn err\n\t\t\t}\n\t\t}\n\t\treturn safety.EnsureNoMountedDescendants(resolved)\n\t}\n\tstrictTargetCheck := func(source *os.File) error {\n\t\treturn targetCheck(source, selectedIdentity)\n\t}\n\tpostWriteTargetCheck := func(source *os.File) error {\n\t\treturn targetCheck(source, selectedIdentity)\n\t}\n''',
    '''\ttargetCheck := func(source *os.File, requireSelectionIdentity bool) error {\n\t\tvar fresh device.BlockDevice\n\t\tvar currentID uint64\n\t\tvar err error\n\t\tif requireSelectionIdentity {\n\t\t\tfresh, currentID, err = safety.RevalidateTarget(resolved, selectedIdentity, *allowFixed)\n\t\t} else {\n\t\t\tfresh, currentID, err = safety.RevalidateOpenBoundTarget(resolved, kernelDeviceID, *allowFixed)\n\t\t}\n\t\tif err != nil {\n\t\t\treturn err\n\t\t}\n\t\tif currentID != kernelDeviceID {\n\t\t\treturn errors.New("the selected kernel device changed after confirmation")\n\t\t}\n\t\tif err := safety.EnsureOpenFileNotOnTarget(source, fresh); err != nil {\n\t\t\treturn err\n\t\t}\n\t\tif !*noUnmount {\n\t\t\tif err := safety.UnmountDescendants(fresh); err != nil {\n\t\t\t\treturn err\n\t\t\t}\n\t\t}\n\t\treturn safety.EnsureNoMountedDescendants(resolved)\n\t}\n\tstrictTargetCheck := func(source *os.File) error {\n\t\treturn targetCheck(source, true)\n\t}\n\tpostWriteTargetCheck := func(source *os.File) error {\n\t\treturn targetCheck(source, false)\n\t}\n''',
)

replace_once(
    "internal/windowsmedia/windowsmedia.go",
    '''\tcheckTarget := func() error {\n\t\tif err := sourcefile.VerifyPinned(isoFile, opts.ExpectedSource); err != nil {\n\t\t\treturn err\n\t\t}\n\t\tif err := safety.VerifyOpenDevice(lock, opts.ExpectedDeviceID, opts.TargetSize); err != nil {\n\t\t\treturn err\n\t\t}\n\t\tif opts.BeforeDestructive != nil {\n\t\t\tif err := opts.BeforeDestructive(isoFile); err != nil {\n\t\t\t\treturn fmt.Errorf("target safety check: %w", err)\n\t\t\t}\n\t\t}\n\t\treturn nil\n\t}\n''',
    '''\tcheckTarget := func() error {\n\t\tif err := sourcefile.VerifyPinned(isoFile, opts.ExpectedSource); err != nil {\n\t\t\treturn err\n\t\t}\n\t\treturn safety.VerifyOpenDevice(lock, opts.ExpectedDeviceID, opts.TargetSize)\n\t}\n''',
)
replace_once(
    "internal/windowsmedia/windowsmedia.go",
    '''\tsend(emit, Event{Stage: "partition", Message: fmt.Sprintf("Creating a %s partition table…", strings.ToUpper(scheme))})\n\tif err := runOnTarget("wipefs", "--all", "--force", "--", devicePath); err != nil {\n''',
    '''\tif err := checkTarget(); err != nil {\n\t\treturn err\n\t}\n\tif opts.BeforeDestructive != nil {\n\t\tif err := opts.BeforeDestructive(isoFile); err != nil {\n\t\t\treturn fmt.Errorf("target safety check: %w", err)\n\t\t}\n\t}\n\tsend(emit, Event{Stage: "partition", Message: fmt.Sprintf("Creating a %s partition table…", strings.ToUpper(scheme))})\n\tif err := runOnTarget("wipefs", "--all", "--force", "--", devicePath); err != nil {\n''',
)

replace_once(
    "internal/linuxmedia/create.go",
    '''\tcheckTarget := func() error {\n\t\tif err := sourcefile.VerifyPinned(isoFile, opts.ExpectedSource); err != nil {\n\t\t\treturn err\n\t\t}\n\t\tif err := safety.VerifyOpenDevice(target, opts.ExpectedDeviceID, opts.TargetSize); err != nil {\n\t\t\treturn err\n\t\t}\n\t\tif opts.BeforeDestructive != nil {\n\t\t\tif err := opts.BeforeDestructive(isoFile); err != nil {\n\t\t\t\treturn fmt.Errorf("target safety check: %w", err)\n\t\t\t}\n\t\t}\n\t\treturn nil\n\t}\n\tif err := checkTarget(); err != nil {\n\t\treturn result, err\n\t}\n\n\tsendPersistent(emit, PersistentEvent{Stage: "partition", Message: "Creating a fresh GPT layout for writable Linux boot files and persistence…"})\n''',
    '''\tcheckTarget := func() error {\n\t\tif err := sourcefile.VerifyPinned(isoFile, opts.ExpectedSource); err != nil {\n\t\t\treturn err\n\t\t}\n\t\treturn safety.VerifyOpenDevice(target, opts.ExpectedDeviceID, opts.TargetSize)\n\t}\n\tif err := checkTarget(); err != nil {\n\t\treturn result, err\n\t}\n\tif opts.BeforeDestructive != nil {\n\t\tif err := opts.BeforeDestructive(isoFile); err != nil {\n\t\t\treturn result, fmt.Errorf("target safety check: %w", err)\n\t\t}\n\t}\n\n\tsendPersistent(emit, PersistentEvent{Stage: "partition", Message: "Creating a fresh GPT layout for writable Linux boot files and persistence…"})\n''',
)
replace_once(
    "internal/linuxmedia/create.go",
    '''\tif err := runPersistentFile(ctx, emit, bootFile, "mkfs.vfat", "-F", "32", "-s", strconv.FormatUint(clusterSectors, 10), "-n", label, bootFDPath); err != nil {\n''',
    '''\tif err := runPersistentFileUnlocked(ctx, emit, bootFile, "mkfs.vfat", "-F", "32", "-s", strconv.FormatUint(clusterSectors, 10), "-n", label, bootFDPath); err != nil {\n''',
)
replace_once(
    "internal/linuxmedia/create.go",
    '''func runPersistentFile(ctx context.Context, emit PersistentEventFunc, file *os.File, name string, args ...string) error {\n''',
    '''func runPersistentFileUnlocked(ctx context.Context, emit PersistentEventFunc, file *os.File, name string, args ...string) error {\n\treturn safety.WithTemporarilyReleasedFlock(file, func() error {\n\t\treturn runPersistentFile(ctx, emit, file, name, args...)\n\t})\n}\n\nfunc runPersistentFile(ctx context.Context, emit PersistentEventFunc, file *os.File, name string, args ...string) error {\n''',
)

replace_once(
    "internal/persistence/filesystem.go",
    '''\tif err := runPartitionCommand(ctx, partition, "mkfs.ext4", "-F", "-L", plan.FilesystemLabel, "-m", "0", "-E", "lazy_itable_init=0,lazy_journal_init=0", partitionFDToken); err != nil {\n\t\treturn fmt.Errorf("format persistence partition: %w", err)\n\t}\n''',
    '''\tif err := safety.WithTemporarilyReleasedFlock(partition, func() error {\n\t\treturn runPartitionCommand(ctx, partition, "mkfs.ext4", "-F", "-L", plan.FilesystemLabel, "-m", "0", "-E", "lazy_itable_init=0,lazy_journal_init=0", partitionFDToken)\n\t}); err != nil {\n\t\treturn fmt.Errorf("format persistence partition: %w", err)\n\t}\n''',
)

replace_once(
    "internal/safety/reopenable_linux_test.go",
    '''func TestOpenReopenableDeviceRefusesSymlink(t *testing.T) {\n''',
    '''func TestWithTemporarilyReleasedFlockRestoresLock(t *testing.T) {\n\tpath := filepath.Join(t.TempDir(), "locked-device")\n\tif err := os.WriteFile(path, []byte("device"), 0o600); err != nil {\n\t\tt.Fatal(err)\n\t}\n\tprimary, err := os.OpenFile(path, os.O_RDWR, 0)\n\tif err != nil {\n\t\tt.Fatal(err)\n\t}\n\tdefer primary.Close()\n\tcontender, err := os.OpenFile(path, os.O_RDWR, 0)\n\tif err != nil {\n\t\tt.Fatal(err)\n\t}\n\tdefer contender.Close()\n\tif err := syscall.Flock(int(primary.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {\n\t\tt.Fatal(err)\n\t}\n\tdefer syscall.Flock(int(primary.Fd()), syscall.LOCK_UN)\n\tif err := syscall.Flock(int(contender.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {\n\t\t_ = syscall.Flock(int(contender.Fd()), syscall.LOCK_UN)\n\t\tt.Fatal("contender unexpectedly acquired the initial lock")\n\t}\n\trun := false\n\tif err := WithTemporarilyReleasedFlock(primary, func() error {\n\t\tif err := syscall.Flock(int(contender.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {\n\t\t\treturn fmt.Errorf("contender could not acquire released lock: %w", err)\n\t\t}\n\t\trun = true\n\t\treturn syscall.Flock(int(contender.Fd()), syscall.LOCK_UN)\n\t}); err != nil {\n\t\tt.Fatal(err)\n\t}\n\tif !run {\n\t\tt.Fatal("trusted operation did not run")\n\t}\n\tif err := syscall.Flock(int(contender.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {\n\t\t_ = syscall.Flock(int(contender.Fd()), syscall.LOCK_UN)\n\t\tt.Fatal("partition lock was not restored")\n\t}\n}\n\nfunc TestOpenReopenableDeviceRefusesSymlink(t *testing.T) {\n''',
)
replace_once(
    "internal/safety/reopenable_linux_test.go",
    '''\tconst inheritedDevice = "/proc/self/fd/3"\n\trunInheritedDeviceCommand(t, device, "mkfs.vfat", "-F", "32", inheritedDevice)\n''',
    '''\tkernelID, err := KernelDeviceID(loopPath)\n\tif err != nil {\n\t\tt.Fatal(err)\n\t}\n\tif _, currentID, err := RevalidateOpenBoundTarget(loopPath, kernelID, true); err != nil || currentID != kernelID {\n\t\tt.Fatalf("revalidate held loop target: id=%d err=%v", currentID, err)\n\t}\n\tif _, _, err := RevalidateOpenBoundTarget(loopPath, kernelID+1, true); err == nil {\n\t\tt.Fatal("changed kernel target identity was accepted")\n\t}\n\n\tconst inheritedDevice = "/proc/self/fd/3"\n\trunInheritedDeviceCommandUnlocked(t, device, "mkfs.vfat", "-F", "32", inheritedDevice)\n''',
)
replace_once(
    "internal/safety/reopenable_linux_test.go",
    '''\trunInheritedDeviceCommand(t, device, "mkfs.ext4", "-F", "-m", "0", inheritedDevice)\n''',
    '''\trunInheritedDeviceCommandUnlocked(t, device, "mkfs.ext4", "-F", "-m", "0", inheritedDevice)\n''',
)
replace_once(
    "internal/safety/reopenable_linux_test.go",
    '''func runInheritedDeviceCommand(t *testing.T, device *os.File, name string, args ...string) {\n''',
    '''func runInheritedDeviceCommandUnlocked(t *testing.T, device *os.File, name string, args ...string) {\n\tt.Helper()\n\terr := WithTemporarilyReleasedFlock(device, func() error {\n\t\tcommand := exec.Command(name, args...)\n\t\tcommand.ExtraFiles = []*os.File{device}\n\t\toutput, runErr := command.CombinedOutput()\n\t\tif runErr != nil {\n\t\t\treturn fmt.Errorf("%s failed: %w: %s", formatCommand(name, args), runErr, strings.TrimSpace(string(output)))\n\t\t}\n\t\treturn nil\n\t})\n\tif err != nil {\n\t\tt.Fatal(err)\n\t}\n}\n\nfunc runInheritedDeviceCommand(t *testing.T, device *os.File, name string, args ...string) {\n''',
)

(ROOT / "internal/windowsmedia/destructive_gate_test.go").write_text('''//go:build linux\n\npackage windowsmedia\n\nimport (\n\t"os"\n\t"strings"\n\t"testing"\n)\n\nfunc TestSelectionIdentityCallbackRunsOnlyBeforeFirstErase(t *testing.T) {\n\tdata, err := os.ReadFile("windowsmedia.go")\n\tif err != nil {\n\t\tt.Fatal(err)\n\t}\n\tsource := string(data)\n\tcallback := "opts.BeforeDestructive(isoFile)"\n\tif count := strings.Count(source, callback); count != 1 {\n\t\tt.Fatalf("selection callback count = %d, want 1", count)\n\t}\n\tcheckStart := strings.Index(source, "checkTarget := func() error {")\n\trunnerStart := strings.Index(source, "runOnTarget := func")\n\tif checkStart < 0 || runnerStart <= checkStart {\n\t\tt.Fatal("target-check anchors not found")\n\t}\n\tif strings.Contains(source[checkStart:runnerStart], callback) {\n\t\tt.Fatal("mutable selection identity remains in the repeated open-device check")\n\t}\n\terase := strings.Index(source, `runOnTarget("wipefs"`)\n\tif gate := strings.Index(source, callback); erase < 0 || gate < 0 || gate > erase {\n\t\tt.Fatal("selection callback is not immediately before the first erase path")\n\t}\n}\n''')

(ROOT / "internal/linuxmedia/destructive_gate_test.go").write_text('''//go:build linux\n\npackage linuxmedia\n\nimport (\n\t"os"\n\t"strings"\n\t"testing"\n)\n\nfunc TestSelectionIdentityCallbackRunsOnlyBeforeFirstErase(t *testing.T) {\n\tdata, err := os.ReadFile("create.go")\n\tif err != nil {\n\t\tt.Fatal(err)\n\t}\n\tsource := string(data)\n\tcallback := "opts.BeforeDestructive(isoFile)"\n\tif count := strings.Count(source, callback); count != 1 {\n\t\tt.Fatalf("selection callback count = %d, want 1", count)\n\t}\n\tcheckStart := strings.Index(source, "checkTarget := func() error {")\n\tfirstCheck := strings.Index(source[checkStart:], "if err := checkTarget();")\n\tif checkStart < 0 || firstCheck < 0 {\n\t\tt.Fatal("target-check anchors not found")\n\t}\n\tif strings.Contains(source[checkStart:checkStart+firstCheck], callback) {\n\t\tt.Fatal("mutable selection identity remains in the repeated open-device check")\n\t}\n\terase := strings.Index(source, `runPersistent(ctx, emit, "wipefs"`)\n\tif gate := strings.Index(source, callback); erase < 0 || gate < 0 || gate > erase {\n\t\tt.Fatal("selection callback is not before the first erase path")\n\t}\n}\n''')
