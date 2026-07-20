#!/usr/bin/env python3
"""One-shot descriptor-binding hardening for the Stage 2 formatter."""

from pathlib import Path

path = Path("internal/nonbootable/backend_linux.go")
text = path.read_text(encoding="utf-8")

replacements = [
    (
        '''type linuxBackend struct {
\toptions DeviceOptions
\ttarget  *os.File
\tlocked  bool
}
''',
        '''type linuxBackend struct {
\toptions           DeviceOptions
\ttarget            *os.File
\tstableTargetPath  string
\tlocked            bool
\tpartition         *os.File
\tpartitionPath     string
\tstablePartitionPath string
\tpartitionDeviceID uint64
\tpartitionLocked   bool
}
''',
        "backend fields",
    ),
    (
        '''\tbackend.target = file
\tif err := safety.AcquireExclusiveFlock(ctx, file); err != nil {
''',
        '''\tbackend.target = file
\tbackend.stableTargetPath = stableDescriptorPath(file)
\tif err := safety.AcquireExclusiveFlock(ctx, file); err != nil {
''',
        "stable target assignment",
    ),
    (
        '''\tif err := backend.verifyTarget(plan); err != nil {
\t\treturn err
\t}
\t_, err := runCommand(ctx, nil, "wipefs", "--all", "--force", "--", plan.DevicePath)
\treturn err
}
''',
        '''\tif err := backend.verifyTargetPath(plan); err != nil {
\t\treturn err
\t}
\t_, err := runCommand(ctx, nil, "wipefs", "--all", "--force", "--", backend.stableTargetPath)
\treturn err
}
''',
        "descriptor-bound wipefs",
    ),
    (
        '''\tif err := backend.verifyTarget(plan); err != nil {
\t\treturn "", err
\t}
\tif _, err := runCommand(ctx, []byte(script), "sfdisk", "--no-reread", "--force", "--wipe", "always", "--wipe-partitions", "always", "--", plan.DevicePath); err != nil {
\t\treturn "", err
\t}
''',
        '''\tif err := backend.verifyTargetPath(plan); err != nil {
\t\treturn "", err
\t}
\tif _, err := runCommand(ctx, []byte(script), "sfdisk", "--no-reread", "--force", "--wipe", "always", "--wipe-partitions", "always", "--", backend.stableTargetPath); err != nil {
\t\treturn "", err
\t}
''',
        "descriptor-bound sfdisk",
    ),
    (
        '''\t_, _ = runCommand(ctx, nil, "blockdev", "--rereadpt", plan.DevicePath)
\treturn backend.waitForPartition(ctx, plan, table)
}
''',
        '''\t_, _ = runCommand(ctx, nil, "blockdev", "--rereadpt", backend.stableTargetPath)
\tif err := backend.verifyTargetPath(plan); err != nil {
\t\treturn "", err
\t}
\tpartitionPath, err := backend.waitForPartition(ctx, plan, table)
\tif err != nil {
\t\treturn "", err
\t}
\tif err := backend.bindPartition(ctx, partitionPath, plan, table); err != nil {
\t\treturn "", err
\t}
\treturn partitionPath, nil
}
''',
        "partition binding",
    ),
    (
        '''func (backend *linuxBackend) Format(ctx context.Context, plan Plan, _ PartitionTable, partitionPath string) error {
\tif err := backend.verifyTarget(plan); err != nil {
\t\treturn err
\t}
\tif err := safety.EnsureNoMountedDescendants(plan.DevicePath); err != nil {
''',
        '''func (backend *linuxBackend) Format(ctx context.Context, plan Plan, _ PartitionTable, partitionPath string) error {
\tif err := backend.verifyTargetPath(plan); err != nil {
\t\treturn err
\t}
\tif err := backend.verifyPartitionPath(plan, partitionPath); err != nil {
\t\treturn err
\t}
\tif err := safety.EnsureNoMountedDescendants(plan.DevicePath); err != nil {
''',
        "format binding checks",
    ),
    (
        '''\targs = append(args, partitionPath)
\t_, err := runCommand(ctx, nil, name, args...)
\treturn err
}
''',
        '''\targs = append(args, backend.stablePartitionPath)
\treturn safety.WithTemporarilyReleasedFlock(backend.partition, func() error {
\t\t_, err := runCommand(ctx, nil, name, args...)
\t\treturn err
\t})
}
''',
        "descriptor-bound mkfs",
    ),
    (
        '''func (backend *linuxBackend) Verify(ctx context.Context, plan Plan, table PartitionTable, partitionPath string) (FilesystemState, error) {
\tif err := backend.verifyTarget(plan); err != nil {
\t\treturn FilesystemState{}, err
\t}
\tif _, err := runCommand(ctx, nil, "blockdev", "--flushbufs", partitionPath); err != nil {
''',
        '''func (backend *linuxBackend) Verify(ctx context.Context, plan Plan, table PartitionTable, partitionPath string) (FilesystemState, error) {
\tif err := backend.verifyTargetPath(plan); err != nil {
\t\treturn FilesystemState{}, err
\t}
\tif err := backend.verifyPartitionPath(plan, partitionPath); err != nil {
\t\treturn FilesystemState{}, err
\t}
\tif _, err := runCommand(ctx, nil, "blockdev", "--flushbufs", backend.stablePartitionPath); err != nil {
''',
        "verify descriptor checks",
    ),
    (
        '''\tcheckName, checkArgs, err := filesystemCheck(plan.Filesystem, partitionPath)
''',
        '''\tcheckName, checkArgs, err := filesystemCheck(plan.Filesystem, backend.stablePartitionPath)
''',
        "descriptor-bound checker",
    ),
    (
        '''\tmetadata, err := readBlkid(ctx, partitionPath)
''',
        '''\tmetadata, err := readBlkid(ctx, backend.stablePartitionPath)
''',
        "descriptor-bound blkid",
    ),
    (
        '''\tsizeText, err := commandText(ctx, "blockdev", "--getsize64", partitionPath)
''',
        '''\tsizeText, err := commandText(ctx, "blockdev", "--getsize64", backend.stablePartitionPath)
''',
        "descriptor-bound partition size",
    ),
    (
        '''\treadOnlyText, err := commandText(ctx, "blockdev", "--getro", partitionPath)
''',
        '''\treadOnlyText, err := commandText(ctx, "blockdev", "--getro", backend.stablePartitionPath)
''',
        "descriptor-bound partition readonly",
    ),
    (
        '''func (backend *linuxBackend) Finish(ctx context.Context, plan Plan, table PartitionTable, filesystem FilesystemState) error {
\tif err := backend.verifyTarget(plan); err != nil {
''',
        '''func (backend *linuxBackend) Finish(ctx context.Context, plan Plan, table PartitionTable, filesystem FilesystemState) error {
\tif err := backend.verifyTargetPath(plan); err != nil {
''',
        "finish target binding",
    ),
    (
        '''\tif _, err := runCommand(ctx, nil, "blockdev", "--flushbufs", plan.DevicePath); err != nil {
''',
        '''\tif err := backend.verifyPartitionPath(plan, filesystem.Path); err != nil {
\t\treturn err
\t}
\tif _, err := runCommand(ctx, nil, "blockdev", "--flushbufs", backend.stableTargetPath); err != nil {
''',
        "descriptor-bound target flush",
    ),
    (
        '''func (backend *linuxBackend) Close() error {
\tif backend.target == nil {
\t\treturn nil
\t}
\tvar result error
''',
        '''func (backend *linuxBackend) Close() error {
\tvar result error
\tif err := backend.closePartition(); err != nil {
\t\tresult = errors.Join(result, err)
\t}
\tif backend.target == nil {
\t\treturn result
\t}
''',
        "partition cleanup",
    ),
    (
        '''\tbackend.target = nil
\tbackend.locked = false
\treturn result
}
''',
        '''\tbackend.target = nil
\tbackend.stableTargetPath = ""
\tbackend.locked = false
\treturn result
}
''',
        "target cleanup state",
    ),
    (
        '''\tfor time.Now().Before(deadline) {
\t\tif err := ctx.Err(); err != nil {
''',
        '''\tfor time.Now().Before(deadline) {
\t\tif err := ctx.Err(); err != nil {
\t\t\treturn "", err
\t\t}
\t\tif err := backend.verifyTargetPath(plan); err != nil {
\t\t\treturn "", err
\t\t}
\t\tif err := ctx.Err(); err != nil {
''',
        "wait path binding",
    ),
    (
        '''func (backend *linuxBackend) verifyPublishedTable(ctx context.Context, plan Plan, table PartitionTable) error {
\tdocument, err := readSfdisk(ctx, plan.DevicePath)
''',
        '''func (backend *linuxBackend) verifyPublishedTable(ctx context.Context, plan Plan, table PartitionTable) error {
\tif err := backend.verifyTargetPath(plan); err != nil {
\t\treturn err
\t}
\tdocument, err := readSfdisk(ctx, plan.DevicePath)
''',
        "published table binding",
    ),
]

for old, new, label in replacements:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    text = text.replace(old, new, 1)

path.write_text(text, encoding="utf-8")
Path(".github/scripts/apply_nonbootable_fd_binding.py").unlink()
