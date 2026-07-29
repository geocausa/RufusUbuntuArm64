#!/usr/bin/env python3
from pathlib import Path


def replace_once(path, old, new):
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one guarded match, found {count}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_once(
    "internal/nonbootable/backend_linux.go",
    'runCommand(ctx, nil, "blkid", "-p", "-o", "export", "--", path)',
    'runCommand(ctx, nil, "blkid", "-p", "--no-encoding", "-o", "export", "--", path)',
)
replace_once(
    "internal/nonbootable/backend_source_test.go",
    '''\t\t`readBlkid(ctx, backend.stablePartitionPath)`,
''',
    '''\t\t`readBlkid(ctx, backend.stablePartitionPath)`,
\t\t`"blkid", "-p", "--no-encoding", "-o", "export", "--", path`,
''',
)
replace_once(
    "internal/linuxmedia/extracted_ntfs_loop_test.go",
    'exec.Command("blkid", "-p", "-o", "export", dataPartitionPath)',
    'exec.Command("blkid", "-p", "--no-encoding", "-o", "export", dataPartitionPath)',
)

replace_once(
    "internal/windowsmedia/windowsmedia.go",
    '[]string{"mount", "umount", "findmnt", "lsblk", "wipefs", "sync", "blockdev"}',
    '[]string{"mount", "umount", "findmnt", "lsblk", "wipefs", "sync", "blockdev", "blkid"}',
)
replace_once(
    "internal/windowsmedia/windowsmedia.go",
    '''\t}
\tif targetSystem == "bios" {
''',
    '''\t}
\tif err := run(ctx, emit, "blockdev", "--flushbufs", partition); err != nil {
\t\treturn fmt.Errorf("flush formatted partition before label readback: %w", err)
\t}
\treadbackLabel, err := readVolumeLabel(ctx, partition)
\tif err != nil {
\t\treturn err
\t}
\tif readbackLabel != label {
\t\treturn fmt.Errorf("formatted volume label %q does not match reviewed label %q", readbackLabel, label)
\t}
\tsend(emit, Event{Stage: "format", Message: fmt.Sprintf("Verified formatted %s volume label %q.", strings.ToUpper(filesystem), label)})
\tif targetSystem == "bios" {
''',
)
replace_once(
    "internal/windowsmedia/windowsmedia.go",
    '''func normalizeVolumeLabel(value, filesystem string) (string, error) {
''',
    '''func readVolumeLabel(ctx context.Context, path string) (string, error) {
\tcommand := exec.CommandContext(ctx, "blkid", "-p", "--no-encoding", "-o", "value", "-s", "LABEL", "--", path)
\toutput, err := command.CombinedOutput()
\tif err != nil {
\t\tif ctx.Err() != nil {
\t\t\treturn "", ctx.Err()
\t\t}
\t\treturn "", fmt.Errorf("read formatted volume label: %w: %s", err, strings.TrimSpace(string(output)))
\t}
\treturn strings.TrimRight(string(output), "\\r\\n"), nil
}

func normalizeVolumeLabel(value, filesystem string) (string, error) {
''',
)
replace_once(
    "internal/windowsmedia/windowsmedia_test.go",
    '''func TestRelayToolLineCompactsWimProgress(t *testing.T) {
''',
    '''func TestReadVolumeLabelRequestsUnencodedOutput(t *testing.T) {
\tdirectory := t.TempDir()
\tscript := filepath.Join(directory, "blkid")
\tcontent := `#!/bin/sh
case " $* " in
  *" --no-encoding "*) ;;
  *) exit 41 ;;
esac
printf 'Rufus:*?-Été\\n'
`
\tif err := os.WriteFile(script, []byte(content), 0o755); err != nil {
\t\tt.Fatal(err)
\t}
\tt.Setenv("PATH", directory)
\tgot, err := readVolumeLabel(context.Background(), "/dev/test")
\tif err != nil || got != "Rufus:*?-Été" {
\t\tt.Fatalf("readVolumeLabel() = %q, %v", got, err)
\t}
}

func TestRelayToolLineCompactsWimProgress(t *testing.T) {
''',
)

print("Unicode blkid readback applied successfully")
