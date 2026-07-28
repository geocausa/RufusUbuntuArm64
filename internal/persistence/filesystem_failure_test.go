//go:build linux

package persistence

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateFilesystemFailureStagesSuppressCompletionAndCleanup(t *testing.T) {
	for _, stage := range []string{"format", "mount", "unmount", "check"} {
		t.Run(stage, func(t *testing.T) {
			partitionPath := filepath.Join(t.TempDir(), "partition")
			partition, err := os.OpenFile(partitionPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			if err := partition.Truncate(int64(minimumPartitionSize)); err != nil {
				partition.Close()
				t.Fatal(err)
			}
			if err := partition.Close(); err != nil {
				t.Fatal(err)
			}
			t.Setenv("RUFUS_TEST_PARTITION", partitionPath)
			t.Setenv("RUFUS_FAIL_STAGE", stage)
			logPath := filepath.Join(t.TempDir(), "commands.log")
			countPath := filepath.Join(t.TempDir(), "umount-count")
			t.Setenv("RUFUS_TEST_LOG", logPath)
			t.Setenv("RUFUS_UMOUNT_COUNT", countPath)

			bin := t.TempDir()
			script := `#!/bin/sh
set -eu
name=$(basename "$0")
printf '%s\n' "$name" >> "$RUFUS_TEST_LOG"
case "${RUFUS_FAIL_STAGE:-}" in
  format)
    [ "$name" != mkfs.ext4 ] || exit 41
    ;;
  mount)
    [ "$name" != mount ] || exit 42
    ;;
  unmount)
    if [ "$name" = umount ]; then
      count=0
      [ ! -f "$RUFUS_UMOUNT_COUNT" ] || count=$(cat "$RUFUS_UMOUNT_COUNT")
      count=$((count + 1))
      printf '%s\n' "$count" > "$RUFUS_UMOUNT_COUNT"
      [ "$count" -ne 1 ] || exit 43
    fi
    ;;
  check)
    [ "$name" != e2fsck ] || exit 44
    ;;
esac
exit 0
`
			for _, name := range []string{"mkfs.ext4", "mount", "umount", "e2fsck"} {
				if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("PATH", bin+":"+os.Getenv("PATH"))

			workRoot := t.TempDir()
			var stages []string
			plan := Plan{
				Family: FamilyUbuntuCasper, SizeBytes: minimumPartitionSize,
				Filesystem: "ext4", FilesystemLabel: "casper-rw", BootParameter: "persistent",
			}
			err = CreateFilesystem(context.Background(), partitionPath, plan, FilesystemOptions{
				WorkDirectory: workRoot,
				Event: func(event FilesystemEvent) {
					stages = append(stages, event.Stage)
				},
			})
			if err == nil {
				t.Fatalf("%s failure reported success", stage)
			}
			if strings.Contains(strings.Join(stages, ","), "complete") {
				t.Fatalf("%s failure emitted completion: %v", stage, stages)
			}
			entries, readErr := os.ReadDir(workRoot)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if len(entries) != 0 {
				t.Fatalf("%s failure left owned workspace entries: %v", stage, entries)
			}
			if stage == "unmount" {
				data, readErr := os.ReadFile(countPath)
				if readErr != nil {
					t.Fatal(readErr)
				}
				if strings.TrimSpace(string(data)) != "2" {
					t.Fatalf("cleanup unmount count = %q, want 2", data)
				}
			}
		})
	}
}
