//go:build linux

package persistence

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateFilesystemDebianContract(t *testing.T) {
	partitionPath := filepath.Join(t.TempDir(), "partition")
	partition, err := os.OpenFile(partitionPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := partition.Truncate(int64(minimumPartitionSize)); err != nil {
		partition.Close()
		t.Fatal(err)
	}
	partition.Close()
	t.Setenv("RUFUS_TEST_PARTITION", partitionPath)

	bin := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "commands.log")
	t.Setenv("RUFUS_TEST_LOG", logPath)
	for _, name := range []string{"mkfs.ext4", "mount", "umount", "e2fsck"} {
		script := `#!/bin/sh
set -eu
printf '%s' "$(basename "$0")" >> "$RUFUS_TEST_LOG"
for arg in "$@"; do printf ' <%s>' "$arg" >> "$RUFUS_TEST_LOG"; last="$arg"; done
printf '\n' >> "$RUFUS_TEST_LOG"
test -e /proc/self/fd/3
if [ "$(basename "$0")" = umount ] && [ -f "$last/persistence.conf" ]; then
  printf 'config=' >> "$RUFUS_TEST_LOG"
  cat "$last/persistence.conf" >> "$RUFUS_TEST_LOG"
fi
`
		path := filepath.Join(bin, name)
		if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))

	plan := Plan{
		Family:            FamilyDebianLive,
		SizeBytes:         minimumPartitionSize,
		Filesystem:        "ext4",
		FilesystemLabel:   "persistence",
		BootParameter:     "persistence",
		PersistenceConfig: "/ union\n",
	}
	beforeCalled := false
	var stages []string
	err = CreateFilesystem(context.Background(), partitionPath, plan, FilesystemOptions{
		WorkDirectory: t.TempDir(),
		BeforeDestructive: func(file *os.File) error {
			beforeCalled = true
			info, err := file.Stat()
			if err != nil {
				return err
			}
			if uint64(info.Size()) != plan.SizeBytes {
				t.Fatalf("partition size=%d", info.Size())
			}
			return nil
		},
		Event: func(event FilesystemEvent) { stages = append(stages, event.Stage) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !beforeCalled {
		t.Fatal("final safety callback was not called")
	}
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	logText := string(logData)
	for _, want := range []string{
		"mkfs.ext4 <-F> <-L> <persistence>",
		"mount <-t> <ext4> <-o> <nosuid,nodev,noexec> </proc/self/fd/3>",
		"config=/ union\n",
		"e2fsck <-f> <-n> </proc/self/fd/3>",
	} {
		if !strings.Contains(logText, want) {
			t.Fatalf("missing %q in command log:\n%s", want, logText)
		}
	}
	if strings.Join(stages, ",") != "format,mount,unmount,check,complete" {
		t.Fatalf("stages=%v", stages)
	}
}

func TestCreateFilesystemRejectsSymlinkPartition(t *testing.T) {
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "partition")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	plan := Plan{Family: FamilyUbuntuCasper, SizeBytes: minimumPartitionSize, Filesystem: "ext4", FilesystemLabel: "casper-rw", BootParameter: "persistent"}
	if err := CreateFilesystem(context.Background(), link, plan, FilesystemOptions{WorkDirectory: t.TempDir()}); err == nil {
		t.Fatal("symlink partition accepted")
	}
}

func TestCreateFilesystemRejectsIncorrectContractBeforeCommands(t *testing.T) {
	plan := Plan{Family: FamilyUbuntuCasper, SizeBytes: minimumPartitionSize, Filesystem: "ext4", FilesystemLabel: "persistence", BootParameter: "persistent"}
	if err := CreateFilesystem(context.Background(), "/does/not/matter", plan, FilesystemOptions{}); err == nil {
		t.Fatal("invalid Ubuntu persistence contract accepted")
	}
}

func TestCreateFilesystemRejectsPersistenceConfigSymlinkAndUnmounts(t *testing.T) {
	partitionPath := filepath.Join(t.TempDir(), "partition")
	partition, err := os.OpenFile(partitionPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := partition.Truncate(int64(minimumPartitionSize)); err != nil {
		partition.Close()
		t.Fatal(err)
	}
	partition.Close()
	t.Setenv("RUFUS_TEST_PARTITION", partitionPath)
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("unchanged\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RUFUS_OUTSIDE", outside)
	logPath := filepath.Join(t.TempDir(), "commands.log")
	t.Setenv("RUFUS_TEST_LOG", logPath)
	bin := t.TempDir()
	for _, name := range []string{"mkfs.ext4", "umount", "e2fsck"} {
		script := "#!/bin/sh\nprintf '%s\\n' \"$(basename \"$0\")\" >> \"$RUFUS_TEST_LOG\"\n"
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mountScript := `#!/bin/sh
set -eu
for last; do :; done
ln -s "$RUFUS_OUTSIDE" "$last/persistence.conf"
printf 'mount\n' >> "$RUFUS_TEST_LOG"
`
	if err := os.WriteFile(filepath.Join(bin, "mount"), []byte(mountScript), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	plan := Plan{Family: FamilyDebianLive, SizeBytes: minimumPartitionSize, Filesystem: "ext4", FilesystemLabel: "persistence", BootParameter: "persistence", PersistenceConfig: "/ union\n"}
	if err := CreateFilesystem(context.Background(), partitionPath, plan, FilesystemOptions{WorkDirectory: t.TempDir()}); err == nil {
		t.Fatal("persistence.conf symlink accepted")
	}
	content, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "unchanged\n" {
		t.Fatal("outside file changed")
	}
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logData), "umount") {
		t.Fatalf("cleanup unmount missing: %s", logData)
	}
}
