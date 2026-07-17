//go:build linux

package windowsmedia

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/geocausa/RufusArm64/internal/sourcefile"
	"github.com/geocausa/RufusArm64/internal/windowsconfig"
)

func TestFindRelativeCaseInsensitive(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "SOURCES")
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	expected := filepath.Join(path, "BOOT.WIM")
	if err := os.WriteFile(expected, []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, ok := findRelativeCaseInsensitive(root, "sources/boot.wim")
	if !ok || got != expected {
		t.Fatalf("got %q, %v; want %q", got, ok, expected)
	}
}

func TestInspectMountedISOARM64(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "sources", "boot.wim"), []byte("boot"))
	writeTestFile(t, filepath.Join(root, "sources", "install.wim"), []byte("install"))
	writeTestFile(t, filepath.Join(root, "efi", "boot", "bootaa64.efi"), []byte("efi"))
	writeTestFile(t, filepath.Join(root, "setup.exe"), []byte("setup"))

	plan, err := inspectMountedISO(root)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Architecture != "ARM64 UEFI" {
		t.Fatalf("architecture=%q", plan.Architecture)
	}
	if plan.NeedsSplit {
		t.Fatal("small install.wim unexpectedly needs splitting")
	}
	if plan.CopyBytes == 0 || plan.RequiredBytes <= plan.CopyBytes {
		t.Fatalf("invalid size plan: copy=%d required=%d", plan.CopyBytes, plan.RequiredBytes)
	}
}

func TestInspectMountedISORejectsOtherOversizedFile(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "sources", "boot.wim"), []byte("boot"))
	writeTestFile(t, filepath.Join(root, "sources", "install.wim"), []byte("install"))
	writeTestFile(t, filepath.Join(root, "efi", "boot", "bootaa64.efi"), []byte("efi"))
	large := filepath.Join(root, "other.bin")
	if err := os.WriteFile(large, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(large, int64(fat32MaxFileSize+1)); err != nil {
		t.Fatal(err)
	}
	plan, err := inspectMountedISO(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateFATCompatibility(root, plan); err == nil {
		t.Fatal("expected oversized-file error")
	}
}

func TestCopyTreeExcludesInstallImage(t *testing.T) {
	source := t.TempDir()
	destination := t.TempDir()
	install := filepath.Join(source, "sources", "install.wim")
	writeTestFile(t, install, []byte("do not copy"))
	writeTestFile(t, filepath.Join(source, "sources", "boot.wim"), []byte("copy me"))
	writeTestFile(t, filepath.Join(source, "efi", "boot", "bootaa64.efi"), []byte("efi"))

	var copied uint64
	if err := copyTree(context.Background(), source, destination, install, "", func(delta uint64) { copied += delta }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(destination, "sources", "install.wim")); !os.IsNotExist(err) {
		t.Fatalf("excluded file exists or unexpected error: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(destination, "sources", "boot.wim"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "copy me" || copied == 0 {
		t.Fatalf("copy failed: content=%q copied=%d", content, copied)
	}
}

func TestCompareFiles(t *testing.T) {
	left := filepath.Join(t.TempDir(), "left")
	right := filepath.Join(t.TempDir(), "right")
	writeTestFile(t, left, []byte("same"))
	writeTestFile(t, right, []byte("same"))
	if _, err := compareFiles(left, right); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(right, []byte("diff"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := compareFiles(left, right); err == nil {
		t.Fatal("expected mismatch")
	}
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func fakeISOFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "image.iso")
	writeTestFile(t, path, []byte("fake ISO descriptor used by the mount test double"))
	return path
}

func TestInspectMountedISOArchitectureFlags(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "sources", "boot.wim"), []byte("boot"))
	writeTestFile(t, filepath.Join(root, "sources", "install.wim"), []byte("install"))
	writeTestFile(t, filepath.Join(root, "efi", "boot", "bootx64.efi"), []byte("efi"))
	plan, err := inspectMountedISO(root)
	if err != nil {
		t.Fatal(err)
	}
	if plan.HasARM64 || !plan.HasX64 || plan.Architecture != "x86-64 UEFI" {
		t.Fatalf("unexpected architecture plan: %#v", plan)
	}
}

func TestValidateSplitPartsRejectsOversizedPart(t *testing.T) {
	part := filepath.Join(t.TempDir(), "install.swm")
	if err := os.WriteFile(part, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(part, int64(fat32MaxFileSize+1)); err != nil {
		t.Fatal(err)
	}
	if _, err := validateSplitParts([]string{part}); err == nil {
		t.Fatal("oversized split part accepted")
	}
}

func TestVerifyTreeComparesEverySplitPart(t *testing.T) {
	sourceRoot := t.TempDir()
	destinationRoot := t.TempDir()
	writeTestFile(t, filepath.Join(sourceRoot, "sources", "boot.wim"), []byte("boot"))
	install := filepath.Join(sourceRoot, "sources", "install.wim")
	writeTestFile(t, install, []byte("original"))
	writeTestFile(t, filepath.Join(destinationRoot, "sources", "boot.wim"), []byte("boot"))

	splitDir := t.TempDir()
	first := filepath.Join(splitDir, "install.swm")
	second := filepath.Join(splitDir, "install2.swm")
	writeTestFile(t, first, []byte("part one"))
	writeTestFile(t, second, []byte("part two"))
	writeTestFile(t, filepath.Join(destinationRoot, "sources", "install.swm"), []byte("part one"))
	writeTestFile(t, filepath.Join(destinationRoot, "sources", "install2.swm"), []byte("part two"))

	plan := mediaPlan{
		InstallPath: install,
		NeedsSplit:  true,
		SplitFiles:  []string{first, second},
		OtherBytes:  uint64(len("boot")),
		SplitBytes:  uint64(len("part one") + len("part two")),
	}
	finalizePlan(&plan)
	if err := verifyTree(context.Background(), sourceRoot, destinationRoot, plan, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(destinationRoot, "sources", "install2.swm"), []byte("corrupt!"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyTree(context.Background(), sourceRoot, destinationRoot, plan, nil); err == nil {
		t.Fatal("corrupted second split part was not detected")
	}
}

func TestCreateWithFakeSystemTools(t *testing.T) {
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
	writeTestFile(t, target, make([]byte, 1024))
	err := Create(context.Background(), iso, target, Options{
		TargetSize:   8 * 1024 * 1024 * 1024,
		Verify:       true,
		RequireARM64: true,
	}, func(event Event) {})
	if err != nil {
		t.Fatal(err)
	}
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	logText := string(logData)
	for _, command := range []string{"wipefs", "mkfs.vfat", "blockdev", "fsck.vfat"} {
		if !strings.Contains(logText, command) {
			t.Fatalf("expected command %q in log:\n%s", command, logText)
		}
	}
}

func TestCreateRejectsX64BeforeDestructiveCommand(t *testing.T) {
	fixture := t.TempDir()
	writeTestFile(t, filepath.Join(fixture, "sources", "boot.wim"), []byte("boot"))
	writeTestFile(t, filepath.Join(fixture, "sources", "install.wim"), []byte("install"))
	writeTestFile(t, filepath.Join(fixture, "efi", "boot", "bootx64.efi"), []byte("efi"))

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
	writeTestFile(t, target, make([]byte, 1024))
	err := Create(context.Background(), iso, target, Options{
		TargetSize:   8 * 1024 * 1024 * 1024,
		RequireARM64: true,
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "x86-64") {
		t.Fatalf("expected ARM64 architecture refusal, got %v", err)
	}
	logData, _ := os.ReadFile(logPath)
	if strings.Contains(string(logData), "wipefs") {
		t.Fatalf("target was touched before architecture refusal:\n%s", logData)
	}
}

func installFakeTools(t *testing.T, directory string) {
	t.Helper()
	mountState := filepath.Join(t.TempDir(), "mount.state")
	t.Setenv("RUFUS_TEST_MOUNT_STATE", mountState)
	tools := []string{"wipefs", "udevadm", "mkfs.vfat", "fsck.vfat", "mkfs.ntfs", "mkntfs", "ntfsfix", "sync"}
	for _, tool := range tools {
		script := "#!/bin/sh\necho '" + tool + " ' \"$@\" >> \"$RUFUS_TEST_LOG\"\nexit 0\n"
		writeExecutable(t, filepath.Join(directory, tool), script)
	}
	writeExecutable(t, filepath.Join(directory, "mkfs.vfat"), `#!/bin/sh
printf 'mkfs.vfat %s\n' "$*" >> "$RUFUS_TEST_LOG"
printf 'FAT32   ' | dd of="$RUFUS_TEST_PARTITION" bs=1 seek=82 conv=notrunc status=none
printf '\006\000' | dd of="$RUFUS_TEST_PARTITION" bs=1 seek=50 conv=notrunc status=none
exit 0
`)
	for _, tool := range []string{"mkfs.ntfs", "mkntfs"} {
		writeExecutable(t, filepath.Join(directory, tool), `#!/bin/sh
printf '`+tool+` %s\n' "$*" >> "$RUFUS_TEST_LOG"
printf 'NTFS    ' | dd of="$RUFUS_TEST_PARTITION" bs=1 seek=3 conv=notrunc status=none
exit 0
`)
	}
	blockdevScript := `#!/bin/sh
printf 'blockdev %s\n' "$*" >> "$RUFUS_TEST_LOG"
if [ "$1" = "--getss" ]; then printf '512\n'; fi
exit 0
`
	writeExecutable(t, filepath.Join(directory, "blockdev"), blockdevScript)
	mountScript := `#!/bin/sh
printf 'mount %s\n' "$*" >> "$RUFUS_TEST_LOG"
previous=""
last=""
for arg in "$@"; do previous="$last"; last="$arg"; done
printf '%s|%s\n' "$previous" "$last" > "$RUFUS_TEST_MOUNT_STATE"
case "$*" in
  *loop,ro*) cp -a "$RUFUS_TEST_ISO/." "$last/" ;;
  *)
    if [ -n "${RUFUS_TEST_USB:-}" ]; then
      rm -rf "$last"
      ln -s "$RUFUS_TEST_USB" "$last"
    fi
    ;;
esac
exit 0
`
	writeExecutable(t, filepath.Join(directory, "mount"), mountScript)
	umountScript := `#!/bin/sh
printf 'umount %s\n' "$*" >> "$RUFUS_TEST_LOG"
target=""
for arg in "$@"; do target="$arg"; done
if [ -f "$RUFUS_TEST_MOUNT_STATE" ]; then
  state=$(cat "$RUFUS_TEST_MOUNT_STATE")
  mounted=${state#*|}
  if [ "$mounted" = "$target" ]; then rm -f "$RUFUS_TEST_MOUNT_STATE"; fi
fi
exit 0
`
	writeExecutable(t, filepath.Join(directory, "umount"), umountScript)
	findmntScript := `#!/bin/sh
source=""
for arg in "$@"; do
  if [ "$arg" = "--target" ]; then printf 'overlay\n'; exit 0; fi
done
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-S" ]; then shift; source="$1"; fi
  shift
done
if [ -f "$RUFUS_TEST_MOUNT_STATE" ]; then
  state=$(cat "$RUFUS_TEST_MOUNT_STATE")
  mounted_source=${state%%|*}
  mounted_target=${state#*|}
  if [ "$mounted_source" = "$source" ]; then printf '%s\n' "$mounted_target"; exit 0; fi
fi
exit 1
`
	writeExecutable(t, filepath.Join(directory, "findmnt"), findmntScript)
	lsblkScript := `#!/bin/sh
printf '%s part\n' "$RUFUS_TEST_PARTITION"
`
	writeExecutable(t, filepath.Join(directory, "lsblk"), lsblkScript)
}

func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareSplitImageBuildsValidatedPartsWithoutRedundantIntegrityPasses(t *testing.T) {
	fakeBin := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "wim.log")
	t.Setenv("RUFUS_TEST_LOG", logPath)
	script := `#!/bin/sh
printf 'wimlib-imagex %s\n' "$*" >> "$RUFUS_TEST_LOG"
if [ "$1" = split ]; then
  printf part1 > "$3"
  dir=$(dirname "$3")
  printf part2 > "$dir/install2.swm"
fi
exit 0
`
	writeExecutable(t, filepath.Join(fakeBin, "wimlib-imagex"), script)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	source := filepath.Join(t.TempDir(), "install.wim")
	writeTestFile(t, source, []byte("fake wim"))
	parts, total, err := prepareSplitImage(context.Background(), source, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 2 || total != uint64(len("part1")+len("part2")) {
		t.Fatalf("unexpected parts=%v total=%d", parts, total)
	}
	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	logText := string(logData)
	if !strings.Contains(logText, "split") {
		t.Fatalf("split command was not executed:\n%s", logText)
	}
	if strings.Contains(logText, "--include-integrity") || strings.Contains(logText, "--check") {
		t.Fatalf("split requested a redundant full integrity pass:\n%s", logText)
	}
	if strings.Contains(logText, " verify ") {
		t.Fatalf("split was followed by an unnecessary full verification pass:\n%s", logText)
	}
}

func TestInspectMountedISOFindsExistingSplitParts(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "sources", "boot.wim"), []byte("boot"))
	writeTestFile(t, filepath.Join(root, "sources", "INSTALL.SWM"), []byte("one"))
	writeTestFile(t, filepath.Join(root, "sources", "INSTALL2.SWM"), []byte("two"))
	writeTestFile(t, filepath.Join(root, "efi", "boot", "bootaa64.efi"), []byte("efi"))
	plan, err := inspectMountedISO(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.ExistingSplitFiles) != 2 || plan.InstallPath != "" {
		t.Fatalf("unexpected existing split plan: %#v", plan)
	}
}

func TestInspectMountedISORejectsMissingBaseSplitPart(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "sources", "boot.wim"), []byte("boot"))
	writeTestFile(t, filepath.Join(root, "sources", "install2.swm"), []byte("two"))
	writeTestFile(t, filepath.Join(root, "efi", "boot", "bootaa64.efi"), []byte("efi"))
	if _, err := inspectMountedISO(root); err == nil || !strings.Contains(err.Error(), "install.swm") {
		t.Fatalf("missing base split part was accepted: %v", err)
	}
}

func TestInspectMountedISORejectsFATCaseCollision(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "sources", "boot.wim"), []byte("boot"))
	writeTestFile(t, filepath.Join(root, "sources", "install.wim"), []byte("install"))
	writeTestFile(t, filepath.Join(root, "efi", "boot", "bootaa64.efi"), []byte("efi"))
	writeTestFile(t, filepath.Join(root, "Readme.txt"), []byte("one"))
	writeTestFile(t, filepath.Join(root, "README.TXT"), []byte("two"))
	plan, err := inspectMountedISO(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateFATCompatibility(root, plan); err == nil || !strings.Contains(err.Error(), "collide") {
		t.Fatalf("case collision was accepted: %v", err)
	}
}

func TestValidateFATRelativePath(t *testing.T) {
	for _, invalid := range []string{"sources/bad:name", "sources/trailing.", "sources/CON.txt"} {
		if err := validateFATRelativePath(invalid); err == nil {
			t.Fatalf("invalid FAT path accepted: %s", invalid)
		}
	}
	if err := validateFATRelativePath("sources/$OEM$/good-file.wim"); err != nil {
		t.Fatalf("valid FAT path rejected: %v", err)
	}
}

func TestCreateRejectsReplacedISO(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "windows.iso")
	writeTestFile(t, path, []byte("original image"))
	_, identity, err := sourcefile.Inspect(path)
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(dir, "replacement.iso")
	writeTestFile(t, replacement, []byte("replacement image"))
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if err := Create(context.Background(), path, "/dev/does-not-matter", Options{ExpectedSource: identity}, nil); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("replaced ISO was not rejected before target access: %v", err)
	}
}

func TestInspectMountedISORejectsConflictingPayloads(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "sources", "boot.wim"), []byte("boot"))
	writeTestFile(t, filepath.Join(root, "sources", "install.wim"), []byte("wim"))
	writeTestFile(t, filepath.Join(root, "sources", "install.esd"), []byte("esd"))
	writeTestFile(t, filepath.Join(root, "efi", "boot", "bootaa64.efi"), []byte("efi"))
	if _, err := inspectMountedISO(root); err == nil || !strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("conflicting payloads were accepted: %v", err)
	}
}

func TestUnmountDeviceMountsUsesDeepestFirst(t *testing.T) {
	fakeBin := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "unmount.log")
	t.Setenv("RUFUS_TEST_LOG", logPath)
	writeExecutable(t, filepath.Join(fakeBin, "findmnt"), "#!/bin/sh\nprintf '/media/usb\\n/media/usb/nested\\n'\n")
	writeExecutable(t, filepath.Join(fakeBin, "umount"), "#!/bin/sh\nprintf '%s\\n' \"$2\" >> \"$RUFUS_TEST_LOG\"\n")
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := unmountDeviceMounts(context.Background(), "/dev/sda1"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Fields(string(data))
	if len(lines) != 2 || lines[0] != "/media/usb/nested" || lines[1] != "/media/usb" {
		t.Fatalf("unexpected order: %q", data)
	}
}

func TestCleanupNeverRemovesWorkDirWhileUSBMayStillBeMounted(t *testing.T) {
	fixture := t.TempDir()
	writeTestFile(t, filepath.Join(fixture, "sources", "boot.wim"), []byte("boot"))
	writeTestFile(t, filepath.Join(fixture, "sources", "install.wim"), []byte("install"))
	writeTestFile(t, filepath.Join(fixture, "efi", "boot", "bootaa64.efi"), []byte("efi"))
	writeTestFile(t, filepath.Join(fixture, "setup.exe"), []byte("keep me"))

	fakeBin := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "commands.log")
	partition := filepath.Join(t.TempDir(), "fake-partition")
	writeTestFile(t, partition, []byte("partition"))
	installFakeTools(t, fakeBin)
	// Simulate a busy mount that cannot be unmounted. The cleanup path must
	// leave the work directory untouched rather than recursively deleting files
	// that could still be on the USB filesystem.
	writeExecutable(t, filepath.Join(fakeBin, "umount"), "#!/bin/sh\nexit 1\n")
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("RUFUS_TEST_ISO", fixture)
	t.Setenv("RUFUS_TEST_LOG", logPath)
	t.Setenv("RUFUS_TEST_PARTITION", partition)

	before, err := filepath.Glob("/var/tmp/rufusarm64-*")
	if err != nil {
		t.Fatal(err)
	}
	known := make(map[string]bool, len(before))
	for _, path := range before {
		known[path] = true
	}
	iso := fakeISOFile(t)
	target := filepath.Join(t.TempDir(), "fake-device")
	writeTestFile(t, target, make([]byte, 1024))
	err = Create(context.Background(), iso, target, Options{
		TargetSize:   8 * 1024 * 1024 * 1024,
		RequireARM64: true,
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "umount") {
		t.Fatalf("expected unmount failure, got %v", err)
	}
	after, err := filepath.Glob("/var/tmp/rufusarm64-*")
	if err != nil {
		t.Fatal(err)
	}
	var created string
	for _, path := range after {
		if !known[path] {
			created = path
			break
		}
	}
	if created == "" {
		t.Fatal("failed cleanup did not leave its safety work directory")
	}
	defer os.RemoveAll(created)
	content, readErr := os.ReadFile(filepath.Join(created, "usb", "setup.exe"))
	if readErr != nil || string(content) != "keep me" {
		t.Fatalf("cleanup deleted possible USB contents: content=%q err=%v", content, readErr)
	}
}

func TestNormalizeVolumeLabel(t *testing.T) {
	label, err := normalizeVolumeLabel("win 11", "fat32")
	if err != nil || label != "WIN 11" {
		t.Fatalf("label=%q err=%v", label, err)
	}
	for _, bad := range []string{"this-label-is-too-long", "BAD/NAME"} {
		if _, err := normalizeVolumeLabel(bad, "fat32"); err == nil {
			t.Fatalf("accepted invalid label %q", bad)
		}
	}
}

func TestRelayToolLineCompactsWimProgress(t *testing.T) {
	var events []Event
	emit := func(event Event) { events = append(events, event) }
	relayToolLine(emit, "/usr/bin/wimlib-imagex", []string{"split"}, "Splitting WIM: 100 MiB of 1000 MiB (10%) written")
	if len(events) != 1 || events[0].Stage != "split" || events[0].Done != 10 || events[0].Total != 100 {
		t.Fatalf("unexpected progress event: %#v", events)
	}
	events = nil
	relayToolLine(emit, "/usr/bin/wimlib-imagex", []string{"split"}, "Splitting WIM: 100 MiB")
	if len(events) != 0 {
		t.Fatalf("repetitive progress line was not suppressed: %#v", events)
	}
}

func TestCopyTreeCanReplaceExistingAnswerFile(t *testing.T) {
	source := t.TempDir()
	destination := t.TempDir()
	answer := filepath.Join(source, "AutoUnattend.XML")
	writeTestFile(t, answer, []byte("old"))
	writeTestFile(t, filepath.Join(source, "setup.exe"), []byte("setup"))
	if err := copyTree(context.Background(), source, destination, "", answer, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(destination, "AutoUnattend.XML")); !os.IsNotExist(err) {
		t.Fatalf("answer file was copied despite replacement exclusion: %v", err)
	}
	if _, err := os.Stat(filepath.Join(destination, "setup.exe")); err != nil {
		t.Fatal(err)
	}
}

func TestCreateUsesCustomLabelAndDoesNotWaitForGlobalUdevQueue(t *testing.T) {
	fixture := t.TempDir()
	writeTestFile(t, filepath.Join(fixture, "sources", "boot.wim"), []byte("boot"))
	writeTestFile(t, filepath.Join(fixture, "sources", "install.wim"), []byte("install"))
	writeTestFile(t, filepath.Join(fixture, "efi", "boot", "bootaa64.efi"), []byte("efi"))

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
	writeTestFile(t, target, make([]byte, 1024))
	if err := Create(context.Background(), iso, target, Options{
		TargetSize:      8 * 1024 * 1024 * 1024,
		VolumeLabel:     "WIN11",
		PartitionScheme: "mbr",
		ClusterSize:     8192,
	}, nil); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	logText := string(data)
	if !strings.Contains(logText, "mkfs.vfat  -F 32 -n WIN11 -s 16") && !strings.Contains(logText, "mkfs.vfat -F 32 -n WIN11 -s 16") {
		t.Fatalf("custom label or cluster size missing from mkfs command:\n%s", logText)
	}
	targetData, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(targetData) < 512 || targetData[446] != 0x80 || targetData[450] != 0x0c || targetData[510] != 0x55 || targetData[511] != 0xaa {
		t.Fatalf("selected MBR layout was not written")
	}
	if strings.Contains(logText, "udevadm") {
		t.Fatalf("global udev settle was called:\n%s", logText)
	}
}

func TestCreateWritesSelectedWindowsOptions(t *testing.T) {
	fixture := t.TempDir()
	writeTestFile(t, filepath.Join(fixture, "sources", "boot.wim"), []byte("boot"))
	writeTestFile(t, filepath.Join(fixture, "sources", "install.wim"), []byte("install"))
	writeTestFile(t, filepath.Join(fixture, "efi", "boot", "bootaa64.efi"), []byte("efi"))
	writeTestFile(t, filepath.Join(fixture, "AutoUnattend.XML"), []byte("old answer"))

	fakeBin := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "commands.log")
	partition := filepath.Join(t.TempDir(), "fake-partition")
	usb := t.TempDir()
	writeTestFile(t, partition, []byte("partition"))
	installFakeTools(t, fakeBin)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("RUFUS_TEST_ISO", fixture)
	t.Setenv("RUFUS_TEST_USB", usb)
	t.Setenv("RUFUS_TEST_LOG", logPath)
	t.Setenv("RUFUS_TEST_PARTITION", partition)
	iso := fakeISOFile(t)
	target := filepath.Join(t.TempDir(), "fake-device")
	writeTestFile(t, target, make([]byte, 1024))

	err := Create(context.Background(), iso, target, Options{
		TargetSize: 8 * 1024 * 1024 * 1024,
		Customizations: windowsconfig.Options{
			BypassHardwareChecks: true,
			BypassOnlineAccount:  true,
			LocalAccount:         "geoca",
			ReduceDataCollection: true,
			DisableBitLocker:     true,
			Locale:               "en-GB",
			TimeZone:             "GMT Standard Time",
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(usb, "autounattend.xml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{"BypassTPMCheck", "BypassNRO", "geoca", "ProtectYourPC", "PreventDeviceEncryption", "<InputLocale>en-GB</InputLocale>", "<TimeZone>GMT Standard Time</TimeZone>"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in answer file:\n%s", want, text)
		}
	}
	if _, err := os.Stat(filepath.Join(usb, "AutoUnattend.XML")); !os.IsNotExist(err) {
		t.Fatalf("original answer file was not replaced cleanly: %v", err)
	}
}

func TestWimlibExecutableIgnoresEnvironmentOverride(t *testing.T) {
	fake := filepath.Join(t.TempDir(), "wimlib-imagex")
	writeExecutable(t, fake, "#!/bin/sh\nexit 0\n")
	t.Setenv("RUFUSARM64_WIMLIB", fake)
	path, err := wimlibExecutable()
	if err == nil && path == fake {
		t.Fatalf("privileged WIM executable followed environment override %q", path)
	}
}

func TestRereadPartitionTableRetriesTargetOnly(t *testing.T) {
	fakeBin := t.TempDir()
	state := filepath.Join(t.TempDir(), "attempts")
	logPath := filepath.Join(t.TempDir(), "blockdev.log")
	t.Setenv("RUFUS_TEST_STATE", state)
	t.Setenv("RUFUS_TEST_LOG", logPath)
	writeExecutable(t, filepath.Join(fakeBin, "blockdev"), `#!/bin/sh
count=0
if [ -f "$RUFUS_TEST_STATE" ]; then count=$(cat "$RUFUS_TEST_STATE"); fi
count=$((count + 1))
printf '%s' "$count" > "$RUFUS_TEST_STATE"
printf '%s\n' "$*" >> "$RUFUS_TEST_LOG"
if [ "$count" -lt 3 ]; then exit 1; fi
exit 0
`)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := rereadPartitionTable(context.Background(), "/dev/fake", nil); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(data), "--rereadpt /dev/fake"); got != 3 {
		t.Fatalf("attempts=%d log=%q", got, data)
	}
}

func TestFirstPartitionPath(t *testing.T) {
	cases := map[string]string{
		"/dev/sdb":     "/dev/sdb1",
		"/dev/nvme0n1": "/dev/nvme0n1p1",
		"/dev/mmcblk0": "/dev/mmcblk0p1",
	}
	for device, want := range cases {
		if got := firstPartitionPath(device); got != want {
			t.Fatalf("firstPartitionPath(%q)=%q want %q", device, got, want)
		}
	}
}

func TestWriteUEFINTFSPartitionImageVerifiesReadback(t *testing.T) {
	imagePath := filepath.Join("..", "..", "vendor", "uefi-ntfs", "uefi-ntfs.img")
	info, err := os.Stat(imagePath)
	if err != nil {
		t.Fatal(err)
	}
	targetPath := filepath.Join(t.TempDir(), "disk.img")
	target, err := os.OpenFile(targetPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	layout := partitionLayout{PartitionStartBytes: 2 * oneMiB, PartitionSizeBytes: uint64(info.Size())}
	if err := target.Truncate(int64(layout.PartitionStartBytes + layout.PartitionSizeBytes + oneMiB)); err != nil {
		target.Close()
		t.Fatal(err)
	}
	if err := writeUEFINTFSPartitionImage(target, imagePath, layout); err != nil {
		target.Close()
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	expected, err := os.ReadFile(imagePath)
	if err != nil {
		t.Fatal(err)
	}
	disk, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	got := disk[layout.PartitionStartBytes : layout.PartitionStartBytes+layout.PartitionSizeBytes]
	if string(got) != string(expected) {
		t.Fatal("UEFI:NTFS bytes were not written at the requested partition offset")
	}
}

func TestUEFINTFSImageFileRejectsModifiedImage(t *testing.T) {
	modified := filepath.Join(t.TempDir(), "uefi-ntfs.img")
	writeTestFile(t, modified, make([]byte, oneMiB))
	t.Setenv("RUFUSARM64_UEFI_NTFS_IMAGE", modified)
	if _, _, err := uefiNTFSImageFile(); err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("modified image was accepted: %v", err)
	}
}

func TestInspectDriverFolder(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "storage", "controller.inf"), []byte("inf"))
	writeTestFile(t, filepath.Join(root, "storage", "controller.sys"), []byte("sys"))
	bytes, err := inspectDriverFolder(root, "fat32")
	if err != nil {
		t.Fatal(err)
	}
	if bytes != uint64(len("inf")+len("sys")) {
		t.Fatalf("driver bytes=%d", bytes)
	}
}

func TestInspectDriverFolderRejectsUnsafeContent(t *testing.T) {
	withoutINF := t.TempDir()
	writeTestFile(t, filepath.Join(withoutINF, "driver.sys"), []byte("sys"))
	if _, err := inspectDriverFolder(withoutINF, "fat32"); err == nil {
		t.Fatal("driver folder without INF was accepted")
	}

	withLink := t.TempDir()
	writeTestFile(t, filepath.Join(withLink, "driver.inf"), []byte("inf"))
	if err := os.Symlink(filepath.Join(withLink, "driver.inf"), filepath.Join(withLink, "alias.inf")); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectDriverFolder(withLink, "ntfs"); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("driver symlink was accepted: %v", err)
	}
}

func TestCreateNTFSWithVerifiedUEFINTFSImage(t *testing.T) {
	fixture := t.TempDir()
	writeTestFile(t, filepath.Join(fixture, "sources", "boot.wim"), []byte("boot"))
	writeTestFile(t, filepath.Join(fixture, "sources", "install.wim"), []byte("install"))
	writeTestFile(t, filepath.Join(fixture, "efi", "boot", "bootaa64.efi"), []byte("efi"))
	writeTestFile(t, filepath.Join(fixture, "setup.exe"), []byte("setup"))

	fakeBin := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "commands.log")
	installFakeTools(t, fakeBin)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("RUFUS_TEST_ISO", fixture)
	t.Setenv("RUFUS_TEST_LOG", logPath)
	usb := t.TempDir()
	t.Setenv("RUFUS_TEST_USB", usb)
	imagePath, err := filepath.Abs(filepath.Join("..", "..", "vendor", "uefi-ntfs", "uefi-ntfs.img"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("RUFUSARM64_UEFI_NTFS_IMAGE", imagePath)

	target := filepath.Join(t.TempDir(), "fake-device")
	writeTestFile(t, target, make([]byte, 1024))
	partition1 := target + "1"
	partition2 := target + "2"
	writeTestFile(t, partition1, []byte("partition-one"))
	writeTestFile(t, partition2, []byte("partition-two"))
	t.Setenv("RUFUS_TEST_PARTITION", partition1)

	iso := fakeISOFile(t)
	const targetSize = uint64(8 * 1024 * 1024 * 1024)
	if err := Create(context.Background(), iso, target, Options{
		TargetSize:      targetSize,
		Verify:          true,
		RequireARM64:    true,
		Filesystem:      "ntfs",
		PartitionScheme: "gpt",
		VolumeLabel:     "WIN11_ARM64",
		ClusterSize:     4096,
	}, nil); err != nil {
		t.Fatal(err)
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	logText := string(logData)
	for _, want := range []string{"mkfs.ntfs", "-L WIN11_ARM64", "-c 4096", "ntfsfix", "-n"} {
		if !strings.Contains(logText, want) {
			t.Fatalf("missing %q from NTFS command log:\n%s", want, logText)
		}
	}

	disk, err := os.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	defer disk.Close()
	entries := make([]byte, 2*gptEntrySize)
	if _, err := disk.ReadAt(entries, 2*512); err != nil {
		t.Fatal(err)
	}
	bootEntry := entries[gptEntrySize : 2*gptEntrySize]
	bootStart := binary.LittleEndian.Uint64(bootEntry[32:40]) * 512
	bootEnd := binary.LittleEndian.Uint64(bootEntry[40:48]) * 512
	bootBytes := make([]byte, bootEnd-bootStart+512)
	if _, err := disk.ReadAt(bootBytes, int64(bootStart)); err != nil {
		t.Fatal(err)
	}
	expected, err := os.ReadFile(imagePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(bootBytes) != string(expected) {
		t.Fatal("written GPT UEFI:NTFS partition does not match the pinned image")
	}
}

func TestOpenWithinRootRefusesSymlinkComponents(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.inf")
	if err := os.WriteFile(secret, []byte("root-only data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "driver.inf"), []byte("legitimate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(root, "link.inf")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	rootHandle, err := os.OpenFile(root, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer rootHandle.Close()

	file, err := openWithinRoot(rootHandle, "driver.inf")
	if err != nil {
		t.Fatalf("legitimate driver file was refused: %v", err)
	}
	file.Close()
	if file, err := openWithinRoot(rootHandle, "link.inf"); err == nil {
		file.Close()
		t.Fatal("a symbolic-link final component was followed")
	}
	if file, err := openWithinRoot(rootHandle, filepath.Join("escape", "secret.inf")); err == nil {
		file.Close()
		t.Fatal("a symbolic-link directory component escaped the driver folder")
	}
	if file, err := openWithinRoot(rootHandle, filepath.Join("..", "anything")); err == nil {
		file.Close()
		t.Fatal("a parent-directory path escaped the driver folder")
	}
}

func TestCopyTreeUntrustedSourceRefusesSwappedSymlink(t *testing.T) {
	source := t.TempDir()
	destination := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "shadow")
	if err := os.WriteFile(secret, []byte("must never reach the USB"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "driver.inf"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Simulate the race: validation saw a regular file, but by copy time the
	// entry is a symbolic link to a root-readable file elsewhere.
	if err := os.Symlink(secret, filepath.Join(source, "swapped.sys")); err != nil {
		t.Fatal(err)
	}
	err := copyTreeWithOptions(context.Background(), source, destination, "", "", true, nil)
	if err == nil {
		t.Fatal("the swapped symbolic link was copied")
	}
	if _, statErr := os.Stat(filepath.Join(destination, "swapped.sys")); statErr == nil {
		data, _ := os.ReadFile(filepath.Join(destination, "swapped.sys"))
		if string(data) == "must never reach the USB" {
			t.Fatal("secret contents were copied to the destination")
		}
	}
}

func TestVerifyTreeChecksDriverMarker(t *testing.T) {
	sourceRoot := t.TempDir()
	destinationRoot := t.TempDir()
	driverRoot := t.TempDir()
	writeTestFile(t, filepath.Join(sourceRoot, "sources", "boot.wim"), []byte("boot"))
	install := filepath.Join(sourceRoot, "sources", "install.wim")
	writeTestFile(t, install, []byte("install"))
	writeTestFile(t, filepath.Join(destinationRoot, "sources", "boot.wim"), []byte("boot"))
	writeTestFile(t, filepath.Join(destinationRoot, "sources", "install.wim"), []byte("install"))
	writeTestFile(t, filepath.Join(destinationRoot, rufusDriverMarkerName), rufusDriverMarker)

	plan := mediaPlan{
		InstallPath:  install,
		InstallSize:  uint64(len("install")),
		OtherBytes:   uint64(len("boot")),
		DriverFolder: driverRoot,
	}
	finalizePlan(&plan)
	if err := verifyTree(context.Background(), sourceRoot, destinationRoot, plan, nil); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(destinationRoot, rufusDriverMarkerName), []byte("tampered"))
	if err := verifyTree(context.Background(), sourceRoot, destinationRoot, plan, nil); err == nil || !strings.Contains(err.Error(), "driver marker") {
		t.Fatalf("tampered driver marker was not rejected: %v", err)
	}
}

func TestCreateLegacyBIOSNTFSWithFakeSystemTools(t *testing.T) {
	fixture := t.TempDir()
	writeTestFile(t, filepath.Join(fixture, "sources", "boot.wim"), []byte("boot"))
	writeTestFile(t, filepath.Join(fixture, "sources", "install.wim"), []byte("install"))
	writeTestFile(t, filepath.Join(fixture, "efi", "boot", "bootx64.efi"), []byte("efi"))
	writeTestFile(t, filepath.Join(fixture, "bootmgr"), []byte("bootmgr"))
	writeTestFile(t, filepath.Join(fixture, "setup.exe"), []byte("setup"))

	fakeBin := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "commands.log")
	partition := filepath.Join(t.TempDir(), "fake-partition")
	writeSizedTestFile(t, partition, 8*oneMiB)
	installFakeTools(t, fakeBin)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("RUFUS_TEST_ISO", fixture)
	t.Setenv("RUFUS_TEST_LOG", logPath)
	t.Setenv("RUFUS_TEST_PARTITION", partition)

	iso := fakeISOFile(t)
	target := filepath.Join(t.TempDir(), "fake-device")
	writeSizedTestFile(t, target, 2*oneMiB)
	err := Create(context.Background(), iso, target, Options{
		TargetSize:      8 * 1024 * 1024 * 1024,
		PartitionScheme: "mbr",
		TargetSystem:    "bios",
		Filesystem:      "ntfs",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	disk, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(disk[:len(windows7MBRCode)], windows7MBRCode) || disk[446] != 0x80 || disk[450] != 0x07 {
		t.Fatal("legacy BIOS MBR was not installed through the complete creation path")
	}
	pbr, err := os.ReadFile(partition)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pbr[:len(ntfsPBR0)], ntfsPBR0) || !bytes.Equal(pbr[0x54:0x54+len(ntfsPBR54)], ntfsPBR54) {
		t.Fatal("legacy BIOS NTFS PBR was not installed through the complete creation path")
	}
}

func TestCreateStagesAndConfiguresWindowsPEDrivers(t *testing.T) {
	fixture := t.TempDir()
	writeTestFile(t, filepath.Join(fixture, "sources", "boot.wim"), []byte("boot"))
	writeTestFile(t, filepath.Join(fixture, "sources", "install.wim"), []byte("install"))
	writeTestFile(t, filepath.Join(fixture, "efi", "boot", "bootaa64.efi"), []byte("efi"))
	writeTestFile(t, filepath.Join(fixture, "setup.exe"), []byte("setup"))

	drivers := t.TempDir()
	writeTestFile(t, filepath.Join(drivers, "storage", "surface.inf"), []byte("[Version]\nSignature=\"$Windows NT$\"\n"))
	writeTestFile(t, filepath.Join(drivers, "storage", "surface.sys"), []byte("driver"))

	fakeBin := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "commands.log")
	partition := filepath.Join(t.TempDir(), "fake-partition")
	writeSizedTestFile(t, partition, 8*oneMiB)
	usbRoot := t.TempDir()
	installFakeTools(t, fakeBin)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("RUFUS_TEST_ISO", fixture)
	t.Setenv("RUFUS_TEST_LOG", logPath)
	t.Setenv("RUFUS_TEST_PARTITION", partition)
	t.Setenv("RUFUS_TEST_USB", usbRoot)

	iso := fakeISOFile(t)
	target := filepath.Join(t.TempDir(), "fake-device")
	writeSizedTestFile(t, target, 2*oneMiB)
	if err := Create(context.Background(), iso, target, Options{
		TargetSize:   8 * 1024 * 1024 * 1024,
		Verify:       true,
		RequireARM64: true,
		DriverFolder: drivers,
	}, nil); err != nil {
		t.Fatal(err)
	}

	answer, err := os.ReadFile(filepath.Join(usbRoot, "autounattend.xml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"RUFUSARM64.DRV", "drvload", "Microsoft-Windows-Setup"} {
		if !strings.Contains(string(answer), want) {
			t.Fatalf("driver autoload answer file is missing %q:\n%s", want, answer)
		}
	}
	marker, err := os.ReadFile(filepath.Join(usbRoot, rufusDriverMarkerName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(marker, rufusDriverMarker) {
		t.Fatalf("unexpected driver marker: %q", marker)
	}
	for _, path := range []string{
		filepath.Join(usbRoot, "drivers", "storage", "surface.inf"),
		filepath.Join(usbRoot, "drivers", "storage", "surface.sys"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("staged driver file missing: %s: %v", path, err)
		}
	}
}
