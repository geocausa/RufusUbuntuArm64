//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validArguments() arguments {
	return arguments{
		devicePath:       "/dev/sdb",
		expectedIdentity: strings.Repeat("a", 64),
		label:            "FREEDOS",
		yes:              true,
		asJSON:           true,
		cancelFile:       "/run/user/1000/rufusarm64-freedos.cancel",
	}
}

func TestValidateArguments(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*arguments)
		pkexec  bool
		wantErr bool
	}{
		{name: "terminal run", mutate: func(*arguments) {}, wantErr: false},
		{name: "graphical run", mutate: func(*arguments) {}, pkexec: true, wantErr: false},
		{name: "missing device", mutate: func(value *arguments) { value.devicePath = "" }, wantErr: true},
		{name: "yes without identity", mutate: func(value *arguments) { value.expectedIdentity = "" }, wantErr: true},
		{name: "json interactive", mutate: func(value *arguments) { value.yes = false }, wantErr: true},
		{name: "cancel dry run", mutate: func(value *arguments) { value.dryRun = true }, wantErr: true},
		{name: "graphical no unmount", mutate: func(value *arguments) { value.noUnmount = true }, pkexec: true, wantErr: true},
		{name: "graphical missing cancel", mutate: func(value *arguments) { value.cancelFile = "" }, pkexec: true, wantErr: true},
		{name: "graphical dry run", mutate: func(value *arguments) { value.cancelFile = ""; value.dryRun = true }, pkexec: true, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := validArguments()
			test.mutate(&value)
			err := validateArguments(value, test.pkexec)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateArguments() error=%v, wantErr=%t", err, test.wantErr)
			}
		})
	}
}

func TestDryRunDoesNotRequireConfirmationOrIdentity(t *testing.T) {
	value := arguments{devicePath: "/dev/sdb", label: "FREEDOS", dryRun: true, asJSON: true}
	if err := validateArguments(value, false); err != nil {
		t.Fatalf("unprivileged dry run was rejected: %v", err)
	}
}

func TestLogicalSectorSizeUsesReadableSysfs(t *testing.T) {
	root := t.TempDir()
	previous := sysClassBlockRoot
	sysClassBlockRoot = root
	t.Cleanup(func() { sysClassBlockRoot = previous })

	queue := filepath.Join(root, "sdb", "queue")
	if err := os.MkdirAll(queue, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(queue, "logical_block_size"), []byte("512\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	value, err := logicalSectorSize("/dev/sdb")
	if err != nil {
		t.Fatal(err)
	}
	if value != 512 {
		t.Fatalf("logical sector size=%d, want 512", value)
	}
}

func TestLogicalSectorSizeRejectsFourKiBSectors(t *testing.T) {
	root := t.TempDir()
	previous := sysClassBlockRoot
	sysClassBlockRoot = root
	t.Cleanup(func() { sysClassBlockRoot = previous })

	queue := filepath.Join(root, "sdb", "queue")
	if err := os.MkdirAll(queue, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(queue, "logical_block_size"), []byte("4096\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := logicalSectorSize("/dev/sdb"); err == nil || !strings.Contains(err.Error(), "requires 512-byte") {
		t.Fatalf("4 KiB sector error=%v", err)
	}
}

func TestLogicalSectorSizeRejectsInvalidSysfsValue(t *testing.T) {
	root := t.TempDir()
	previous := sysClassBlockRoot
	sysClassBlockRoot = root
	t.Cleanup(func() { sysClassBlockRoot = previous })

	queue := filepath.Join(root, "sdb", "queue")
	if err := os.MkdirAll(queue, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(queue, "logical_block_size"), []byte("invalid\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := logicalSectorSize("/dev/sdb"); err == nil || !strings.Contains(err.Error(), "parse logical sector size") {
		t.Fatalf("invalid sector value error=%v", err)
	}
}
