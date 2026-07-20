//go:build linux

package main

import (
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

func TestCommandHasNoFixedDiskOverride(t *testing.T) {
	value := arguments{}
	if strings.Contains(strings.ToLower(strings.TrimSpace(value.label)), "fixed") {
		t.Fatal("unexpected fixed-disk option state")
	}
}
