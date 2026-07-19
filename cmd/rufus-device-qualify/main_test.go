package main

import (
	"strings"
	"testing"

	"github.com/geocausa/RufusArm64/internal/devicequal"
)

func TestParseProfile(t *testing.T) {
	for _, test := range []struct {
		input string
		want  devicequal.Profile
	}{
		{input: "quick", want: devicequal.ProfileQuick},
		{input: " QUICK ", want: devicequal.ProfileQuick},
		{input: "full", want: devicequal.ProfileFull},
		{input: "FULL", want: devicequal.ProfileFull},
	} {
		got, err := parseProfile(test.input)
		if err != nil {
			t.Fatalf("parse %q: %v", test.input, err)
		}
		if got != test.want {
			t.Fatalf("parse %q = %q, want %q", test.input, got, test.want)
		}
	}
	if _, err := parseProfile("sample"); err == nil {
		t.Fatal("expected unsupported profile error")
	}
}

func TestRunValidatesArgumentsBeforeDeviceAccess(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"--profile", "full"},
		{"--device", "/dev/does-not-exist", "extra"},
		{"--device", "/dev/does-not-exist", "--profile", "invalid"},
		{"--device", "/dev/does-not-exist", "--region-size", "0"},
		{"--device", "/dev/does-not-exist", "--yes"},
		{"--device", "/dev/does-not-exist", "--allow-fixed"},
		{"--device", "/dev/does-not-exist", "--json"},
	} {
		if err := run(args); err == nil {
			t.Fatalf("args %v: expected validation error", args)
		}
	}
}

func TestGraphicalInvocationRequiresGuardedIdentityBoundMode(t *testing.T) {
	t.Setenv("PKEXEC_UID", "1000")
	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{name: "dry run", args: []string{"--device", "/dev/does-not-exist", "--expected-identity", "token", "--yes", "--json", "--dry-run"}, want: "requires --yes, --json"},
		{name: "interactive", args: []string{"--device", "/dev/does-not-exist", "--expected-identity", "token", "--json"}, want: "requires --yes, --json"},
		{name: "fixed disk", args: []string{"--device", "/dev/does-not-exist", "--expected-identity", "token", "--yes", "--json", "--allow-fixed"}, want: "normal removable targets"},
		{name: "unmount relaxed", args: []string{"--device", "/dev/does-not-exist", "--expected-identity", "token", "--yes", "--json", "--no-unmount"}, want: "guarded unmounting"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := run(test.args)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestHumanBytes(t *testing.T) {
	for _, test := range []struct {
		value uint64
		want  string
	}{
		{value: 0, want: "0 B"},
		{value: 1023, want: "1023 B"},
		{value: 1024, want: "1.0 KiB"},
		{value: 1024 * 1024, want: "1.0 MiB"},
	} {
		if got := humanBytes(test.value); got != test.want {
			t.Fatalf("humanBytes(%d) = %q, want %q", test.value, got, test.want)
		}
	}
}
