package main

import (
	"testing"

	"github.com/geocausa/RufusArm64/internal/devicequal"
)

func TestParseDeviceQualificationProfile(t *testing.T) {
	for _, test := range []struct {
		input string
		want  devicequal.Profile
	}{
		{input: "quick", want: devicequal.ProfileQuick},
		{input: " QUICK ", want: devicequal.ProfileQuick},
		{input: "full", want: devicequal.ProfileFull},
		{input: "FULL", want: devicequal.ProfileFull},
	} {
		got, err := parseDeviceQualificationProfile(test.input)
		if err != nil {
			t.Fatalf("parse %q: %v", test.input, err)
		}
		if got != test.want {
			t.Fatalf("parse %q = %q, want %q", test.input, got, test.want)
		}
	}
	if _, err := parseDeviceQualificationProfile("sample"); err == nil {
		t.Fatal("expected unsupported profile error")
	}
}

func TestRunDeviceCommandRequiresSubcommand(t *testing.T) {
	if err := runDevice(nil); err == nil {
		t.Fatal("expected missing subcommand error")
	}
	if err := runDevice([]string{"unknown"}); err == nil {
		t.Fatal("expected unknown subcommand error")
	}
}

func TestRunDeviceQualifyValidatesArgumentsBeforeDeviceAccess(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"--profile", "full"},
		{"--device", "/dev/does-not-exist", "extra"},
		{"--device", "/dev/does-not-exist", "--profile", "invalid"},
		{"--device", "/dev/does-not-exist", "--region-size", "0"},
	} {
		if err := runDeviceQualify(args); err == nil {
			t.Fatalf("args %v: expected validation error", args)
		}
	}
}
