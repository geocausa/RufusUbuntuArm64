package main

import (
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
