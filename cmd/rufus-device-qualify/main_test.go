package main

import (
	"encoding/json"
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
		{"--device", "/dev/does-not-exist", "--json-progress"},
		{"--device", "/dev/does-not-exist", "--json", "--json-progress"},
		{"--device", "/dev/does-not-exist", "--dry-run", "--json-progress"},
	} {
		if err := run(args); err == nil {
			t.Fatalf("args %v: expected validation error", args)
		}
	}
}

func TestGraphicalLaunchRequiresProgressStream(t *testing.T) {
	t.Setenv("PKEXEC_UID", "1000")
	err := run([]string{
		"--device", "/dev/does-not-exist",
		"--expected-identity", "identity",
		"--yes",
		"--json",
	})
	if err == nil || !strings.Contains(err.Error(), "--json-progress") {
		t.Fatalf("error = %v, want graphical stream refusal", err)
	}
}

func TestQualificationEventJSONContract(t *testing.T) {
	report := devicequal.Report{Schema: 1, Profile: devicequal.ProfileQuick, Status: devicequal.StatusPassed}
	payload, err := json.Marshal(qualificationEvent{Event: "result", Report: &report})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["event"] != "result" {
		t.Fatalf("event = %v, want result", decoded["event"])
	}
	reportValue, ok := decoded["report"].(map[string]any)
	if !ok || reportValue["schema"] != float64(1) || reportValue["status"] != "passed" {
		t.Fatalf("unexpected report event: %s", payload)
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
