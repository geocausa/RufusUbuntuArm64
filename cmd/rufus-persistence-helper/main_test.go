//go:build linux

package main

import (
	"strings"
	"testing"
)

func TestRunRequiresIdentityBoundSelections(t *testing.T) {
	err := run([]string{"--json-progress", "--yes", "--cancel-file", "/run/user/1000/cancel"})
	if err == nil || !strings.Contains(err.Error(), "--expected-source-identity") {
		t.Fatalf("missing-selection error = %v", err)
	}
}

func TestRunRefusesDirectRootStyleInvocation(t *testing.T) {
	t.Setenv("PKEXEC_UID", "")
	err := run([]string{
		"--image", "/tmp/image.iso",
		"--expected-source-identity", "1:2:3:4:5",
		"--device", "/dev/sdz",
		"--expected-identity", "target",
		"--cancel-file", "/run/user/1000/cancel",
		"--json-progress",
		"--yes",
	})
	if err == nil || !strings.Contains(err.Error(), "must be launched through pkexec") {
		t.Fatalf("direct invocation error = %v", err)
	}
}

func TestRunRequiresGraphicalSafetyFlags(t *testing.T) {
	t.Setenv("PKEXEC_UID", "1000")
	err := run([]string{
		"--image", "/tmp/image.iso",
		"--expected-source-identity", "1:2:3:4:5",
		"--device", "/dev/sdz",
		"--expected-identity", "target",
	})
	if err == nil || !strings.Contains(err.Error(), "requires --json-progress") {
		t.Fatalf("graphical safety error = %v", err)
	}
}
