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

func TestPackagedRuntimeUEFILoaderContract(t *testing.T) {
	if packagedRuntimeUEFILoaderPath != "/usr/lib/rufusarm64/bootaa64-uefi-md5sum.efi" {
		t.Fatalf("loader path = %q", packagedRuntimeUEFILoaderPath)
	}
	if packagedRuntimeUEFILoaderSHA256 != "543615a8e97fed1cb5293bee7bdfe10f9feb6979f191b20ab32dafdcf097b502" {
		t.Fatalf("loader digest = %q", packagedRuntimeUEFILoaderSHA256)
	}
	if !strings.Contains(packagedRuntimeUEFILoaderProvenance, "unsigned") {
		t.Fatalf("loader provenance must disclose unsigned status: %q", packagedRuntimeUEFILoaderProvenance)
	}
}
