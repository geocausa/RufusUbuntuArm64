//go:build linux

package drivebackup

import (
	"os"
	"strconv"
	"testing"
)

func TestResolveGraphicalUID(t *testing.T) {
	uid, err := resolveGraphicalUID("1000")
	if err != nil {
		t.Fatal(err)
	}
	if uid != 1000 {
		t.Fatalf("uid = %d", uid)
	}
	for _, value := range []string{"", "-1", "not-a-number"} {
		if _, err := resolveGraphicalUID(value); err == nil {
			t.Fatalf("resolveGraphicalUID(%q) succeeded", value)
		}
	}
}

func TestApplyDestinationOwnerCurrentUser(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "owner-*")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := applyDestinationOwner(file, os.Getuid()); err != nil {
		t.Fatal(err)
	}
}

func TestApplyGraphicalDestinationOwnerDisabled(t *testing.T) {
	t.Setenv("PKEXEC_UID", "")
	file, err := os.CreateTemp(t.TempDir(), "disabled-*")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := applyGraphicalDestinationOwner(file); err != nil {
		t.Fatal(err)
	}
}

func TestApplyGraphicalDestinationOwnerCurrentUser(t *testing.T) {
	t.Setenv("PKEXEC_UID", strconv.Itoa(os.Getuid()))
	file, err := os.CreateTemp(t.TempDir(), "enabled-*")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := applyGraphicalDestinationOwner(file); err != nil {
		t.Fatal(err)
	}
}
