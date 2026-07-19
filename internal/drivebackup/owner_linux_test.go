//go:build linux

package drivebackup

import (
	"errors"
	"os"
	"os/user"
	"strconv"
	"testing"
)

func TestResolveGraphicalOwner(t *testing.T) {
	lookup := func(id string) (*user.User, error) {
		if id != "1000" {
			t.Fatalf("lookup id = %q", id)
		}
		return &user.User{Uid: "1000", Gid: "1001"}, nil
	}
	uid, gid, err := resolveGraphicalOwner("1000", lookup)
	if err != nil {
		t.Fatal(err)
	}
	if uid != 1000 || gid != 1001 {
		t.Fatalf("owner = %d:%d", uid, gid)
	}

	for _, value := range []string{"", "-1", "not-a-number"} {
		if _, _, err := resolveGraphicalOwner(value, lookup); err == nil {
			t.Fatalf("resolveGraphicalOwner(%q) succeeded", value)
		}
	}

	_, _, err = resolveGraphicalOwner("1000", func(string) (*user.User, error) {
		return nil, errors.New("missing")
	})
	if err == nil {
		t.Fatal("missing user succeeded")
	}

	_, _, err = resolveGraphicalOwner("1000", func(string) (*user.User, error) {
		return &user.User{Uid: "1000", Gid: "bad"}, nil
	})
	if err == nil {
		t.Fatal("invalid group succeeded")
	}
}

func TestApplyDestinationOwnerCurrentUser(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "owner-*")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := applyDestinationOwner(file, os.Getuid(), os.Getgid()); err != nil {
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
	current, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil {
		t.Skipf("current user is not available through os/user: %v", err)
	}
	if current.Gid != strconv.Itoa(os.Getgid()) {
		t.Skipf("current primary gid %s differs from process gid %d", current.Gid, os.Getgid())
	}
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
