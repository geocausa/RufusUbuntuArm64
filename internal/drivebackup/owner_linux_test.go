//go:build linux

package drivebackup

import (
	"os"
	"strconv"
	"syscall"
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

func TestDirectoryPermitsCreate(t *testing.T) {
	groups := map[uint32]struct{}{42: {}}
	tests := []struct {
		name string
		stat syscall.Stat_t
		want bool
	}{
		{name: "owner", stat: syscall.Stat_t{Mode: syscall.S_IFDIR | 0o700, Uid: 1000, Gid: 1}, want: true},
		{name: "group", stat: syscall.Stat_t{Mode: syscall.S_IFDIR | 0o730, Uid: 0, Gid: 42}, want: true},
		{name: "world", stat: syscall.Stat_t{Mode: syscall.S_IFDIR | 0o703, Uid: 0, Gid: 1}, want: true},
		{name: "read-only", stat: syscall.Stat_t{Mode: syscall.S_IFDIR | 0o755, Uid: 0, Gid: 1}, want: false},
		{name: "write-without-search", stat: syscall.Stat_t{Mode: syscall.S_IFDIR | 0o702, Uid: 0, Gid: 1}, want: false},
		{name: "not-directory", stat: syscall.Stat_t{Mode: syscall.S_IFREG | 0o700, Uid: 1000, Gid: 1}, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := directoryPermitsCreate(&test.stat, 1000, groups); got != test.want {
				t.Fatalf("directoryPermitsCreate() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestValidateGraphicalDestinationDirectoryCurrentUser(t *testing.T) {
	t.Setenv("PKEXEC_UID", strconv.Itoa(os.Getuid()))
	directory, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if err := validateGraphicalDestinationDirectory(directory); err != nil {
		t.Fatal(err)
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
