//go:build linux

package isocapture

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestRequirePortableMetadataRejectsSpecialPermissionBits(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "metadata-*")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	stat.Mode |= syscall.S_ISUID
	if err := requirePortableMetadata(file.Fd(), stat, "FILE.BIN"); err == nil || !strings.Contains(err.Error(), "setuid") {
		t.Fatalf("special-mode error = %v", err)
	}
}

func TestRequirePortableMetadataRejectsExtendedAttributes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "FILE.BIN")
	if err := os.WriteFile(path, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Setxattr(path, "user.rufusarm64-test", []byte("metadata"), 0); err != nil {
		if err == syscall.ENOTSUP || err == syscall.EOPNOTSUPP {
			t.Skip("test filesystem does not support extended attributes")
		}
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	if err := requirePortableMetadata(file.Fd(), stat, "FILE.BIN"); err == nil || !strings.Contains(err.Error(), "extended attributes") {
		t.Fatalf("extended-metadata error = %v", err)
	}
}
