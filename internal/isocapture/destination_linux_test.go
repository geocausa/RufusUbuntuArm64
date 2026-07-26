//go:build linux

package isocapture

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func TestPrepareISODestinationAndPublishNoReplace(t *testing.T) {
	t.Setenv("PKEXEC_UID", "")
	directory := t.TempDir()
	output := filepath.Join(directory, "capture.iso")
	plan, err := prepareISODestination(output, "/dev/test-source", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Directory.Close()
	if plan.Path != output || plan.Name != "capture.iso" || plan.AvailableBytes < plan.RequiredBytes {
		t.Fatalf("unexpected destination plan: %+v", plan)
	}
	temporary, temporaryName, err := plan.createTemporary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := temporary.Write([]byte("verified ISO")); err != nil {
		t.Fatal(err)
	}
	info, err := temporary.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("temporary permissions = %#o", info.Mode().Perm())
	}
	if err := temporary.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := temporary.Close(); err != nil {
		t.Fatal(err)
	}
	if err := plan.revalidate(); err != nil {
		t.Fatal(err)
	}
	if err := publishISONoReplace(plan.Directory, temporaryName, plan.Name); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "verified ISO" {
		t.Fatalf("published data = %q", data)
	}
}

func TestPublishISONoReplacePreservesExistingFile(t *testing.T) {
	t.Setenv("PKEXEC_UID", "")
	directory := t.TempDir()
	output := filepath.Join(directory, "capture.iso")
	plan, err := prepareISODestination(output, "/dev/test-source", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Directory.Close()
	temporary, temporaryName, err := plan.createTemporary()
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Unlinkat(int(plan.Directory.Fd()), temporaryName)
	if _, err := temporary.Write([]byte("new")); err != nil {
		t.Fatal(err)
	}
	if err := temporary.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := publishISONoReplace(plan.Directory, temporaryName, plan.Name); err == nil {
		t.Fatal("publication replaced an existing destination")
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "existing" {
		t.Fatalf("existing destination changed to %q", data)
	}
}

func TestPrepareISODestinationRejectsUnsafePaths(t *testing.T) {
	t.Setenv("PKEXEC_UID", "")
	directory := t.TempDir()
	realParent := filepath.Join(directory, "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	symlinkParent := filepath.Join(directory, "link")
	if err := os.Symlink(realParent, symlinkParent); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		output string
		device string
		need   uint64
		text   string
	}{
		{name: "relative", output: "capture.iso", device: "/dev/test", need: 1, text: "absolute"},
		{name: "extension", output: filepath.Join(directory, "capture.img"), device: "/dev/test", need: 1, text: ".iso"},
		{name: "source", output: filepath.Join(directory, "capture.iso"), device: "test", need: 1, text: "source-device"},
		{name: "size", output: filepath.Join(directory, "capture.iso"), device: "/dev/test", need: 0, text: "positive"},
		{name: "symlink-parent", output: filepath.Join(symlinkParent, "capture.iso"), device: "/dev/test", need: 1, text: "real directory"},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan, err := prepareISODestination(test.output, test.device, test.need)
			if plan.Directory != nil {
				plan.Directory.Close()
			}
			if err == nil || !strings.Contains(err.Error(), test.text) {
				t.Fatalf("error=%v want text %q", err, test.text)
			}
		})
	}
}

func TestPrepareISODestinationRejectsExistingObject(t *testing.T) {
	t.Setenv("PKEXEC_UID", "")
	directory := t.TempDir()
	output := filepath.Join(directory, "capture.iso")
	if err := os.WriteFile(output, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := prepareISODestination(output, "/dev/test-source", 1)
	if plan.Directory != nil {
		plan.Directory.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing destination error = %v", err)
	}
}

func TestISORenameat2NumberSupportsReleaseArchitectures(t *testing.T) {
	number, err := isoRenameat2Number()
	switch runtime.GOARCH {
	case "amd64", "arm64":
		if err != nil || number == 0 {
			t.Fatalf("renameat2 number=%d error=%v", number, err)
		}
	default:
		if err == nil || !errors.Is(err, syscall.ENOSYS) && !strings.Contains(err.Error(), "unsupported") {
			t.Fatalf("unsupported architecture error = %v", err)
		}
	}
}
