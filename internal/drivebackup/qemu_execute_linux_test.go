//go:build linux

package drivebackup

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConvertContainerPassesOnlyInheritedDescriptors(t *testing.T) {
	directory := t.TempDir()
	arguments := filepath.Join(directory, "arguments")
	script := filepath.Join(directory, "qemu-img")
	body := `#!/bin/sh
set -eu
printf '%s\n' "$@" > "$TEST_ARGUMENTS"
test -r /proc/self/fd/3
test -w /proc/self/fd/4
printf 'container' >&4
printf '(50.00/100%%)\r(100.00/100%%)\r' >&2
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	setTestQEMUResolver(t, script)
	t.Setenv("TEST_ARGUMENTS", arguments)

	sourcePath := filepath.Join(directory, "private-source.raw")
	outputPath := filepath.Join(directory, "private-output.vhdx")
	if err := os.WriteFile(sourcePath, bytes.Repeat([]byte{0x5a}, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	output, err := os.OpenFile(outputPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	var progress []Progress
	if err := ConvertContainer(context.Background(), source, output, 4096, FormatVHDX, func(event Progress) {
		progress = append(progress, event)
	}); err != nil {
		t.Fatal(err)
	}
	if len(progress) < 2 || progress[0].Done != 0 || progress[len(progress)-1].Done != 4096 {
		t.Fatalf("progress=%+v", progress)
	}
	data, err := os.ReadFile(arguments)
	if err != nil {
		t.Fatal(err)
	}
	argumentText := string(data)
	if strings.Contains(argumentText, sourcePath) || strings.Contains(argumentText, outputPath) {
		t.Fatalf("private path leaked to qemu-img: %q", argumentText)
	}
	want := "convert\n-p\n-f\nraw\n-O\nvhdx\n-o\nsubformat=dynamic,block_state_zero=on\n-S\n4k\n/proc/self/fd/3\n/proc/self/fd/4\n"
	if argumentText != want {
		t.Fatalf("arguments=%q want=%q", argumentText, want)
	}
}

func TestDescriptorCommandsPropagateCancellation(t *testing.T) {
	directory := t.TempDir()
	script := filepath.Join(directory, "qemu-img")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexec sleep 30\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	setTestQEMUResolver(t, script)
	source := openTestFile(t, filepath.Join(directory, "source.raw"), []byte("source"))
	defer source.Close()
	output := openTestFile(t, filepath.Join(directory, "output.vhdx"), nil)
	defer output.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := ConvertContainer(ctx, source, output, 6, FormatVHDX, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("conversion cancellation error=%v", err)
	}
}

func TestValidateQEMUJSONObject(t *testing.T) {
	for _, valid := range []string{`{}`, `{"check-errors":0}`} {
		if err := validateQEMUJSONObject([]byte(valid)); err != nil {
			t.Fatalf("valid object %s: %v", valid, err)
		}
	}
	for _, invalid := range []string{"", "[]", "{} {}", "{broken"} {
		if err := validateQEMUJSONObject([]byte(invalid)); err == nil {
			t.Fatalf("invalid object was accepted: %q", invalid)
		}
	}
}

func TestSystemQEMUDescriptorConversionAndComparison(t *testing.T) {
	executable, err := exec.LookPath("qemu-img")
	if err != nil {
		t.Skip("qemu-img unavailable")
	}
	setTestQEMUResolver(t, executable)
	directory := t.TempDir()
	raw := make([]byte, 8*1024*1024)
	copy(raw[0:4096], bytes.Repeat([]byte{0x11}, 4096))
	copy(raw[len(raw)-4096:], bytes.Repeat([]byte{0xee}, 4096))
	sourcePath := filepath.Join(directory, "source.raw")
	if err := os.WriteFile(sourcePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, format := range []Format{FormatVHD, FormatVHDX} {
		t.Run(string(format), func(t *testing.T) {
			source, err := os.Open(sourcePath)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			outputPath := filepath.Join(directory, "output"+format.Extension())
			output, err := os.OpenFile(outputPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			defer output.Close()
			if err := ConvertContainer(context.Background(), source, output, uint64(len(raw)), format, nil); err != nil {
				t.Fatal(err)
			}
			if err := CompareContainer(context.Background(), source, output, format); err != nil {
				t.Fatal(err)
			}
			state, err := CheckContainer(context.Background(), output, format)
			if err != nil {
				t.Fatal(err)
			}
			if format == FormatVHDX && state != ConsistencyPassed {
				t.Fatalf("VHDX consistency=%q", state)
			}
			if format == FormatVHD && state != ConsistencyUnsupported {
				t.Fatalf("VHD consistency=%q", state)
			}
			info, err := output.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if info.Size() <= 0 {
				t.Fatalf("container size=%d", info.Size())
			}
		})
	}
}

func setTestQEMUResolver(t *testing.T, executable string) {
	t.Helper()
	previous := resolveQEMUImg
	resolveQEMUImg = func() (string, error) { return executable, nil }
	t.Cleanup(func() { resolveQEMUImg = previous })
}

func openTestFile(t *testing.T, path string, data []byte) *os.File {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	return file
}
