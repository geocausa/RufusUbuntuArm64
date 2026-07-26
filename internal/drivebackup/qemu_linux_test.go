//go:build linux

package drivebackup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseContainerMeasureStrict(t *testing.T) {
	got, err := parseContainerMeasure([]byte(`{"required":4096,"fully-allocated":8192,"bitmaps":0}`))
	if err != nil {
		t.Fatal(err)
	}
	if got.RequiredBytes != 4096 || got.FullyAllocatedBytes != 8192 {
		t.Fatalf("measure=%+v", got)
	}
	for _, data := range []string{
		`{"required":1,"required":2,"fully-allocated":2}`,
		`{"required":1,"fully-allocated":2,"unknown":0}`,
		`{"required":1.5,"fully-allocated":2}`,
		`{"required":3,"fully-allocated":2}`,
		`{"required":0,"fully-allocated":2}`,
		`{"required":1,"fully-allocated":2} {}`,
		`[]`,
	} {
		if _, err := parseContainerMeasure([]byte(data)); err == nil {
			t.Fatalf("malformed measure was accepted: %s", data)
		}
	}
}

func TestMeasureContainerUsesFixedTrustedArguments(t *testing.T) {
	directory := t.TempDir()
	arguments := filepath.Join(directory, "arguments")
	script := filepath.Join(directory, "qemu-img")
	body := `#!/bin/sh
set -eu
printf '%s\n' "$@" > "$TEST_ARGUMENTS"
printf '{"required":1048576,"fully-allocated":2097152,"bitmaps":0}\n'
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	previous := resolveQEMUImg
	resolveQEMUImg = func() (string, error) { return script, nil }
	t.Cleanup(func() { resolveQEMUImg = previous })
	t.Setenv("TEST_ARGUMENTS", arguments)

	measure, err := MeasureContainer(context.Background(), 8*1024*1024, FormatVHDX)
	if err != nil {
		t.Fatal(err)
	}
	if measure.RequiredBytes != 1048576 || measure.FullyAllocatedBytes != 2097152 {
		t.Fatalf("measure=%+v", measure)
	}
	data, err := os.ReadFile(arguments)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSpace(string(data)), "\n")
	want := []string{"measure", "--output=json", "-O", "vhdx", "-o", "subformat=dynamic,block_state_zero=on", "--size", "8388608"}
	if len(got) != len(want) {
		t.Fatalf("arguments=%q want=%q", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("argument %d=%q want %q; all=%q", index, got[index], want[index], got)
		}
	}
}

func TestMeasureContainerFailsClosed(t *testing.T) {
	previous := resolveQEMUImg
	t.Cleanup(func() { resolveQEMUImg = previous })
	resolveQEMUImg = func() (string, error) { return "", errors.New("unsafe utility") }
	if _, err := MeasureContainer(context.Background(), 1, FormatVHD); err == nil || !strings.Contains(err.Error(), "unsafe utility") {
		t.Fatalf("resolver error=%v", err)
	}
	if _, err := MeasureContainer(context.Background(), 1, FormatRaw); err == nil {
		t.Fatal("raw measurement succeeded")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := MeasureContainer(cancelled, 1, FormatVHD); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled measurement error=%v", err)
	}
}

func TestBoundedCommandBufferRecordsOverflowWithoutShortWrite(t *testing.T) {
	buffer := newBoundedCommandBuffer(4)
	data := []byte("abcdefgh")
	n, err := buffer.Write(data)
	if err != nil || n != len(data) {
		t.Fatalf("write=%d,%v", n, err)
	}
	if !buffer.exceeded || string(buffer.Bytes()) != "abcd" {
		t.Fatalf("buffer exceeded=%t data=%q", buffer.exceeded, buffer.Bytes())
	}
}
