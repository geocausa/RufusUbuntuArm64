//go:build linux

package windowsmedia

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestCreateInterruptionAfterEachDestructiveBoundary(t *testing.T) {
	makeFixture := func(t *testing.T) (string, string, []byte, Options) {
		t.Helper()
		fixture := t.TempDir()
		writeTestFile(t, filepath.Join(fixture, "sources", "boot.wim"), []byte("boot"))
		writeTestFile(t, filepath.Join(fixture, "sources", "install.wim"), []byte("install"))
		writeTestFile(t, filepath.Join(fixture, "efi", "boot", "bootaa64.efi"), []byte("efi"))
		writeTestFile(t, filepath.Join(fixture, "setup.exe"), []byte("setup"))
		fakeBin := t.TempDir()
		logPath := filepath.Join(t.TempDir(), "commands.log")
		partition := filepath.Join(t.TempDir(), "fake-partition")
		writeTestFile(t, partition, []byte("partition"))
		installFakeTools(t, fakeBin)
		t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
		t.Setenv("RUFUS_TEST_ISO", fixture)
		t.Setenv("RUFUS_TEST_LOG", logPath)
		t.Setenv("RUFUS_TEST_PARTITION", partition)
		iso := fakeISOFile(t)
		target := filepath.Join(t.TempDir(), "fake-device")
		original := bytes.Repeat([]byte{0x5a}, 1024)
		writeTestFile(t, target, original)
		return iso, target, original, Options{
			TargetSize:      8 * 1024 * 1024 * 1024,
			RequireARM64:    true,
			PartitionScheme: "gpt",
			TargetSystem:    "uefi",
			Filesystem:      "fat32",
		}
	}
	targetChanged := func(t *testing.T, path string, original []byte) bool {
		t.Helper()
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() != int64(len(original)) {
			return true
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		prefix := make([]byte, len(original))
		_, err = io.ReadFull(file, prefix)
		if err != nil {
			t.Fatal(err)
		}
		return !bytes.Equal(prefix, original)
	}

	t.Run("pre-destructive refusal leaves target unchanged", func(t *testing.T) {
		iso, target, original, options := makeFixture(t)
		injected := errors.New("injected pre-destructive refusal")
		options.BeforeDestructive = func(*os.File) error { return injected }
		err := Create(context.Background(), iso, target, options, nil)
		if !errors.Is(err, injected) {
			t.Fatalf("error=%v, want injected pre-destructive refusal", err)
		}
		if targetChanged(t, target, original) {
			t.Fatal("pre-destructive refusal changed the target")
		}
	})

	tests := []struct {
		name      string
		configure func(*mutationFaults, error)
	}{
		{"partition", func(faults *mutationFaults, err error) { faults.afterPartition = func() error { return err } }},
		{"format", func(faults *mutationFaults, err error) { faults.afterFormat = func() error { return err } }},
		{"copy", func(faults *mutationFaults, err error) { faults.afterCopy = func() error { return err } }},
		{"sync", func(faults *mutationFaults, err error) { faults.afterSync = func() error { return err } }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			iso, target, original, options := makeFixture(t)
			injected := errors.New("injected " + test.name + " interruption")
			faults := &mutationFaults{}
			test.configure(faults, injected)
			options.faults = faults
			var events []Event
			err := Create(context.Background(), iso, target, options, func(event Event) { events = append(events, event) })
			if !errors.Is(err, injected) {
				t.Fatalf("error=%v, want injected %s interruption", err, test.name)
			}
			if !targetChanged(t, target, original) {
				t.Fatalf("%s interruption did not reach target mutation", test.name)
			}
			for _, event := range events {
				if event.Stage == "complete" {
					t.Fatalf("%s interruption emitted successful completion: %+v", test.name, event)
				}
			}
		})
	}
}
