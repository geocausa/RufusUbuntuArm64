//go:build linux

package windowstogo

import (
	"errors"
	"os"
	"testing"
)

func TestWriteGPTPersistsAndReadsBackEveryRegion(t *testing.T) {
	plan, err := BuildPlan(baseRequest())
	if err != nil {
		t.Fatal(err)
	}
	layout, err := BuildGPT(plan, deterministicRandom())
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/disk.img"
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := file.Truncate(int64(plan.TargetSizeBytes)); err != nil {
		t.Fatal(err)
	}
	if err := WriteGPT(file, layout, plan); err != nil {
		t.Fatal(err)
	}
	for _, region := range []gptRegion{
		{name: "backup entries", offset: layout.BackupEntriesLBA * layout.SectorSize, data: layout.BackupEntries},
		{name: "backup header", offset: layout.BackupHeaderLBA * layout.SectorSize, data: layout.BackupHeader},
		{name: "primary entries", offset: layout.PrimaryEntriesLBA * layout.SectorSize, data: layout.PrimaryEntries},
		{name: "primary header", offset: layout.PrimaryHeaderLBA * layout.SectorSize, data: layout.PrimaryHeader},
		{name: "protective MBR", offset: 0, data: layout.ProtectiveMBR},
	} {
		if err := verifyGPTRegion(file, region); err != nil {
			t.Fatal(err)
		}
	}
}

type corruptingGPTDevice struct {
	*os.File
	corruptAfterSync int
	syncs            int
}

func (device *corruptingGPTDevice) Sync() error {
	device.syncs++
	if err := device.File.Sync(); err != nil {
		return err
	}
	if device.syncs == device.corruptAfterSync {
		_, err := device.File.WriteAt([]byte{0xff}, 0)
		return err
	}
	return nil
}

func TestWriteGPTRejectsReadbackCorruption(t *testing.T) {
	plan, err := BuildPlan(baseRequest())
	if err != nil {
		t.Fatal(err)
	}
	layout, err := BuildGPT(plan, deterministicRandom())
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.CreateTemp(t.TempDir(), "disk-*.img")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := file.Truncate(int64(plan.TargetSizeBytes)); err != nil {
		t.Fatal(err)
	}
	device := &corruptingGPTDevice{File: file, corruptAfterSync: 2}
	if err := WriteGPT(device, layout, plan); err == nil || !errors.Is(err, os.ErrInvalid) && err.Error() != "read back protective MBR: content mismatch" {
		if err == nil || err.Error() != "read back protective MBR: content mismatch" {
			t.Fatalf("error=%v, want protective MBR readback mismatch", err)
		}
	}
}
