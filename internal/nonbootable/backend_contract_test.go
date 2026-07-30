//go:build linux

package nonbootable

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestSfdiskReadbackValidation(t *testing.T) {
	plan := executorPlan(t)
	table, err := BuildPartitionTable(plan)
	if err != nil {
		t.Fatal(err)
	}
	document := sfdiskDocument{}
	document.PartitionTable.Label = "gpt"
	document.PartitionTable.Device = plan.DevicePath
	document.PartitionTable.Unit = "sectors"
	document.PartitionTable.SectorSize = plan.LogicalSectorSize
	document.PartitionTable.Partitions = append(document.PartitionTable.Partitions, struct {
		Node  string `json:"node"`
		Start uint64 `json:"start"`
		Size  uint64 `json:"size"`
		Type  string `json:"type"`
		Name  string `json:"name"`
	}{
		Node:  "/dev/sdb1",
		Start: table.StartSector,
		Size:  table.SizeSectors,
		Type:  strings.ToLower(table.PartitionType),
		Name:  "RUFUSARM64-DATA",
	})
	if err := validateSfdiskDocument(document, plan, table); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*sfdiskDocument)
	}{
		{name: "scheme", mutate: func(value *sfdiskDocument) { value.PartitionTable.Label = "dos" }},
		{name: "device", mutate: func(value *sfdiskDocument) { value.PartitionTable.Device = "/dev/sdc" }},
		{name: "sector size", mutate: func(value *sfdiskDocument) { value.PartitionTable.SectorSize = 4096 }},
		{name: "start", mutate: func(value *sfdiskDocument) { value.PartitionTable.Partitions[0].Start++ }},
		{name: "size", mutate: func(value *sfdiskDocument) { value.PartitionTable.Partitions[0].Size-- }},
		{name: "type", mutate: func(value *sfdiskDocument) {
			value.PartitionTable.Partitions[0].Type = "0FC63DAF-8483-4772-8E79-3D69D8477DE4"
		}},
		{name: "name", mutate: func(value *sfdiskDocument) { value.PartitionTable.Partitions[0].Name = "EFI SYSTEM" }},
		{name: "second partition", mutate: func(value *sfdiskDocument) {
			value.PartitionTable.Partitions = append(value.PartitionTable.Partitions, value.PartitionTable.Partitions[0])
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			copy := document
			copy.PartitionTable.Partitions = append([]struct {
				Node  string `json:"node"`
				Start uint64 `json:"start"`
				Size  uint64 `json:"size"`
				Type  string `json:"type"`
				Name  string `json:"name"`
			}(nil), document.PartitionTable.Partitions...)
			test.mutate(&copy)
			if err := validateSfdiskDocument(copy, plan, table); err == nil {
				t.Fatal("altered partition table was accepted")
			}
		})
	}
}

func TestSfdiskJSONAllowsUnrelatedOptionalFields(t *testing.T) {
	payload := `{
		"partitiontable": {
			"label": "gpt",
			"id": "01234567-89AB-CDEF-0123-456789ABCDEF",
			"device": "/dev/sdb",
			"unit": "sectors",
			"firstlba": 2048,
			"lastlba": 16775134,
			"sectorsize": 512,
			"partitions": [{
				"node": "/dev/sdb1",
				"start": 2048,
				"size": 16773120,
				"type": "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7",
				"uuid": "11111111-2222-3333-4444-555555555555",
				"name": "RUFUSARM64-DATA",
				"attrs": ""
			}]
		}
	}`
	var document sfdiskDocument
	if err := json.NewDecoder(bytes.NewBufferString(payload)).Decode(&document); err != nil {
		t.Fatalf("optional sfdisk fields caused parsing failure: %v", err)
	}
	if document.PartitionTable.Partitions[0].Node != "/dev/sdb1" {
		t.Fatal("required partition fields were not decoded")
	}
}

func TestFilesystemCheckCommandsAreReadOnly(t *testing.T) {
	tests := map[string]struct {
		name string
		args string
	}{
		FilesystemFAT16: {name: "fsck.vfat", args: "-n /dev/sdb1"},
		FilesystemFAT32: {name: "fsck.vfat", args: "-n /dev/sdb1"},
		FilesystemExFAT: {name: "fsck.exfat", args: "-n /dev/sdb1"},
		FilesystemNTFS:  {name: "ntfsfix", args: "-n /dev/sdb1"},
		FilesystemExt4:  {name: "e2fsck", args: "-f -n /dev/sdb1"},
	}
	for filesystem, expected := range tests {
		name, args, err := filesystemCheck(filesystem, "/dev/sdb1")
		if err != nil {
			t.Fatal(err)
		}
		if name != expected.name || strings.Join(args, " ") != expected.args {
			t.Fatalf("%s check=%s %v, want %s %s", filesystem, name, args, expected.name, expected.args)
		}
	}
}

func TestDetectFATFilesystemUsesClusterCount(t *testing.T) {
	tests := []struct {
		name              string
		total             uint32
		sectorsPerCluster byte
		reserved          uint16
		fats              byte
		rootEntries       uint16
		fatSectors        uint32
		want              string
		wantErr           bool
	}{
		{name: "fat12 refused", total: 2880, sectorsPerCluster: 1, reserved: 1, fats: 2, rootEntries: 224, fatSectors: 9, wantErr: true},
		{name: "fat16", total: 65536, sectorsPerCluster: 4, reserved: 1, fats: 2, rootEntries: 512, fatSectors: 128, want: FilesystemFAT16},
		{name: "fat32", total: 1_000_000, sectorsPerCluster: 8, reserved: 32, fats: 2, rootEntries: 0, fatSectors: 1000, want: FilesystemFAT32},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			boot := make([]byte, 512)
			binary.LittleEndian.PutUint16(boot[11:13], 512)
			boot[13] = test.sectorsPerCluster
			binary.LittleEndian.PutUint16(boot[14:16], test.reserved)
			boot[16] = test.fats
			binary.LittleEndian.PutUint16(boot[17:19], test.rootEntries)
			if test.total <= 0xffff {
				binary.LittleEndian.PutUint16(boot[19:21], uint16(test.total))
			} else {
				binary.LittleEndian.PutUint32(boot[32:36], test.total)
			}
			if test.rootEntries != 0 {
				binary.LittleEndian.PutUint16(boot[22:24], uint16(test.fatSectors))
			} else {
				binary.LittleEndian.PutUint32(boot[36:40], test.fatSectors)
			}
			path := t.TempDir() + "/fat.img"
			if err := os.WriteFile(path, boot, 0o600); err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			got, err := detectFATFilesystem(file)
			if test.wantErr {
				if err == nil {
					t.Fatalf("got %q, want refusal", got)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("detectFATFilesystem() = %q, %v; want %q", got, err, test.want)
			}
		})
	}
}

func TestPartitionTypeNormalization(t *testing.T) {
	for _, pair := range [][2]string{{"0c", "0c"}, {"c", "0c"}, {"07", "7"}, {"EBD0A0A2-B9E5-4433-87C0-68B6B72699C7", "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"}} {
		if !samePartitionType(pair[0], pair[1]) {
			t.Fatalf("equivalent partition types were rejected: %q %q", pair[0], pair[1])
		}
	}
	if samePartitionType("83", "0c") {
		t.Fatal("different MBR partition types were treated as equal")
	}
}

func TestRunCommandReturnsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := runCommand(ctx, nil, "sh", "-c", "exit 0")
	if err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("cancelled command error=%v", err)
	}
}
