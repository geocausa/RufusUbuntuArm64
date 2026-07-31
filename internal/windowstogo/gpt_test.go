//go:build linux

package windowstogo

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"testing"
)

func deterministicRandom() *bytes.Reader {
	data := make([]byte, 48)
	for index := range data {
		data[index] = byte(index + 1)
	}
	return bytes.NewReader(data)
}

func TestBuildGPTCreatesExactPrimaryAndBackupMetadata(t *testing.T) {
	plan, err := BuildPlan(baseRequest())
	if err != nil {
		t.Fatal(err)
	}
	layout, err := BuildGPT(plan, deterministicRandom())
	if err != nil {
		t.Fatal(err)
	}
	if layout.TotalSectors != plan.TargetSizeBytes/512 || layout.BackupHeaderLBA != layout.TotalSectors-1 {
		t.Fatalf("layout geometry=%#v", layout)
	}
	if layout.Partitions[0].FirstLBA != plan.ESP.StartBytes/512 || layout.Partitions[1].FirstLBA != plan.OS.StartBytes/512 {
		t.Fatalf("partition LBAs=%#v", layout.Partitions)
	}
	if layout.Partitions[1].Attributes != uint64(1)<<63 {
		t.Fatalf("OS attributes=%#x", layout.Partitions[1].Attributes)
	}
	if !bytes.Equal(layout.PrimaryEntries, layout.BackupEntries) {
		t.Fatal("primary and backup entry tables differ")
	}
	if binary.LittleEndian.Uint64(layout.PrimaryHeader[24:32]) != 1 || binary.LittleEndian.Uint64(layout.PrimaryHeader[32:40]) != layout.BackupHeaderLBA {
		t.Fatal("primary header current/backup LBA mismatch")
	}
	if binary.LittleEndian.Uint64(layout.BackupHeader[24:32]) != layout.BackupHeaderLBA || binary.LittleEndian.Uint64(layout.BackupHeader[32:40]) != 1 {
		t.Fatal("backup header current/backup LBA mismatch")
	}
	entriesBytes := int(gptEntryCount * gptEntrySize)
	if got := crc32.ChecksumIEEE(layout.PrimaryEntries[:entriesBytes]); got != binary.LittleEndian.Uint32(layout.PrimaryHeader[88:92]) {
		t.Fatalf("entries CRC=%#x", got)
	}
	if layout.ProtectiveMBR[446+4] != 0xee || binary.LittleEndian.Uint32(layout.ProtectiveMBR[446+8:446+12]) != 1 {
		t.Fatal("protective MBR partition is invalid")
	}
}

func TestBuildGPTSupportsFourKilobyteSectors(t *testing.T) {
	request := baseRequest()
	request.LogicalSectorSize = 4096
	plan, err := BuildPlan(request)
	if err != nil {
		t.Fatal(err)
	}
	layout, err := BuildGPT(plan, deterministicRandom())
	if err != nil {
		t.Fatal(err)
	}
	if len(layout.PrimaryHeader) != 4096 || len(layout.ProtectiveMBR) != 4096 || layout.PrimaryEntriesLBA != 2 {
		t.Fatalf("4 KiB layout=%#v", layout)
	}
	if layout.FirstUsableLBA != 6 {
		t.Fatalf("first usable LBA=%d, want 6", layout.FirstUsableLBA)
	}
}

func TestValidateGPTRejectsCorruption(t *testing.T) {
	plan, err := BuildPlan(baseRequest())
	if err != nil {
		t.Fatal(err)
	}
	layout, err := BuildGPT(plan, deterministicRandom())
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*GPTLayout){
		"MBR signature": func(g *GPTLayout) { g.ProtectiveMBR[510] = 0 },
		"header CRC":    func(g *GPTLayout) { g.PrimaryHeader[24] ^= 1 },
		"entry table":   func(g *GPTLayout) { g.PrimaryEntries[0] ^= 1 },
		"backup table":  func(g *GPTLayout) { g.BackupEntries[0] ^= 1 },
		"attributes":    func(g *GPTLayout) { g.Partitions[1].Attributes = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			copy := layout
			copy.ProtectiveMBR = append([]byte(nil), layout.ProtectiveMBR...)
			copy.PrimaryHeader = append([]byte(nil), layout.PrimaryHeader...)
			copy.BackupHeader = append([]byte(nil), layout.BackupHeader...)
			copy.PrimaryEntries = append([]byte(nil), layout.PrimaryEntries...)
			copy.BackupEntries = append([]byte(nil), layout.BackupEntries...)
			copy.Partitions = append([]GPTPartition(nil), layout.Partitions...)
			mutate(&copy)
			if err := ValidateGPT(copy, plan); err == nil {
				t.Fatal("corrupted GPT was accepted")
			}
		})
	}
}
