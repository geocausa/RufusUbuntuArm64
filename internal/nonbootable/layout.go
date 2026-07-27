//go:build linux

package nonbootable

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// PartitionTable is the exact destructive layout derived from a reviewed Plan.
// Values are expressed in logical sectors because that is the unit accepted and
// reported by sfdisk. No caller-provided geometry is accepted here.
type PartitionTable struct {
	Schema            int    `json:"schema"`
	Scheme            string `json:"scheme"`
	DevicePath        string `json:"device_path"`
	SectorSize        uint64 `json:"sector_size"`
	PartitionNumber   int    `json:"partition_number"`
	StartSector       uint64 `json:"start_sector"`
	SizeSectors       uint64 `json:"size_sectors"`
	PartitionType     string `json:"partition_type"`
	Filesystem        string `json:"filesystem"`
	FilesystemDisplay string `json:"filesystem_display"`
	Label             string `json:"label"`
}

// BuildPartitionTable translates only an exact canonical Plan into sector
// geometry. It is deliberately pure so the reviewed dry-run data and the later
// privileged executor cannot disagree about layout arithmetic.
func BuildPartitionTable(plan Plan) (PartitionTable, error) {
	if err := validatePlan(plan); err != nil {
		return PartitionTable{}, err
	}
	if plan.PartitionStartBytes%plan.LogicalSectorSize != 0 || plan.PartitionSizeBytes%plan.LogicalSectorSize != 0 {
		return PartitionTable{}, errors.New("canonical partition geometry is not sector aligned")
	}
	table := PartitionTable{
		Schema:            SchemaVersion,
		Scheme:            plan.Scheme,
		DevicePath:        plan.DevicePath,
		SectorSize:        plan.LogicalSectorSize,
		PartitionNumber:   plan.PartitionNumber,
		StartSector:       plan.PartitionStartBytes / plan.LogicalSectorSize,
		SizeSectors:       plan.PartitionSizeBytes / plan.LogicalSectorSize,
		PartitionType:     plan.PartitionType,
		Filesystem:        plan.Filesystem,
		FilesystemDisplay: plan.FilesystemDisplay,
		Label:             plan.Label,
	}
	if err := validatePartitionTable(table, plan); err != nil {
		return PartitionTable{}, err
	}
	return table, nil
}

// SfdiskScript returns deterministic stdin for sfdisk. The script contains one
// partition only, uses explicit sectors, and never relies on sfdisk defaults.
func SfdiskScript(plan Plan) (string, error) {
	table, err := BuildPartitionTable(plan)
	if err != nil {
		return "", err
	}
	var builder strings.Builder
	builder.WriteString("label: ")
	if table.Scheme == SchemeGPT {
		builder.WriteString("gpt\n")
	} else {
		builder.WriteString("dos\n")
	}
	builder.WriteString("unit: sectors\n\n")
	builder.WriteString("start=")
	builder.WriteString(strconv.FormatUint(table.StartSector, 10))
	builder.WriteString(", size=")
	builder.WriteString(strconv.FormatUint(table.SizeSectors, 10))
	builder.WriteString(", type=")
	builder.WriteString(table.PartitionType)
	if table.Scheme == SchemeGPT {
		builder.WriteString(", name=RUFUSARM64-DATA")
	}
	builder.WriteByte('\n')
	return builder.String(), nil
}

func validatePartitionTable(table PartitionTable, plan Plan) error {
	if table.Schema != SchemaVersion || table.DevicePath != plan.DevicePath || table.SectorSize != plan.LogicalSectorSize {
		return errors.New("partition table does not match the reviewed device contract")
	}
	if table.Scheme != plan.Scheme || table.PartitionNumber != 1 || table.PartitionType != plan.PartitionType {
		return errors.New("partition table does not match the reviewed partition contract")
	}
	if table.StartSector == 0 || table.SizeSectors == 0 {
		return errors.New("partition table has empty geometry")
	}
	if table.StartSector > ^uint64(0)-table.SizeSectors {
		return errors.New("partition table sector range overflows")
	}
	endExclusive := table.StartSector + table.SizeSectors
	deviceSectors := plan.DeviceSizeBytes / plan.LogicalSectorSize
	if endExclusive > deviceSectors {
		return fmt.Errorf("partition table exceeds the device: end=%d sectors device=%d sectors", endExclusive, deviceSectors)
	}
	if table.Scheme == SchemeMBR && endExclusive > mbrAddressSpaceSectors {
		return fmt.Errorf("MBR cannot represent the reviewed partition end sector %d; use GPT for this drive", endExclusive-1)
	}
	if table.Filesystem != plan.Filesystem || table.FilesystemDisplay != plan.FilesystemDisplay || table.Label != plan.Label {
		return errors.New("partition table does not match the reviewed filesystem contract")
	}
	return nil
}
