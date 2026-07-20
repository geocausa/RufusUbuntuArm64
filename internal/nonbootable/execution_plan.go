//go:build linux

package nonbootable

import (
	"errors"
	"fmt"
)

const mbrAddressSpaceSectors = uint64(1) << 32

// ValidateExecutionPlan applies destructive-tool representation limits in
// addition to the display-plan contract. It must pass before confirmation and
// again inside the privileged executor.
func ValidateExecutionPlan(plan Plan) error {
	table, err := BuildPartitionTable(plan)
	if err != nil {
		return err
	}
	if table.Scheme == SchemeMBR {
		if table.StartSector >= mbrAddressSpaceSectors || table.SizeSectors == 0 {
			return errors.New("MBR partition geometry is outside its 32-bit sector address space")
		}
		if table.SizeSectors > mbrAddressSpaceSectors-table.StartSector {
			return fmt.Errorf(
				"MBR cannot represent the reviewed partition end sector %d; use GPT for this drive",
				table.StartSector+table.SizeSectors-1,
			)
		}
	}
	return nil
}
