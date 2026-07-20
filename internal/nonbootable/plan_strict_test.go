//go:build linux

package nonbootable

import "testing"

func TestConfirmationRejectsAllCanonicalPlanTampering(t *testing.T) {
	base, err := BuildPlan(baseRequest())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*Plan)
	}{
		{name: "identity whitespace", mutate: func(plan *Plan) { plan.ExpectedIdentity = " " + plan.ExpectedIdentity }},
		{name: "device size", mutate: func(plan *Plan) { plan.DeviceSizeBytes += 512 }},
		{name: "partition start", mutate: func(plan *Plan) { plan.PartitionStartBytes += plan.LogicalSectorSize }},
		{name: "partition size", mutate: func(plan *Plan) { plan.PartitionSizeBytes -= plan.LogicalSectorSize }},
		{name: "partition type", mutate: func(plan *Plan) { plan.PartitionType = "83" }},
		{name: "filesystem display", mutate: func(plan *Plan) { plan.FilesystemDisplay = "FAT" }},
		{name: "tool", mutate: func(plan *Plan) { plan.RequiredTools[0] = "parted" }},
		{name: "warning", mutate: func(plan *Plan) { plan.Warnings[0] = "Formatting may erase data." }},
		{name: "bootable", mutate: func(plan *Plan) { plan.Bootable = true }},
		{name: "non-destructive", mutate: func(plan *Plan) { plan.Destructive = false }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := base
			plan.RequiredTools = append([]string(nil), base.RequiredTools...)
			plan.Warnings = append([]string(nil), base.Warnings...)
			test.mutate(&plan)
			if _, err := ConfirmationPhrase(plan); err == nil {
				t.Fatal("tampered plan was accepted")
			}
		})
	}
}
