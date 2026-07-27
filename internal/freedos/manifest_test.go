package freedos

import "testing"

func TestPinnedManifestIsValid(t *testing.T) {
	if err := ValidateManifest(PinnedManifest()); err != nil {
		t.Fatalf("pinned manifest is invalid: %v", err)
	}
}

func TestManifestRejectsTampering(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{"target CPU", func(value *Manifest) { value.TargetCPU = "arm64" }},
		{"firmware", func(value *Manifest) { value.Firmware = "UEFI" }},
		{"host execution", func(value *Manifest) { value.HostExecutionRequired = true }},
		{"archive hash", func(value *Manifest) { value.LiteUSBArchiveSHA256 = "0" + value.LiteUSBArchiveSHA256[1:] }},
		{"reference commit", func(value *Manifest) { value.RufusReferenceCommit = "0" + value.RufusReferenceCommit[1:] }},
		{"kernel blob", func(value *Manifest) { value.RufusKernelBlobSHA1 = "0" + value.RufusKernelBlobSHA1[1:] }},
		{"FORCELBA offset", func(value *Manifest) { value.KernelForceLBAOffset++ }},
		{"root files", func(value *Manifest) { value.RequiredRootFiles[0] = "IO.SYS" }},
		{"warnings", func(value *Manifest) { value.SafetyWarnings = value.SafetyWarnings[:2] }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := PinnedManifest()
			test.mutate(&value)
			if err := ValidateManifest(value); err == nil {
				t.Fatal("tampered manifest was accepted")
			}
		})
	}
}

func TestFeasibilityGateDoesNotAuthorizeImplementation(t *testing.T) {
	value := PinnedManifest()
	if value.HostExecutionRequired {
		t.Fatal("the ARM64 host must never execute the x86 FreeDOS payload")
	}
	if value.TargetCPU != "x86" || value.Firmware != "BIOS or UEFI Legacy/CSM" {
		t.Fatal("FreeDOS target limitations must remain explicit")
	}
}
