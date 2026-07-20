package freedos

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedPayloadsAreValid(t *testing.T) {
	if err := ValidatePayloads(); err != nil {
		t.Fatalf("pinned FreeDOS payload is invalid: %v", err)
	}
	payload, err := PinnedMinimalPayload()
	if err != nil {
		t.Fatal(err)
	}
	if len(payload.Kernel) != kernelSYSSize || len(payload.Command) != commandCOMSize {
		t.Fatalf("unexpected payload sizes: kernel=%d command=%d", len(payload.Kernel), len(payload.Command))
	}
}

func TestPayloadRejectsTampering(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(original, configured, command []byte)
	}{
		{
			name: "original kernel",
			mutate: func(original, _, _ []byte) {
				original[0x20] ^= 0xff
			},
		},
		{
			name: "configured kernel",
			mutate: func(_, configured, _ []byte) {
				configured[0x20] ^= 0xff
			},
		},
		{
			name: "FORCELBA",
			mutate: func(_, configured, _ []byte) {
				configured[kernelForceLBAOffset] = 0
			},
		},
		{
			name: "command shell",
			mutate: func(_, _, command []byte) {
				command[len(command)-1] ^= 0xff
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			original := append([]byte(nil), originalKernelSYS...)
			configured := append([]byte(nil), configuredKernelSYS...)
			command := append([]byte(nil), commandCOM...)
			test.mutate(original, configured, command)
			if err := validatePayloadSet(original, configured, command); err == nil {
				t.Fatal("tampered payload was accepted")
			}
		})
	}
}

func TestKernelDerivationChangesOnlyFORCELBA(t *testing.T) {
	if originalKernelSYS[kernelForceLBAOffset] != 0 {
		t.Fatalf("original FORCELBA value is %#x", originalKernelSYS[kernelForceLBAOffset])
	}
	if configuredKernelSYS[kernelForceLBAOffset] != kernelForceLBAValue {
		t.Fatalf("configured FORCELBA value is %#x", configuredKernelSYS[kernelForceLBAOffset])
	}
	for offset := range originalKernelSYS {
		if offset == kernelForceLBAOffset {
			continue
		}
		if originalKernelSYS[offset] != configuredKernelSYS[offset] {
			t.Fatalf("unexpected kernel difference at %#x", offset)
		}
	}
}

func TestPinnedPayloadReturnsDefensiveCopies(t *testing.T) {
	first, err := PinnedMinimalPayload()
	if err != nil {
		t.Fatal(err)
	}
	second, err := PinnedMinimalPayload()
	if err != nil {
		t.Fatal(err)
	}
	if !payloadsEqual(first, second) {
		t.Fatal("fresh payload copies differ")
	}
	first.Kernel[0] ^= 0xff
	first.Command[0] ^= 0xff
	if payloadsEqual(first, second) {
		t.Fatal("mutating a returned payload changed another copy")
	}
	third, err := PinnedMinimalPayload()
	if err != nil {
		t.Fatal(err)
	}
	if !payloadsEqual(second, third) {
		t.Fatal("mutating a returned payload changed embedded bytes")
	}
}

func TestPayloadManifestMatchesGoContract(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "vendor", "freedos", "PAYLOADS.json"))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Archive struct {
			SHA256 string `json:"sha256"`
		} `json:"archive"`
		Files map[string]struct {
			Size       int    `json:"size"`
			SHA256     string `json:"sha256"`
			GitBlobSHA string `json:"git_blob_sha1"`
		} `json:"files"`
		KernelPatch struct {
			Offset        int  `json:"offset"`
			OriginalValue byte `json:"original_value"`
			PatchedValue  byte `json:"patched_value"`
			Preserved     bool `json:"all_other_bytes_preserved"`
		} `json:"kernel_patch"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Archive.SHA256 != PinnedManifest().FullUSBArchiveSHA256 {
		t.Fatal("payload and feasibility archive hashes differ")
	}
	for name, expected := range map[string]struct {
		size   int
		sha256 string
		blob   string
	}{
		"COMMAND.COM": {commandCOMSize, commandCOMSHA256, PinnedManifest().RufusCommandBlobSHA1},
		"KERNEL.SYS":  {kernelSYSSize, configuredKernelSHA256, PinnedManifest().RufusKernelBlobSHA1},
	} {
		record, ok := manifest.Files[name]
		if !ok {
			t.Fatalf("manifest is missing %s", name)
		}
		if record.Size != expected.size || record.SHA256 != expected.sha256 || record.GitBlobSHA != expected.blob {
			t.Fatalf("manifest record for %s differs from Go contract", name)
		}
	}
	if manifest.KernelPatch.Offset != kernelForceLBAOffset ||
		manifest.KernelPatch.OriginalValue != 0 ||
		manifest.KernelPatch.PatchedValue != kernelForceLBAValue ||
		!manifest.KernelPatch.Preserved {
		t.Fatal("kernel patch manifest differs from Go contract")
	}
	if bytes.Equal(originalKernelSYS, configuredKernelSYS) {
		t.Fatal("configured kernel unexpectedly equals the original")
	}
}
