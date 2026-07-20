package freedos

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestParseKernelConfiguration(t *testing.T) {
	configuration, err := ParseKernelConfiguration(testKernel(1, 6))
	if err != nil {
		t.Fatalf("parse valid kernel configuration: %v", err)
	}
	if configuration.ConfigSize != 6 || configuration.ForceLBA != 1 {
		t.Fatalf("unexpected configuration: %+v", configuration)
	}
}

func TestParseKernelConfigurationRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name   string
		kernel func() []byte
		want   string
	}{
		{"short", func() []byte { return make([]byte, 13) }, "need at least 14"},
		{"entry opcode", func() []byte { value := testKernel(1, 6); value[0] = 0x90; return value }, "short jump opcode"},
		{"signature", func() []byte { value := testKernel(1, 6); value[2] = 'X'; return value }, "CONFIG signature"},
		{"config size", func() []byte { return testKernel(1, 3) }, "requires at least 4"},
		{"non-binary FORCELBA", func() []byte { return testKernel(2, 6) }, "is not binary"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseKernelConfiguration(test.kernel())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected error containing %q, got %v", test.want, err)
			}
		})
	}
}

func TestVerifyPinnedRufusKernelRejectsUnexpectedConfigurationBeforeIdentity(t *testing.T) {
	err := VerifyPinnedRufusKernel(testKernel(0, 6))
	if err == nil || !strings.Contains(err.Error(), "expected 0x01") {
		t.Fatalf("expected FORCELBA rejection, got %v", err)
	}
}

func TestVerifyPinnedRufusKernelRejectsUnreviewedBlob(t *testing.T) {
	err := VerifyPinnedRufusKernel(testKernel(1, 6))
	if err == nil || !strings.Contains(err.Error(), "does not match the reviewed Rufus payload") {
		t.Fatalf("expected blob identity rejection, got %v", err)
	}
}

func TestGitBlobSHA1(t *testing.T) {
	if got, want := gitBlobSHA1([]byte("test content\n")), "d670460b4b4aece5915caf5c68d12f560a9fe3e4"; got != want {
		t.Fatalf("Git blob SHA-1 = %s; want %s", got, want)
	}
}

func TestKernelForceLBAOffsetRemainsSourceBacked(t *testing.T) {
	if got := kernelConfigFieldsOffset + kernelForceLBAFieldIndex; got != 0x0d {
		t.Fatalf("FORCELBA offset = 0x%x; want 0x0d", got)
	}
	if PinnedManifest().KernelForceLBAOffset != 0x0d {
		t.Fatal("manifest FORCELBA offset drifted")
	}
}

func testKernel(forceLBA byte, configSize uint16) []byte {
	value := make([]byte, 32)
	value[0], value[1] = kernelShortJumpOpcode, 0x1b
	copy(value[kernelConfigSignatureOffset:], kernelConfigSignature)
	binary.LittleEndian.PutUint16(value[kernelConfigSizeOffset:], configSize)
	value[kernelConfigFieldsOffset+0] = 0
	value[kernelConfigFieldsOffset+1] = 1
	value[kernelConfigFieldsOffset+2] = 2
	value[kernelConfigFieldsOffset+kernelForceLBAFieldIndex] = forceLBA
	value[kernelConfigFieldsOffset+4] = 1
	return value
}
