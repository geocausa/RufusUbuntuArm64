package freedos

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
)

const (
	kernelShortJumpOpcode       = 0xeb
	kernelConfigSignatureOffset = 2
	kernelConfigSignatureSize   = 6
	kernelConfigSizeOffset      = kernelConfigSignatureOffset + kernelConfigSignatureSize
	kernelConfigFieldsOffset    = kernelConfigSizeOffset + 2
	kernelForceLBAFieldIndex    = 3
	kernelMinimumConfigSize     = kernelForceLBAFieldIndex + 1
)

var kernelConfigSignature = []byte("CONFIG")

// KernelConfiguration is the source-backed subset of the configuration area
// at the beginning of KERNEL.SYS that is needed by the FreeDOS feasibility gate.
type KernelConfiguration struct {
	ConfigSize uint16
	ForceLBA   byte
}

// ParseKernelConfiguration validates the documented FreeDOS CONFIG header and
// returns the FORCELBA setting without executing or modifying the x86 payload.
func ParseKernelConfiguration(kernel []byte) (KernelConfiguration, error) {
	manifest := PinnedManifest()
	forceLBAOffset := kernelConfigFieldsOffset + kernelForceLBAFieldIndex
	if manifest.KernelForceLBAOffset != uint64(forceLBAOffset) {
		return KernelConfiguration{}, fmt.Errorf("pinned FORCELBA offset 0x%x does not match the source-backed layout 0x%x", manifest.KernelForceLBAOffset, forceLBAOffset)
	}
	if len(kernel) <= forceLBAOffset {
		return KernelConfiguration{}, fmt.Errorf("FreeDOS kernel has %d bytes; need at least %d for the CONFIG header", len(kernel), forceLBAOffset+1)
	}
	if kernel[0] != kernelShortJumpOpcode {
		return KernelConfiguration{}, fmt.Errorf("FreeDOS kernel does not begin with the expected short jump opcode")
	}
	if !bytes.Equal(kernel[kernelConfigSignatureOffset:kernelConfigSizeOffset], kernelConfigSignature) {
		return KernelConfiguration{}, fmt.Errorf("FreeDOS kernel CONFIG signature is missing at offset 0x%x", kernelConfigSignatureOffset)
	}
	configSize := binary.LittleEndian.Uint16(kernel[kernelConfigSizeOffset:kernelConfigFieldsOffset])
	if configSize < kernelMinimumConfigSize {
		return KernelConfiguration{}, fmt.Errorf("FreeDOS kernel CONFIG area has size %d; FORCELBA requires at least %d bytes", configSize, kernelMinimumConfigSize)
	}
	forceLBA := kernel[forceLBAOffset]
	if forceLBA > 1 {
		return KernelConfiguration{}, fmt.Errorf("FreeDOS kernel FORCELBA value 0x%02x is not binary", forceLBA)
	}
	return KernelConfiguration{ConfigSize: configSize, ForceLBA: forceLBA}, nil
}

// VerifyPinnedRufusKernel requires the exact reviewed Rufus KERNEL.SYS Git blob
// and the source-backed FORCELBA=1 configuration. It performs no host execution
// and does not authorize copying the payload to a device.
func VerifyPinnedRufusKernel(kernel []byte) error {
	configuration, err := ParseKernelConfiguration(kernel)
	if err != nil {
		return err
	}
	manifest := PinnedManifest()
	if configuration.ForceLBA != manifest.KernelForceLBAValue {
		return fmt.Errorf("FreeDOS kernel FORCELBA value is 0x%02x; expected 0x%02x", configuration.ForceLBA, manifest.KernelForceLBAValue)
	}
	if digest := gitBlobSHA1(kernel); digest != manifest.RufusKernelBlobSHA1 {
		return fmt.Errorf("FreeDOS kernel Git blob SHA-1 %s does not match the reviewed Rufus payload", digest)
	}
	return nil
}

func gitBlobSHA1(data []byte) string {
	digest := sha1.New()
	fmt.Fprintf(digest, "blob %d\x00", len(data))
	_, _ = digest.Write(data)
	return fmt.Sprintf("%x", digest.Sum(nil))
}
