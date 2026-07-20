package freedos

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"fmt"
)

const (
	kernelForceLBAOffset = 0x0d
	kernelForceLBAValue  = byte(0x01)

	commandCOMSize         = 87772
	kernelSYSSize          = 46256
	commandCOMSHA256       = "077808379e896476f7f69d62e6c8989d8fc23e8ef58d1c8492db1ac106784107"
	originalKernelSHA256   = "932c0c155701eddb7b902f7269a1b2ce31f5c82a6dc195172f2336d18a74e1fb"
	configuredKernelSHA256 = "57504a0d5e1d57a0407d995e77fcebb9627da2c0dbe0f1cbf7c5fa901d2efc6c"
)

//go:embed payload/COMMAND.COM
var commandCOM []byte

//go:embed payload/KERNL386.SYS
var originalKernelSYS []byte

//go:embed payload/KERNEL.SYS
var configuredKernelSYS []byte

// MinimalPayload contains the two root files required for the reviewed
// English-only FreeDOS shell checkpoint. Returned slices are defensive copies.
type MinimalPayload struct {
	Kernel  []byte
	Command []byte
}

type payloadRecord struct {
	name   string
	data   []byte
	size   int
	sha256 string
}

// ValidatePayloads proves that the embedded bytes match the official FreeDOS
// 1.4 package extraction and that Rufus's configured kernel changes only the
// reviewed FORCELBA byte. It performs no host execution or device operation.
func ValidatePayloads() error {
	return validatePayloadSet(originalKernelSYS, configuredKernelSYS, commandCOM)
}

// PinnedMinimalPayload returns verified defensive copies of KERNEL.SYS and
// COMMAND.COM for future ordinary-file media construction.
func PinnedMinimalPayload() (MinimalPayload, error) {
	if err := ValidatePayloads(); err != nil {
		return MinimalPayload{}, err
	}
	return MinimalPayload{
		Kernel:  append([]byte(nil), configuredKernelSYS...),
		Command: append([]byte(nil), commandCOM...),
	}, nil
}

func validatePayloadSet(originalKernel, configuredKernel, command []byte) error {
	records := []payloadRecord{
		{
			name:   "COMMAND.COM",
			data:   command,
			size:   commandCOMSize,
			sha256: commandCOMSHA256,
		},
		{
			name:   "KERNL386.SYS",
			data:   originalKernel,
			size:   kernelSYSSize,
			sha256: originalKernelSHA256,
		},
		{
			name:   "KERNEL.SYS",
			data:   configuredKernel,
			size:   kernelSYSSize,
			sha256: configuredKernelSHA256,
		},
	}
	for _, record := range records {
		if err := validatePayloadRecord(record); err != nil {
			return err
		}
	}
	originalConfiguration, err := ParseKernelConfiguration(originalKernel)
	if err != nil {
		return fmt.Errorf("original FreeDOS kernel configuration: %w", err)
	}
	if originalConfiguration.ForceLBA != 0 {
		return fmt.Errorf("original FreeDOS kernel has FORCELBA value %#x", originalConfiguration.ForceLBA)
	}
	if err := VerifyPinnedRufusKernel(configuredKernel); err != nil {
		return fmt.Errorf("configured FreeDOS kernel: %w", err)
	}
	if originalKernel[kernelForceLBAOffset] != 0 {
		return fmt.Errorf("original FreeDOS kernel has FORCELBA value %#x", originalKernel[kernelForceLBAOffset])
	}
	if configuredKernel[kernelForceLBAOffset] != kernelForceLBAValue {
		return fmt.Errorf("configured FreeDOS kernel has FORCELBA value %#x", configuredKernel[kernelForceLBAOffset])
	}
	if len(originalKernel) != len(configuredKernel) {
		return fmt.Errorf("kernel derivation changed size from %d to %d", len(originalKernel), len(configuredKernel))
	}
	for offset := range originalKernel {
		if offset == kernelForceLBAOffset {
			continue
		}
		if originalKernel[offset] != configuredKernel[offset] {
			return fmt.Errorf("kernel derivation changed unexpected byte offset %#x", offset)
		}
	}
	return nil
}

func validatePayloadRecord(record payloadRecord) error {
	if len(record.data) != record.size {
		return fmt.Errorf("payload %s has size %d; expected %d", record.name, len(record.data), record.size)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(record.data))
	if digest != record.sha256 {
		return fmt.Errorf("payload %s failed its pinned SHA-256 check", record.name)
	}
	return nil
}

func payloadsEqual(left, right MinimalPayload) bool {
	return bytes.Equal(left.Kernel, right.Kernel) && bytes.Equal(left.Command, right.Command)
}
