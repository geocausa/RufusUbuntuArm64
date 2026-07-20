package freedos

import (
	"bytes"
	"crypto/sha1" // #nosec G505 -- required only for immutable Git blob identity
	"crypto/sha256"
	_ "embed"
	"fmt"
)

const (
	commandCOMSize             = 87772
	kernelSYSSize              = 46256
	commandCOMSHA256           = "077808379e896476f7f69d62e6c8989d8fc23e8ef58d1c8492db1ac106784107"
	commandCOMGitBlobSHA1      = "255525acc562e0411e3e5f000bc1ba788733056d"
	originalKernelSHA256       = "932c0c155701eddb7b902f7269a1b2ce31f5c82a6dc195172f2336d18a74e1fb"
	originalKernelGitBlobSHA1  = "bfe7cdfe616dc71ded366bc57fa8c370a548faa6"
	configuredKernelSHA256     = "57504a0d5e1d57a0407d995e77fcebb9627da2c0dbe0f1cbf7c5fa901d2efc6c"
	configuredKernelGitBlobSHA1 = "6b524a99481f2286a5ddcb06c4fbccfe2bc5cfbd"
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
	name       string
	data       []byte
	size       int
	sha256     string
	gitBlobSHA string
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
			name:       "COMMAND.COM",
			data:       command,
			size:       commandCOMSize,
			sha256:     commandCOMSHA256,
			gitBlobSHA: commandCOMGitBlobSHA1,
		},
		{
			name:       "KERNL386.SYS",
			data:       originalKernel,
			size:       kernelSYSSize,
			sha256:     originalKernelSHA256,
			gitBlobSHA: originalKernelGitBlobSHA1,
		},
		{
			name:       "KERNEL.SYS",
			data:       configuredKernel,
			size:       kernelSYSSize,
			sha256:     configuredKernelSHA256,
			gitBlobSHA: configuredKernelGitBlobSHA1,
		},
	}
	for _, record := range records {
		if err := validatePayloadRecord(record); err != nil {
			return err
		}
	}
	if originalKernel[KernelForceLBAOffset] != 0 {
		return fmt.Errorf("original FreeDOS kernel has FORCELBA value %#x", originalKernel[KernelForceLBAOffset])
	}
	if configuredKernel[KernelForceLBAOffset] != KernelForceLBAValue {
		return fmt.Errorf("configured FreeDOS kernel has FORCELBA value %#x", configuredKernel[KernelForceLBAOffset])
	}
	if len(originalKernel) != len(configuredKernel) {
		return fmt.Errorf("FreeDOS kernel derivation changed size from %d to %d", len(originalKernel), len(configuredKernel))
	}
	for offset := range originalKernel {
		if offset == int(KernelForceLBAOffset) {
			continue
		}
		if originalKernel[offset] != configuredKernel[offset] {
			return fmt.Errorf("FreeDOS kernel derivation changed unexpected byte offset %#x", offset)
		}
	}
	return nil
}

func validatePayloadRecord(record payloadRecord) error {
	if len(record.data) != record.size {
		return fmt.Errorf("%s has size %d; expected %d", record.name, len(record.data), record.size)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(record.data))
	if digest != record.sha256 {
		return fmt.Errorf("%s failed its pinned SHA-256 check", record.name)
	}
	header := []byte(fmt.Sprintf("blob %d\x00", len(record.data)))
	object := sha1.Sum(append(header, record.data...)) // #nosec G401 -- Git object identity, not security
	if fmt.Sprintf("%x", object) != record.gitBlobSHA {
		return fmt.Errorf("%s failed its pinned Git blob check", record.name)
	}
	return nil
}

func payloadsEqual(left, right MinimalPayload) bool {
	return bytes.Equal(left.Kernel, right.Kernel) && bytes.Equal(left.Command, right.Command)
}
