package freedos

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

const ManifestSchema = 1

// Manifest records the immutable upstream evidence for the FreeDOS feasibility
// gate. It authorizes no device operation and contains no executable payload.
type Manifest struct {
	Schema                 int      `json:"schema"`
	Distribution           string   `json:"distribution"`
	Version                string   `json:"version"`
	TargetCPU              string   `json:"target_cpu"`
	Firmware               string   `json:"firmware"`
	HostExecutionRequired  bool     `json:"host_execution_required"`
	FullUSBArchiveSHA256   string   `json:"full_usb_archive_sha256"`
	LiteUSBArchiveSHA256   string   `json:"lite_usb_archive_sha256"`
	RufusReferenceCommit   string   `json:"rufus_reference_commit"`
	KernelSourceCommit     string   `json:"kernel_source_commit"`
	FreeCOMSourceCommit    string   `json:"freecom_source_commit"`
	RufusKernelBlobSHA1    string   `json:"rufus_kernel_blob_sha1"`
	RufusCommandBlobSHA1   string   `json:"rufus_command_blob_sha1"`
	KernelForceLBAOffset   uint64   `json:"kernel_force_lba_offset"`
	KernelForceLBAValue    byte     `json:"kernel_force_lba_value"`
	RequiredRootFiles      []string `json:"required_root_files"`
	SafetyWarnings         []string `json:"safety_warnings"`
}

// PinnedManifest returns the evidence reviewed for the first feasibility
// checkpoint. Archive hashes come from the official FreeDOS 1.4 verification
// file. Git object IDs pin the source and Rufus reference used for analysis.
func PinnedManifest() Manifest {
	return Manifest{
		Schema:                ManifestSchema,
		Distribution:          "FreeDOS",
		Version:               "1.4",
		TargetCPU:             "x86",
		Firmware:              "BIOS or UEFI Legacy/CSM",
		HostExecutionRequired: false,
		FullUSBArchiveSHA256:  "cd440cd165f5a8a184870cb615f525af182660c15f9bcf1e9d198ca19cedcaff",
		LiteUSBArchiveSHA256:  "857dcd2ebf9d3d094320154db5fb5b830acba6fb98f981a95a0ca7ab3350338b",
		RufusReferenceCommit:  "6d8fbf98305ff37eb531c45cbd6ff44563c53917",
		KernelSourceCommit:    "d6791add2043c9d7b584d840a8ffaf8829fd2bdc",
		FreeCOMSourceCommit:   "04fc21a9f6792abe9048598e8f2d048b4f6cd0e5",
		RufusKernelBlobSHA1:   "6b524a99481f2286a5ddcb06c4fbccfe2bc5cfbd",
		RufusCommandBlobSHA1:  "255525acc562e0411e3e5f000bc1ba788733056d",
		KernelForceLBAOffset:  0x0d,
		KernelForceLBAValue:   0x01,
		RequiredRootFiles:     []string{"KERNEL.SYS", "COMMAND.COM"},
		SafetyWarnings: []string{
			"FreeDOS runs only on x86-compatible processors.",
			"The media requires BIOS or UEFI Legacy/CSM firmware and is not for UEFI-only systems.",
			"Software verification cannot prove that a particular physical PC will boot the media.",
		},
	}
}

// ValidateManifest rejects plausible but altered provenance or platform claims.
func ValidateManifest(manifest Manifest) error {
	canonical := PinnedManifest()
	if manifest.Schema != ManifestSchema || manifest.Distribution != canonical.Distribution || manifest.Version != canonical.Version {
		return errors.New("unsupported FreeDOS feasibility manifest")
	}
	if manifest.TargetCPU != canonical.TargetCPU || manifest.Firmware != canonical.Firmware || manifest.HostExecutionRequired {
		return errors.New("FreeDOS platform boundary was altered")
	}
	for name, value := range map[string]string{
		"FullUSB SHA-256": manifest.FullUSBArchiveSHA256,
		"LiteUSB SHA-256": manifest.LiteUSBArchiveSHA256,
	} {
		if !validHex(value, 64) {
			return fmt.Errorf("%s is invalid", name)
		}
	}
	for name, value := range map[string]string{
		"Rufus commit":       manifest.RufusReferenceCommit,
		"kernel commit":      manifest.KernelSourceCommit,
		"FreeCOM commit":     manifest.FreeCOMSourceCommit,
		"Rufus kernel blob":  manifest.RufusKernelBlobSHA1,
		"Rufus command blob": manifest.RufusCommandBlobSHA1,
	} {
		if !validHex(value, 40) {
			return fmt.Errorf("%s is invalid", name)
		}
	}
	if manifest.FullUSBArchiveSHA256 != canonical.FullUSBArchiveSHA256 ||
		manifest.LiteUSBArchiveSHA256 != canonical.LiteUSBArchiveSHA256 ||
		manifest.RufusReferenceCommit != canonical.RufusReferenceCommit ||
		manifest.KernelSourceCommit != canonical.KernelSourceCommit ||
		manifest.FreeCOMSourceCommit != canonical.FreeCOMSourceCommit ||
		manifest.RufusKernelBlobSHA1 != canonical.RufusKernelBlobSHA1 ||
		manifest.RufusCommandBlobSHA1 != canonical.RufusCommandBlobSHA1 {
		return errors.New("FreeDOS provenance does not match the reviewed manifest")
	}
	if manifest.KernelForceLBAOffset != canonical.KernelForceLBAOffset || manifest.KernelForceLBAValue != canonical.KernelForceLBAValue {
		return errors.New("FreeDOS kernel configuration contract was altered")
	}
	if !slices.Equal(manifest.RequiredRootFiles, canonical.RequiredRootFiles) || !slices.Equal(manifest.SafetyWarnings, canonical.SafetyWarnings) {
		return errors.New("FreeDOS file or warning contract was altered")
	}
	return nil
}

func validHex(value string, length int) bool {
	if len(value) != length || strings.ToLower(value) != value {
		return false
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}
