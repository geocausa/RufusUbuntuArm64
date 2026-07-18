package secureboot

// Exported PE/COFF constants used by audited media-tree transformations.
const (
	MachineARM64            = imageFileMachineARM64
	SubsystemEFIApplication = imageSubsystemEFIApp
)

// EFIImageInfo is the bounded structural result for one in-memory EFI image.
// It does not establish signature trust or firmware bootability.
type EFIImageInfo struct {
	Machine       uint16          `json:"machine"`
	MachineName   string          `json:"machine_name"`
	Subsystem     uint16          `json:"subsystem"`
	SubsystemName string          `json:"subsystem_name"`
	SBAT          []SBATComponent `json:"sbat,omitempty"`
}

// InspectEFIImage parses the same bounded PE/COFF and SBAT structures used by
// media validation without opening a pathname or consulting firmware policy.
func InspectEFIImage(data []byte) (EFIImageInfo, error) {
	parsed, err := parseUEFIImage(data)
	if err != nil {
		return EFIImageInfo{}, err
	}
	return EFIImageInfo{
		Machine:       parsed.machine,
		MachineName:   uefiMachineName(parsed.machine),
		Subsystem:     parsed.subsystem,
		SubsystemName: uefiSubsystemName(parsed.subsystem),
		SBAT:          parsed.sbat,
	}, nil
}
