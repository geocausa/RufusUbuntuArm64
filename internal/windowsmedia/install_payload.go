//go:build linux

package windowsmedia

import (
	"errors"
	"path/filepath"
	"strings"
)

// InstallPayload is the exact installation-image payload admitted by the
// existing Windows ISO scanner. PrimaryPath is a WIM, ESD, or the first SWM
// part. ReferencePaths contains every split SWM part when Kind is "SWM".
// BootWIMPath and architecture flags are retained so specialized writers can
// independently enforce their own boot and architecture policy.
type InstallPayload struct {
	Kind           string
	PrimaryPath    string
	ReferencePaths []string
	BootWIMPath    string
	Architecture   string
	HasARM64       bool
	HasX64         bool
	HasX86         bool
}

// InspectMountedInstallPayload reuses the bounded, symlink-refusing,
// case-insensitive Windows ISO parser and returns only the installation-image
// facts needed by specialized writers. root must already be a private,
// read-only mount of the selected ISO.
func InspectMountedInstallPayload(root string) (InstallPayload, error) {
	plan, err := inspectMountedISO(root)
	if err != nil {
		return InstallPayload{}, err
	}
	payload := InstallPayload{
		BootWIMPath:  plan.BootWIMPath,
		Architecture: plan.Architecture,
		HasARM64:     plan.HasARM64,
		HasX64:       plan.HasX64,
		HasX86:       plan.HasX86,
	}
	if len(plan.ExistingSplitFiles) != 0 {
		payload.Kind = "SWM"
		payload.PrimaryPath = plan.ExistingSplitFiles[0]
		payload.ReferencePaths = append([]string(nil), plan.ExistingSplitFiles...)
		return payload, nil
	}
	if strings.TrimSpace(plan.InstallPath) == "" {
		return InstallPayload{}, errors.New("windows installation payload path is unavailable")
	}
	switch strings.ToLower(filepath.Ext(plan.InstallPath)) {
	case ".wim":
		payload.Kind = "WIM"
	case ".esd":
		payload.Kind = "ESD"
	default:
		return InstallPayload{}, errors.New("windows installation payload type is unsupported")
	}
	payload.PrimaryPath = plan.InstallPath
	return payload, nil
}
