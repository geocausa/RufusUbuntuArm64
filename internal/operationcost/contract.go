package operationcost

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// Contract records the reviewed user-visible work scope of every long-running
// RufusArm64 operation. It is deliberately machine-readable so an ordinary
// creation workflow cannot quietly become target-capacity-scaled again.
type Contract struct {
	Schema           int               `json:"schema"`
	ReviewedUpstream UpstreamReference `json:"reviewed_upstream"`
	ScalingBases     []string          `json:"scaling_bases"`
	Operations       []Operation       `json:"operations"`
}

type UpstreamReference struct {
	Repository string   `json:"repository"`
	Commit     string   `json:"commit"`
	Paths      []string `json:"paths"`
}

type Operation struct {
	ID                         string  `json:"id"`
	Surface                    string  `json:"surface"`
	Classification             string  `json:"classification"`
	Status                     string  `json:"status"`
	TrackingIssue              int     `json:"tracking_issue"`
	UpstreamOperation          string  `json:"upstream_operation"`
	IntentionalLinuxDivergence string  `json:"intentional_linux_divergence"`
	Phases                     []Phase `json:"phases"`
}

type Phase struct {
	Name             string `json:"name"`
	Direction        string `json:"direction"`
	Scaling          string `json:"scaling"`
	Multiplier       int    `json:"multiplier"`
	EnabledByDefault bool   `json:"enabled_by_default"`
}

var (
	commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	idPattern     = regexp.MustCompile(`^[a-z0-9]+(?:_[a-z0-9]+)*$`)
)

var requiredOperations = []string{
	"freedos_create",
	"windows_install",
	"linux_persistent_create",
	"raw_image_write",
	"compressed_image_prepare",
	"virtual_disk_prepare",
	"nonbootable_quick_format",
	"windows_full_format",
	"windows_bad_block_check",
	"check_usb_quick",
	"check_usb_full",
	"save_drive_image",
	"verified_download",
}

var allowedDirections = map[string]struct{}{
	"source_read":     {},
	"target_write":    {},
	"target_read":     {},
	"temporary_write": {},
	"temporary_read":  {},
	"output_write":    {},
	"network_read":    {},
}

var allowedClassifications = map[string]struct{}{
	"ordinary_creation":      {},
	"explicit_maintenance":   {},
	"explicit_qualification": {},
	"imaging":                {},
	"acquisition":            {},
}

var allowedStatuses = map[string]struct{}{
	"conformant": {},
	"audit":      {},
}

// Decode parses one strict contract document and rejects trailing JSON or
// unknown fields before validating its semantic invariants.
func Decode(reader io.Reader) (Contract, error) {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	var contract Contract
	if err := decoder.Decode(&contract); err != nil {
		return Contract{}, fmt.Errorf("decode operation-cost contract: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return Contract{}, fmt.Errorf("operation-cost contract contains trailing JSON")
		}
		return Contract{}, fmt.Errorf("decode trailing operation-cost data: %w", err)
	}
	if err := Validate(contract); err != nil {
		return Contract{}, err
	}
	return contract, nil
}

// Validate enforces the policy boundaries that prevent ordinary creation from
// silently inheriting whole-device qualification work.
func Validate(contract Contract) error {
	if contract.Schema != 1 {
		return fmt.Errorf("operation-cost schema must be 1, got %d", contract.Schema)
	}
	if contract.ReviewedUpstream.Repository != "pbatard/rufus" {
		return fmt.Errorf("reviewed upstream repository must be pbatard/rufus")
	}
	if !commitPattern.MatchString(contract.ReviewedUpstream.Commit) {
		return fmt.Errorf("reviewed upstream commit must be a lowercase 40-character Git object ID")
	}
	if len(contract.ReviewedUpstream.Paths) == 0 {
		return fmt.Errorf("reviewed upstream paths must not be empty")
	}
	for _, path := range contract.ReviewedUpstream.Paths {
		if strings.TrimSpace(path) == "" || strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
			return fmt.Errorf("invalid reviewed upstream path %q", path)
		}
	}

	scaling := make(map[string]struct{}, len(contract.ScalingBases))
	for _, basis := range contract.ScalingBases {
		if !idPattern.MatchString(basis) {
			return fmt.Errorf("invalid scaling basis %q", basis)
		}
		if _, duplicate := scaling[basis]; duplicate {
			return fmt.Errorf("duplicate scaling basis %q", basis)
		}
		scaling[basis] = struct{}{}
	}
	for _, required := range []string{"source_size", "copied_payload", "required_extents", "partition_capacity", "target_capacity"} {
		if _, ok := scaling[required]; !ok {
			return fmt.Errorf("required scaling basis %q is missing", required)
		}
	}

	operations := make(map[string]Operation, len(contract.Operations))
	for _, operation := range contract.Operations {
		if !idPattern.MatchString(operation.ID) {
			return fmt.Errorf("invalid operation ID %q", operation.ID)
		}
		if _, duplicate := operations[operation.ID]; duplicate {
			return fmt.Errorf("duplicate operation ID %q", operation.ID)
		}
		if strings.TrimSpace(operation.Surface) == "" || strings.TrimSpace(operation.UpstreamOperation) == "" || strings.TrimSpace(operation.IntentionalLinuxDivergence) == "" {
			return fmt.Errorf("operation %s must describe its surface, upstream operation, and Linux divergence", operation.ID)
		}
		if operation.TrackingIssue <= 0 {
			return fmt.Errorf("operation %s must name a tracking issue", operation.ID)
		}
		if _, ok := allowedClassifications[operation.Classification]; !ok {
			return fmt.Errorf("operation %s has invalid classification %q", operation.ID, operation.Classification)
		}
		if _, ok := allowedStatuses[operation.Status]; !ok {
			return fmt.Errorf("operation %s has invalid status %q", operation.ID, operation.Status)
		}
		if len(operation.Phases) == 0 {
			return fmt.Errorf("operation %s has no work phases", operation.ID)
		}
		phaseNames := make(map[string]struct{}, len(operation.Phases))
		for _, phase := range operation.Phases {
			if !idPattern.MatchString(phase.Name) {
				return fmt.Errorf("operation %s has invalid phase name %q", operation.ID, phase.Name)
			}
			if _, duplicate := phaseNames[phase.Name]; duplicate {
				return fmt.Errorf("operation %s has duplicate phase %q", operation.ID, phase.Name)
			}
			phaseNames[phase.Name] = struct{}{}
			if _, ok := allowedDirections[phase.Direction]; !ok {
				return fmt.Errorf("operation %s phase %s has invalid direction %q", operation.ID, phase.Name, phase.Direction)
			}
			if _, ok := scaling[phase.Scaling]; !ok {
				return fmt.Errorf("operation %s phase %s uses undeclared scaling basis %q", operation.ID, phase.Name, phase.Scaling)
			}
			if phase.Multiplier <= 0 {
				return fmt.Errorf("operation %s phase %s multiplier must be positive", operation.ID, phase.Name)
			}
			if operation.Classification == "ordinary_creation" && phase.EnabledByDefault &&
				(phase.Direction == "target_write" || phase.Direction == "target_read") &&
				(phase.Scaling == "partition_capacity" || phase.Scaling == "target_capacity") {
				return fmt.Errorf("ordinary creation operation %s must not perform default %s work scaled to %s", operation.ID, phase.Direction, phase.Scaling)
			}
		}
		operations[operation.ID] = operation
	}
	for _, required := range requiredOperations {
		if _, ok := operations[required]; !ok {
			return fmt.Errorf("required operation %q is missing", required)
		}
	}

	if err := requirePhase(operations["freedos_create"], "target_write", "required_extents", true); err != nil {
		return err
	}
	if err := requirePhase(operations["freedos_create"], "target_read", "required_extents", true); err != nil {
		return err
	}
	if err := requireExactPhase(operations["windows_install"], "authenticate_held_iso", "source_read", "source_size", 1, true); err != nil {
		return err
	}
	if err := requireExactPhase(operations["windows_install"], "conservative_fallback_hashes", "source_read", "source_size", 2, false); err != nil {
		return err
	}
	if err := requirePhase(operations["windows_install"], "target_write", "copied_payload", true); err != nil {
		return err
	}
	if err := requireExactPhase(operations["linux_persistent_create"], "authenticate_held_source_image", "source_read", "source_size", 1, true); err != nil {
		return err
	}
	if err := requireExactPhase(operations["linux_persistent_create"], "conservative_fallback_hashes", "source_read", "source_size", 2, false); err != nil {
		return err
	}
	if err := requireExactPhase(operations["raw_image_write"], "bind_source_hash", "source_read", "source_size", 1, true); err != nil {
		return err
	}
	if err := requireExactPhase(operations["raw_image_write"], "write_and_hash_source", "source_read", "source_size", 1, true); err != nil {
		return err
	}
	if err := rejectPhaseName(operations["raw_image_write"], "verification_source_read"); err != nil {
		return err
	}
	if err := requireExactPhase(operations["raw_image_write"], "verification_target_read", "target_read", "source_size", 1, false); err != nil {
		return err
	}
	if err := requirePhase(operations["raw_image_write"], "target_write", "source_size", true); err != nil {
		return err
	}
	if err := requirePhase(operations["check_usb_full"], "target_write", "target_capacity", true); err != nil {
		return err
	}
	if err := requirePhase(operations["check_usb_full"], "target_read", "target_capacity", true); err != nil {
		return err
	}
	if err := requirePhase(operations["save_drive_image"], "target_read", "target_capacity", true); err != nil {
		return err
	}
	if err := requirePhase(operations["save_drive_image"], "output_write", "target_capacity", true); err != nil {
		return err
	}
	return nil
}

func rejectPhaseName(operation Operation, name string) error {
	for _, phase := range operation.Phases {
		if phase.Name == name {
			return fmt.Errorf("operation %s must not contain phase %s", operation.ID, name)
		}
	}
	return nil
}

func requireExactPhase(operation Operation, name, direction, scaling string, multiplier int, enabled bool) error {
	for _, phase := range operation.Phases {
		if phase.Name == name && phase.Direction == direction && phase.Scaling == scaling && phase.Multiplier == multiplier && phase.EnabledByDefault == enabled {
			return nil
		}
	}
	return fmt.Errorf("operation %s must contain phase %s as %s/%s multiplier=%d enabled_by_default=%t", operation.ID, name, direction, scaling, multiplier, enabled)
}

func requirePhase(operation Operation, direction, scaling string, enabled bool) error {
	for _, phase := range operation.Phases {
		if phase.Direction == direction && phase.Scaling == scaling && phase.EnabledByDefault == enabled {
			return nil
		}
	}
	return fmt.Errorf("operation %s must contain a %s/%s phase with enabled_by_default=%t", operation.ID, direction, scaling, enabled)
}
