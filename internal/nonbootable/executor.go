//go:build linux

package nonbootable

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const (
	StatusPassed    = "passed"
	StatusFailed    = "failed"
	StatusCancelled = "cancelled"

	PhasePreflight = "preflight"
	PhaseErase     = "erase"
	PhasePartition = "partition"
	PhaseFormat    = "format"
	PhaseVerify    = "verify"
	PhaseComplete  = "complete"
)

// FilesystemState is read back from the freshly created partition. Empty UUIDs
// are permitted only when the filesystem tooling does not publish one.
type FilesystemState struct {
	Path       string `json:"path"`
	Type       string `json:"type"`
	Label      string `json:"label,omitempty"`
	UUID       string `json:"uuid,omitempty"`
	SizeBytes  uint64 `json:"size_bytes"`
	ReadOnly   bool   `json:"read_only"`
	ParentPath string `json:"parent_path"`
}

// Failure is always present for failed and cancelled reports and never present
// for a successful report.
type Failure struct {
	Phase        string `json:"phase"`
	Message      string `json:"message"`
	MediaChanged bool   `json:"media_changed"`
}

// Report is the deterministic schema returned by the dedicated formatter.
type Report struct {
	Schema       int              `json:"schema"`
	Mode         string           `json:"mode"`
	Status       string           `json:"status"`
	Plan         Plan             `json:"plan"`
	Table        PartitionTable   `json:"partition_table"`
	Filesystem   *FilesystemState `json:"filesystem,omitempty"`
	StartedAt    string           `json:"started_at"`
	CompletedAt  string           `json:"completed_at"`
	MediaChanged bool             `json:"media_changed"`
	Reusable     bool             `json:"reusable"`
	Bootable     bool             `json:"bootable"`
	Failure      *Failure         `json:"failure,omitempty"`
}

// Backend owns every privileged operation. Execute validates all data before it
// calls Prepare and enforces the irreversible phase ordering around it.
type Backend interface {
	Prepare(context.Context, Plan, PartitionTable) error
	Erase(context.Context, Plan, PartitionTable) error
	Partition(context.Context, Plan, PartitionTable, string) (string, error)
	Format(context.Context, Plan, PartitionTable, string) error
	Verify(context.Context, Plan, PartitionTable, string) (FilesystemState, error)
	Finish(context.Context, Plan, PartitionTable, FilesystemState) error
}

// Execute applies a reviewed plan through a narrow backend. Cancellation is
// checked before each phase. Once Erase succeeds the report always states that
// media changed, even when a later phase fails or is cancelled.
func Execute(ctx context.Context, plan Plan, backend Backend, now func() time.Time) (Report, error) {
	if backend == nil {
		return Report{}, errors.New("formatter backend is required")
	}
	if now == nil {
		now = time.Now
	}
	table, err := BuildPartitionTable(plan)
	if err != nil {
		return Report{}, err
	}
	started := now().UTC()
	report := Report{
		Schema:      SchemaVersion,
		Mode:        Mode,
		Status:      StatusFailed,
		Plan:        plan,
		Table:       table,
		StartedAt:   started.Format(time.RFC3339Nano),
		CompletedAt: started.Format(time.RFC3339Nano),
		Bootable:    false,
	}
	finishFailure := func(status, phase string, mediaChanged bool, failure error) (Report, error) {
		completed := now().UTC()
		report.Status = status
		report.CompletedAt = completed.Format(time.RFC3339Nano)
		report.MediaChanged = mediaChanged
		report.Reusable = false
		report.Failure = &Failure{Phase: phase, Message: failure.Error(), MediaChanged: mediaChanged}
		if err := ValidateReport(report); err != nil {
			return Report{}, errors.Join(failure, fmt.Errorf("build formatter report: %w", err))
		}
		return report, failure
	}
	checkCancelled := func(phase string, changed bool) (Report, error, bool) {
		if err := ctx.Err(); err != nil {
			wrapped := fmt.Errorf("formatting cancelled during %s: %w", phase, err)
			out, failure := finishFailure(StatusCancelled, phase, changed, wrapped)
			return out, failure, true
		}
		return Report{}, nil, false
	}

	if out, failure, cancelled := checkCancelled(PhasePreflight, false); cancelled {
		return out, failure
	}
	if err := backend.Prepare(ctx, plan, table); err != nil {
		return finishFailure(StatusFailed, PhasePreflight, false, fmt.Errorf("prepare formatter: %w", err))
	}
	if out, failure, cancelled := checkCancelled(PhaseErase, false); cancelled {
		return out, failure
	}
	if err := backend.Erase(ctx, plan, table); err != nil {
		return finishFailure(StatusFailed, PhaseErase, false, fmt.Errorf("erase old signatures: %w", err))
	}
	mediaChanged := true
	if out, failure, cancelled := checkCancelled(PhasePartition, mediaChanged); cancelled {
		return out, failure
	}
	script, err := SfdiskScript(plan)
	if err != nil {
		return finishFailure(StatusFailed, PhasePartition, mediaChanged, fmt.Errorf("build partition table: %w", err))
	}
	partitionPath, err := backend.Partition(ctx, plan, table, script)
	if err != nil {
		return finishFailure(StatusFailed, PhasePartition, mediaChanged, fmt.Errorf("publish partition table: %w", err))
	}
	if partitionPath == "" {
		return finishFailure(StatusFailed, PhasePartition, mediaChanged, errors.New("partition backend returned an empty path"))
	}
	if out, failure, cancelled := checkCancelled(PhaseFormat, mediaChanged); cancelled {
		return out, failure
	}
	if err := backend.Format(ctx, plan, table, partitionPath); err != nil {
		return finishFailure(StatusFailed, PhaseFormat, mediaChanged, fmt.Errorf("create filesystem: %w", err))
	}
	if out, failure, cancelled := checkCancelled(PhaseVerify, mediaChanged); cancelled {
		return out, failure
	}
	filesystem, err := backend.Verify(ctx, plan, table, partitionPath)
	if err != nil {
		return finishFailure(StatusFailed, PhaseVerify, mediaChanged, fmt.Errorf("verify filesystem: %w", err))
	}
	report.Filesystem = &filesystem
	if err := backend.Finish(ctx, plan, table, filesystem); err != nil {
		return finishFailure(StatusFailed, PhaseVerify, mediaChanged, fmt.Errorf("finalize filesystem: %w", err))
	}
	report.Status = StatusPassed
	report.CompletedAt = now().UTC().Format(time.RFC3339Nano)
	report.MediaChanged = true
	report.Reusable = true
	report.Failure = nil
	if err := ValidateReport(report); err != nil {
		return Report{}, err
	}
	return report, nil
}

// ValidateReport rejects status, bootability, phase, geometry, filesystem and
// media-state contradictions before a command or GUI may display success.
func ValidateReport(report Report) error {
	if report.Schema != SchemaVersion || report.Mode != Mode || report.Bootable {
		return errors.New("invalid formatter report envelope")
	}
	if _, err := time.Parse(time.RFC3339Nano, report.StartedAt); err != nil {
		return errors.New("formatter report has an invalid start time")
	}
	if _, err := time.Parse(time.RFC3339Nano, report.CompletedAt); err != nil {
		return errors.New("formatter report has an invalid completion time")
	}
	canonical, err := BuildPartitionTable(report.Plan)
	if err != nil || canonical != report.Table {
		return errors.New("formatter report partition table does not match its plan")
	}
	switch report.Status {
	case StatusPassed:
		if report.Failure != nil || !report.MediaChanged || !report.Reusable || report.Filesystem == nil {
			return errors.New("successful formatter report has inconsistent completion state")
		}
		state := report.Filesystem
		if state.Path == "" || state.ParentPath != report.Plan.DevicePath || state.ReadOnly {
			return errors.New("successful formatter report has an invalid partition binding")
		}
		if state.Type != report.Plan.Filesystem || state.Label != report.Plan.Label || state.SizeBytes != report.Plan.PartitionSizeBytes {
			return errors.New("successful formatter report does not match the reviewed filesystem")
		}
	case StatusFailed, StatusCancelled:
		if report.Failure == nil || report.Failure.Message == "" || report.Failure.Phase == "" {
			return errors.New("failed or cancelled formatter report is missing failure details")
		}
		if report.Reusable || report.Failure.MediaChanged != report.MediaChanged {
			return errors.New("failed or cancelled formatter report has inconsistent media state")
		}
		if report.Filesystem != nil {
			return errors.New("failed or cancelled formatter report must not publish a verified filesystem")
		}
	default:
		return fmt.Errorf("unsupported formatter report status %q", report.Status)
	}
	return nil
}
