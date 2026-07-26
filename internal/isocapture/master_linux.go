//go:build linux

package isocapture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
)

const (
	CaptureReportSchema                        = 1
	maxProviderDiagnostic                      = 64 * 1024
	minimumMasteringReserve  uint64             = 64 * 1024 * 1024
	perEntryMasteringReserve uint64             = 8 * 1024
	maximumMasteringDepth                       = 8
)

type CaptureStatus string

const (
	CapturePassed    CaptureStatus = "passed"
	CaptureFailed    CaptureStatus = "failed"
	CaptureCancelled CaptureStatus = "cancelled"
)

type CaptureProgress struct {
	Phase   string `json:"phase"`
	Message string `json:"message"`
	Done    uint64 `json:"done"`
	Total   uint64 `json:"total"`
}

type CaptureProgressFunc func(CaptureProgress)

type MasterOptions struct {
	Profile  string
	VolumeID string
	Limits   Limits
	Progress CaptureProgressFunc
}

type CaptureReport struct {
	Schema              int           `json:"schema"`
	Status              CaptureStatus `json:"status"`
	Profile             string        `json:"profile"`
	VolumeID            string        `json:"volume_id"`
	Provider            string        `json:"provider"`
	Files               uint64        `json:"files"`
	Directories         uint64        `json:"directories"`
	SourceBytes         uint64        `json:"source_bytes"`
	MaximumOutputBytes  uint64        `json:"maximum_output_bytes"`
	OutputBytes         uint64        `json:"output_bytes"`
	SourceBindingSHA256 string        `json:"source_binding_sha256"`
	SourceContentSHA256 string        `json:"source_content_sha256"`
	OutputSHA256        string        `json:"output_sha256"`
	SourceStable        bool          `json:"source_stable"`
	FailureKind         string        `json:"failure_kind,omitempty"`
	Failure             string        `json:"failure,omitempty"`
}

var errMasterOutputLimit = errors.New("ISO mastering output exceeds the admitted bound")

// Master inventories a held source directory, runs the fixed provider with only
// that descriptor inherited as fd 3, and inventories the source again before it
// returns success. The output descriptor must already refer to a private regular
// file; no path publication is performed here.
func Master(ctx context.Context, sourceRoot, output *os.File, options MasterOptions) (CaptureReport, error) {
	profile := options.Profile
	if profile == "" {
		profile = ProfileISO9660JolietUDF
	}
	report := CaptureReport{Schema: CaptureReportSchema, Status: CaptureFailed, Profile: profile}
	if ctx == nil {
		return captureFailure(report, "invalid_context", errors.New("ISO mastering context is nil"))
	}
	if sourceRoot == nil || output == nil {
		return captureFailure(report, "invalid_descriptor", errors.New("ISO mastering requires open source and output descriptors"))
	}
	if err := ctx.Err(); err != nil {
		return captureCancellation(report, err)
	}
	limits, err := normalizeMasterLimits(options.Limits)
	if err != nil {
		return captureFailure(report, "invalid_limits", err)
	}
	plan, err := BuildProviderPlan(profile, options.VolumeID)
	if err != nil {
		return captureFailure(report, "provider_policy", err)
	}
	report.VolumeID = plan.VolumeID
	report.Provider = plan.Executable
	if err := validatePrivateOutput(output); err != nil {
		return captureFailure(report, "invalid_output", err)
	}

	emitCapture(options.Progress, CaptureProgress{Phase: "inventory_source", Message: "Inventorying and hashing the source tree before mastering."})
	before, err := Scan(ctx, sourceRoot, limits)
	if err != nil {
		return captureContextFailure(report, "source_inventory", err)
	}
	report.Files = before.Files
	report.Directories = before.Directories
	report.SourceBytes = before.TotalBytes
	report.SourceBindingSHA256 = before.BindingSHA256
	report.SourceContentSHA256 = before.ContentSHA256
	outputLimit, err := masteringOutputLimit(before.TotalBytes, uint64(len(before.Entries)))
	if err != nil {
		return captureFailure(report, "output_limit", err)
	}
	report.MaximumOutputBytes = outputLimit

	if err := output.Truncate(0); err != nil {
		return captureFailure(report, "reset_output", fmt.Errorf("reset ISO output descriptor: %w", err))
	}
	if _, err := output.Seek(0, io.SeekStart); err != nil {
		return captureFailure(report, "reset_output", fmt.Errorf("rewind ISO output descriptor: %w", err))
	}

	imageWriter := &boundedOutputWriter{output: output, maximum: outputLimit}
	diagnostics := newBoundedDiagnostic(maxProviderDiagnostic)
	command := exec.Command(plan.Executable, plan.Arguments...)
	command.Dir = "/"
	command.Env = append([]string(nil), plan.Environment...)
	command.ExtraFiles = []*os.File{sourceRoot}
	command.Stdout = imageWriter
	command.Stderr = diagnostics
	emitCapture(options.Progress, CaptureProgress{Phase: "master", Message: "Creating the private ISO9660/Joliet/UDF image.", Total: outputLimit})
	runErr := runProcessGroup(ctx, command)
	if err := ctx.Err(); err != nil {
		return captureCancellation(report, contextCause(ctx, err))
	}
	if imageWriter.failure != nil {
		return captureFailure(report, "output_limit", imageWriter.failure)
	}
	if runErr != nil {
		return captureFailure(report, "provider_execution", providerError(runErr, diagnostics))
	}
	if imageWriter.written == 0 {
		return captureFailure(report, "empty_output", errors.New("ISO mastering provider produced an empty image"))
	}
	if err := output.Sync(); err != nil {
		return captureFailure(report, "sync_output", fmt.Errorf("sync mastered ISO image: %w", err))
	}

	emitCapture(options.Progress, CaptureProgress{Phase: "revalidate_source", Message: "Reinventorying the source tree after mastering."})
	after, err := Scan(ctx, sourceRoot, limits)
	if err != nil {
		return captureContextFailure(report, "source_revalidation", err)
	}
	if before.BindingSHA256 != after.BindingSHA256 {
		return captureFailure(report, "source_changed", errors.New("source tree changed while the ISO image was being mastered"))
	}
	report.SourceStable = true

	info, err := output.Stat()
	if err != nil {
		return captureFailure(report, "inspect_output", fmt.Errorf("inspect mastered ISO image: %w", err))
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 {
		return captureFailure(report, "invalid_output", errors.New("mastered ISO image is not a non-empty regular file"))
	}
	if uint64(info.Size()) != imageWriter.written || uint64(info.Size()) > outputLimit {
		return captureFailure(report, "invalid_output", fmt.Errorf("mastered ISO image size %d does not match admitted output %d", info.Size(), imageWriter.written))
	}
	if _, err := output.Seek(0, io.SeekStart); err != nil {
		return captureFailure(report, "hash_output", fmt.Errorf("rewind mastered ISO image: %w", err))
	}
	digest, hashedBytes, err := hashFile(ctx, output)
	if err != nil {
		return captureContextFailure(report, "hash_output", fmt.Errorf("hash mastered ISO image: %w", err))
	}
	if hashedBytes != imageWriter.written {
		return captureFailure(report, "hash_output", fmt.Errorf("mastered ISO image yielded %d bytes, expected %d", hashedBytes, imageWriter.written))
	}
	report.OutputBytes = hashedBytes
	report.OutputSHA256 = digest
	report.Status = CapturePassed
	emitCapture(options.Progress, CaptureProgress{Phase: "master", Message: "Private ISO image mastered and hashed.", Done: hashedBytes, Total: hashedBytes})
	return report, nil
}

func normalizeMasterLimits(limits Limits) (Limits, error) {
	defaults := DefaultLimits()
	defaults.MaxDepth = maximumMasteringDepth
	if limits.MaxEntries == 0 {
		limits.MaxEntries = defaults.MaxEntries
	}
	if limits.MaxDepth == 0 {
		limits.MaxDepth = defaults.MaxDepth
	}
	if limits.MaxPathBytes == 0 {
		limits.MaxPathBytes = defaults.MaxPathBytes
	}
	if limits.MaxPathLength == 0 {
		limits.MaxPathLength = defaults.MaxPathLength
	}
	if limits.MaxComponentBytes == 0 {
		limits.MaxComponentBytes = defaults.MaxComponentBytes
	}
	if limits.MaxFileBytes == 0 {
		limits.MaxFileBytes = defaults.MaxFileBytes
	}
	if limits.MaxTotalBytes == 0 {
		limits.MaxTotalBytes = defaults.MaxTotalBytes
	}
	normalized, err := normalizeLimits(limits)
	if err != nil {
		return Limits{}, err
	}
	if normalized.MaxDepth > maximumMasteringDepth {
		return Limits{}, fmt.Errorf("ISO mastering depth %d exceeds supported maximum %d", normalized.MaxDepth, maximumMasteringDepth)
	}
	return normalized, nil
}

func masteringOutputLimit(sourceBytes, entries uint64) (uint64, error) {
	reserve := minimumMasteringReserve
	fraction := sourceBytes / 8
	if sourceBytes%8 != 0 {
		fraction++
	}
	if fraction > reserve {
		reserve = fraction
	}
	if entries > math.MaxUint64/perEntryMasteringReserve {
		return 0, errors.New("ISO mastering entry reserve overflows uint64")
	}
	entryReserve := entries * perEntryMasteringReserve
	if reserve > math.MaxUint64-entryReserve {
		return 0, errors.New("ISO mastering reserve overflows uint64")
	}
	reserve += entryReserve
	if sourceBytes > math.MaxUint64-reserve {
		return 0, errors.New("ISO mastering output bound overflows uint64")
	}
	return sourceBytes + reserve, nil
}

func validatePrivateOutput(output *os.File) error {
	info, err := output.Stat()
	if err != nil {
		return fmt.Errorf("inspect ISO output descriptor: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("ISO output descriptor is not a regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("ISO output descriptor has no Linux identity metadata")
	}
	if stat.Nlink != 1 {
		return fmt.Errorf("ISO output descriptor has %d links; exactly one is required", stat.Nlink)
	}
	if info.Mode().Perm() != 0o600 {
		if err := output.Chmod(0o600); err != nil {
			return fmt.Errorf("secure ISO output descriptor: %w", err)
		}
	}
	return nil
}

type boundedOutputWriter struct {
	output  *os.File
	maximum uint64
	written uint64
	failure error
}

func (writer *boundedOutputWriter) Write(data []byte) (int, error) {
	if writer.failure != nil {
		return 0, writer.failure
	}
	count := uint64(len(data))
	if writer.written > writer.maximum || count > writer.maximum-writer.written {
		writer.failure = fmt.Errorf("%w: maximum %d bytes", errMasterOutputLimit, writer.maximum)
		return 0, writer.failure
	}
	written, err := writer.output.Write(data)
	writer.written += uint64(written)
	if err != nil {
		writer.failure = err
		return written, err
	}
	if written != len(data) {
		writer.failure = io.ErrShortWrite
		return written, writer.failure
	}
	return written, nil
}

type boundedDiagnostic struct {
	mutex     sync.Mutex
	maximum   int
	data      []byte
	truncated bool
}

func newBoundedDiagnostic(maximum int) *boundedDiagnostic {
	return &boundedDiagnostic{maximum: maximum}
}

func (buffer *boundedDiagnostic) Write(data []byte) (int, error) {
	buffer.mutex.Lock()
	defer buffer.mutex.Unlock()
	available := buffer.maximum - len(buffer.data)
	if available > 0 {
		if available > len(data) {
			available = len(data)
		}
		buffer.data = append(buffer.data, data[:available]...)
	}
	if available < len(data) {
		buffer.truncated = true
	}
	return len(data), nil
}

func (buffer *boundedDiagnostic) String() string {
	buffer.mutex.Lock()
	defer buffer.mutex.Unlock()
	value := strings.TrimSpace(string(buffer.data))
	if buffer.truncated {
		if value != "" {
			value += " "
		}
		value += "[diagnostic truncated]"
	}
	return value
}

func providerError(runErr error, diagnostics *boundedDiagnostic) error {
	message := diagnostics.String()
	if message == "" {
		return fmt.Errorf("ISO mastering provider failed: %w", runErr)
	}
	return fmt.Errorf("ISO mastering provider failed: %w: %s", runErr, message)
}

func captureContextFailure(report CaptureReport, kind string, err error) (CaptureReport, error) {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return captureCancellation(report, err)
	}
	return captureFailure(report, kind, err)
}

func captureFailure(report CaptureReport, kind string, err error) (CaptureReport, error) {
	report.Status = CaptureFailed
	report.FailureKind = kind
	report.Failure = err.Error()
	return report, err
}

func captureCancellation(report CaptureReport, err error) (CaptureReport, error) {
	report.Status = CaptureCancelled
	report.FailureKind = "cancelled"
	report.Failure = err.Error()
	return report, err
}

func contextCause(ctx context.Context, fallback error) error {
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	return fallback
}

func emitCapture(progress CaptureProgressFunc, event CaptureProgress) {
	if progress != nil {
		progress(event)
	}
}
