//go:build linux

package isocapture

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"syscall"
)

const FilesystemCaptureReportSchema = 1

type ContentComparison string

const (
	ContentComparisonPassed ContentComparison = "passed"
)

// FilesystemCaptureOptions binds the filesystem remaster to the selected whole
// source disk and the one reviewed UDF bridge policy.
type FilesystemCaptureOptions struct {
	SourceDevicePath string
	VolumeID         string
	Limits           Limits
	Progress         CaptureProgressFunc
}

// FilesystemCaptureReport is the complete evidence required before an ISO file
// is considered published. It deliberately makes no bootability or whole-disk
// image claim.
type FilesystemCaptureReport struct {
	Schema              int               `json:"schema"`
	Status              CaptureStatus     `json:"status"`
	Profile             string            `json:"profile"`
	Filesystem          string            `json:"filesystem"`
	VolumeID            string            `json:"volume_id"`
	SourceDevice        string            `json:"source_device"`
	SourceMount         string            `json:"source_mount"`
	Destination         string            `json:"destination"`
	Files               uint64            `json:"files"`
	Directories         uint64            `json:"directories"`
	SourceBytes         uint64            `json:"source_bytes"`
	RequiredBytes       uint64            `json:"required_bytes"`
	OutputBytes         uint64            `json:"output_bytes"`
	SourceBindingSHA256 string            `json:"source_binding_sha256"`
	SourceContentSHA256 string            `json:"source_content_sha256"`
	OutputSHA256        string            `json:"output_sha256"`
	ContentComparison   ContentComparison `json:"content_comparison,omitempty"`
	SourceStable        bool              `json:"source_stable"`
	UDFValidated        bool              `json:"udf_validated"`
	Published           bool              `json:"published"`
	FailureKind         string            `json:"failure_kind,omitempty"`
	Failure             string            `json:"failure,omitempty"`
}

// CaptureFilesystem creates and publishes one verified filesystem remaster. The
// output is private and unnamed to the mastering provider until every source,
// content, image and destination check succeeds.
func CaptureFilesystem(ctx context.Context, sourceMount, outputPath string, options FilesystemCaptureOptions) (report FilesystemCaptureReport, returnErr error) {
	report = FilesystemCaptureReport{
		Schema:       FilesystemCaptureReportSchema,
		Status:       CaptureFailed,
		Profile:      ProfileISO9660JolietUDF,
		Filesystem:   "udf",
		SourceDevice: options.SourceDevicePath,
		SourceMount:  sourceMount,
		Destination:  outputPath,
	}
	if ctx == nil {
		return filesystemFailure(report, "invalid_context", errors.New("ISO capture context is nil"))
	}
	if strings.TrimSpace(options.SourceDevicePath) == "" {
		return filesystemFailure(report, "invalid_source_device", errors.New("ISO capture requires the selected whole source-device path"))
	}
	if err := ctx.Err(); err != nil {
		return filesystemCancellation(report, contextCause(ctx, err))
	}

	emitCapture(options.Progress, CaptureProgress{Phase: "source_view", Message: "Creating and authenticating the private read-only source view."})
	view, err := OpenReadOnlySourceView(ctx, sourceMount, options.Limits)
	if err != nil {
		return filesystemContextFailure(report, "source_view", err)
	}
	viewOpen := true
	defer func() {
		if !viewOpen {
			return
		}
		if cleanupErr := view.Close(); cleanupErr != nil {
			if returnErr == nil {
				report, returnErr = filesystemFailure(report, "source_view_cleanup", cleanupErr)
			} else {
				returnErr = errors.Join(returnErr, cleanupErr)
				report.Status = CaptureFailed
				report.FailureKind = "source_view_cleanup"
				report.Failure = returnErr.Error()
			}
		}
	}()
	report.Files = view.Inventory.Files
	report.Directories = view.Inventory.Directories
	report.SourceBytes = view.Inventory.TotalBytes
	report.SourceBindingSHA256 = view.Inventory.BindingSHA256
	report.SourceContentSHA256 = view.Inventory.ContentSHA256

	requiredBytes, err := masteringOutputLimit(view.Inventory.TotalBytes, uint64(len(view.Inventory.Entries)))
	if err != nil {
		return filesystemFailure(report, "destination_bound", err)
	}
	report.RequiredBytes = requiredBytes
	destination, err := prepareISODestination(outputPath, options.SourceDevicePath, requiredBytes)
	if err != nil {
		return filesystemFailure(report, "destination_preflight", err)
	}
	defer destination.Directory.Close()
	temporary, temporaryName, err := destination.createTemporary()
	if err != nil {
		return filesystemFailure(report, "open_destination", err)
	}
	temporaryOpen := true
	published := false
	defer func() {
		if temporaryOpen {
			_ = temporary.Close()
		}
		if !published {
			_ = syscall.Unlinkat(int(destination.Directory.Fd()), temporaryName)
		}
	}()

	masterReport, err := Master(ctx, view.Root, temporary, MasterOptions{
		Profile:  ProfileISO9660JolietUDF,
		VolumeID: options.VolumeID,
		Limits:   options.Limits,
		Progress: options.Progress,
	})
	report.VolumeID = masterReport.VolumeID
	if err != nil {
		return filesystemContextFailure(report, "master", err)
	}
	if masterReport.Status != CapturePassed || !masterReport.SourceStable {
		return filesystemFailure(report, "master_evidence", errors.New("ISO mastering did not return stable passed evidence"))
	}
	if masterReport.SourceBindingSHA256 != view.Inventory.BindingSHA256 || masterReport.SourceContentSHA256 != view.Inventory.ContentSHA256 {
		return filesystemFailure(report, "source_changed", errors.New("ISO mastering source evidence differs from the authenticated read-only view"))
	}
	if masterReport.MaximumOutputBytes != requiredBytes || masterReport.OutputBytes == 0 || masterReport.OutputBytes > requiredBytes {
		return filesystemFailure(report, "output_bound", errors.New("ISO mastering output violates the admitted destination bound"))
	}

	validationReport, err := VerifyImage(
		ctx,
		temporary,
		masterReport.SourceContentSHA256,
		masterReport.OutputSHA256,
		masterReport.OutputBytes,
		ValidationOptions{Limits: options.Limits, Progress: options.Progress},
	)
	if err != nil {
		return filesystemContextFailure(report, "validate_image", err)
	}
	if validationReport.Status != CapturePassed || validationReport.MountedContentSHA256 != masterReport.SourceContentSHA256 || validationReport.ImageSHA256 != masterReport.OutputSHA256 {
		return filesystemFailure(report, "validation_evidence", errors.New("independent UDF validation did not return matching passed evidence"))
	}

	emitCapture(options.Progress, CaptureProgress{Phase: "revalidate_source", Message: "Rechecking the authenticated source view before publication."})
	finalInventory, err := Scan(ctx, view.Root, options.Limits)
	if err != nil {
		return filesystemContextFailure(report, "source_revalidation", err)
	}
	if finalInventory.BindingSHA256 != view.Inventory.BindingSHA256 || finalInventory.ContentSHA256 != view.Inventory.ContentSHA256 {
		return filesystemFailure(report, "source_changed", errors.New("source filesystem changed before ISO publication"))
	}
	report.SourceStable = true
	report.UDFValidated = true
	report.ContentComparison = ContentComparisonPassed
	report.OutputBytes = masterReport.OutputBytes
	report.OutputSHA256 = masterReport.OutputSHA256

	if err := view.Close(); err != nil {
		return filesystemFailure(report, "source_view_cleanup", err)
	}
	viewOpen = false
	if err := applyGraphicalISOOwner(temporary); err != nil {
		return filesystemFailure(report, "destination_ownership", err)
	}
	if err := temporary.Sync(); err != nil {
		return filesystemFailure(report, "sync_destination", fmt.Errorf("sync completed ISO image: %w", err))
	}
	if err := temporary.Close(); err != nil {
		temporaryOpen = false
		return filesystemFailure(report, "close_destination", fmt.Errorf("close completed ISO image: %w", err))
	}
	temporaryOpen = false
	if err := destination.revalidate(); err != nil {
		return filesystemFailure(report, "destination_revalidation", err)
	}
	emitCapture(options.Progress, CaptureProgress{Phase: "publish", Message: "Publishing the verified ISO without replacing an existing file."})
	if err := publishISONoReplace(destination.Directory, temporaryName, destination.Name); err != nil {
		return filesystemFailure(report, "publish_destination", err)
	}
	published = true
	report.Published = true
	report.Status = CapturePassed
	emitCapture(options.Progress, CaptureProgress{Phase: "publish", Message: "Verified filesystem ISO published.", Done: report.OutputBytes, Total: report.OutputBytes})
	return report, nil
}

func filesystemContextFailure(report FilesystemCaptureReport, kind string, err error) (FilesystemCaptureReport, error) {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return filesystemCancellation(report, err)
	}
	return filesystemFailure(report, kind, err)
}

func filesystemFailure(report FilesystemCaptureReport, kind string, err error) (FilesystemCaptureReport, error) {
	report.Status = CaptureFailed
	report.FailureKind = kind
	report.Failure = err.Error()
	return report, err
}

func filesystemCancellation(report FilesystemCaptureReport, err error) (FilesystemCaptureReport, error) {
	report.Status = CaptureCancelled
	report.FailureKind = "cancelled"
	report.Failure = err.Error()
	return report, err
}
