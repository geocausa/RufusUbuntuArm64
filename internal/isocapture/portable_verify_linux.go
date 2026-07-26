//go:build linux

package isocapture

import (
	"context"
	"errors"
	"fmt"
	"os"
)

// portableContentSHA256 computes the filesystem-independent content identity
// used for remaster validation. Directory st_size is an implementation detail
// of the source and destination filesystems, so only regular-file sizes are
// part of the portable content model.
func portableContentSHA256(inventory Inventory) (string, error) {
	portable := inventory
	portable.Entries = append([]Entry(nil), inventory.Entries...)
	for index := range portable.Entries {
		if portable.Entries[index].Kind == EntryDirectory {
			portable.Entries[index].Size = 0
		}
	}
	return inventoryDigest(portable, false)
}

// VerifyPortableImage independently mounts the private image as UDF and
// compares its portable path/type/regular-file-size/content identity with the
// authenticated source. It deliberately excludes filesystem-specific directory
// allocation sizes while retaining all of VerifyImage's descriptor, mount,
// image-hash, and cleanup checks.
func VerifyPortableImage(ctx context.Context, image *os.File, expectedContentSHA256, expectedImageSHA256 string, expectedImageBytes uint64, options ValidationOptions) (report ValidationReport, returnErr error) {
	report = ValidationReport{
		Schema:                ValidationReportSchema,
		Status:                CaptureFailed,
		Filesystem:            "udf",
		ExpectedContentSHA256: expectedContentSHA256,
		ImageBytes:            expectedImageBytes,
	}
	if ctx == nil {
		return validationFailure(report, "invalid_context", errors.New("ISO validation context is nil"))
	}
	if image == nil {
		return validationFailure(report, "invalid_image", errors.New("ISO validation requires an open image descriptor"))
	}
	if err := validateDigest(expectedContentSHA256); err != nil {
		return validationFailure(report, "invalid_content_digest", fmt.Errorf("validate expected content digest: %w", err))
	}
	if err := validateDigest(expectedImageSHA256); err != nil {
		return validationFailure(report, "invalid_image_digest", fmt.Errorf("validate expected image digest: %w", err))
	}
	if expectedImageBytes == 0 {
		return validationFailure(report, "invalid_image_size", errors.New("expected ISO image size must be greater than zero"))
	}
	if err := ctx.Err(); err != nil {
		return validationCancellation(report, contextCause(ctx, err))
	}
	limits, err := normalizeMasterLimits(options.Limits)
	if err != nil {
		return validationFailure(report, "invalid_limits", err)
	}
	if err := validateImageDescriptor(image, expectedImageBytes); err != nil {
		return validationFailure(report, "image_identity", err)
	}
	beforeDigest, err := hashImageExact(ctx, image, expectedImageBytes)
	if err != nil {
		return validationContextFailure(report, "hash_image_before", err)
	}
	if beforeDigest != expectedImageSHA256 {
		return validationFailure(report, "image_digest_mismatch", fmt.Errorf("ISO image digest %s does not match expected %s", beforeDigest, expectedImageSHA256))
	}

	emitCapture(options.Progress, CaptureProgress{Phase: "validate_mount", Message: "Mounting the private image read-only as UDF."})
	session, err := openUDFMount(ctx, image)
	if err != nil {
		return validationContextFailure(report, "mount_validation", err)
	}
	cleanupNeeded := true
	defer func() {
		if !cleanupNeeded {
			return
		}
		if cleanupErr := session.Close(); cleanupErr != nil {
			if returnErr == nil {
				report, returnErr = validationFailure(report, "unmount_validation", cleanupErr)
			} else {
				returnErr = errors.Join(returnErr, cleanupErr)
				report.Status = CaptureFailed
				report.FailureKind = "unmount_validation"
				report.Failure = returnErr.Error()
			}
		}
	}()
	if session == nil || session.Root == nil {
		return validationFailure(report, "mount_validation", errors.New("UDF mount provider returned no root descriptor"))
	}

	emitCapture(options.Progress, CaptureProgress{Phase: "validate_content", Message: "Inventorying the mounted UDF content."})
	mountedInventory, err := Scan(ctx, session.Root, limits)
	if err != nil {
		return validationContextFailure(report, "mounted_inventory", err)
	}
	mountedContentSHA256, err := portableContentSHA256(mountedInventory)
	if err != nil {
		return validationFailure(report, "mounted_inventory", fmt.Errorf("compute portable mounted UDF content digest: %w", err))
	}
	report.Files = mountedInventory.Files
	report.Directories = mountedInventory.Directories
	report.ContentBytes = mountedInventory.TotalBytes
	report.MountedContentSHA256 = mountedContentSHA256
	report.ReadOnly = true
	report.NoSuid = true
	report.NoDev = true
	report.NoExec = true
	if mountedContentSHA256 != expectedContentSHA256 {
		return validationFailure(report, "content_mismatch", fmt.Errorf("mounted UDF portable content digest %s does not match source digest %s", mountedContentSHA256, expectedContentSHA256))
	}

	if err := session.Close(); err != nil {
		cleanupNeeded = false
		return validationFailure(report, "unmount_validation", err)
	}
	cleanupNeeded = false
	if err := validateImageDescriptor(image, expectedImageBytes); err != nil {
		return validationFailure(report, "image_identity", err)
	}
	afterDigest, err := hashImageExact(ctx, image, expectedImageBytes)
	if err != nil {
		return validationContextFailure(report, "hash_image_after", err)
	}
	if afterDigest != expectedImageSHA256 || afterDigest != beforeDigest {
		return validationFailure(report, "image_changed", errors.New("ISO image changed while its UDF content was validated"))
	}
	report.ImageSHA256 = afterDigest
	report.Status = CapturePassed
	emitCapture(options.Progress, CaptureProgress{Phase: "validate_content", Message: "Mounted UDF content matches the authenticated source inventory.", Done: mountedInventory.TotalBytes, Total: mountedInventory.TotalBytes})
	return report, nil
}
