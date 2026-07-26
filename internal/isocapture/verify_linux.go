//go:build linux

package isocapture

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/geocausa/RufusArm64/internal/trustedexec"
)

const (
	ValidationReportSchema        = 1
	udfSuperMagic          int64  = 0x15013346
	statfsReadOnly         uint64 = 0x1
	statfsNoSuid           uint64 = 0x2
	statfsNoDev            uint64 = 0x4
	statfsNoExec           uint64 = 0x8
	validationImageFD             = 3
	validationImagePath           = "/proc/self/fd/3"
)

type ValidationOptions struct {
	Limits   Limits
	Progress CaptureProgressFunc
}

type ValidationReport struct {
	Schema                int           `json:"schema"`
	Status                CaptureStatus `json:"status"`
	Filesystem            string        `json:"filesystem"`
	Files                 uint64        `json:"files"`
	Directories           uint64        `json:"directories"`
	ContentBytes          uint64        `json:"content_bytes"`
	ExpectedContentSHA256 string        `json:"expected_content_sha256"`
	MountedContentSHA256  string        `json:"mounted_content_sha256"`
	ImageBytes            uint64        `json:"image_bytes"`
	ImageSHA256           string        `json:"image_sha256"`
	ReadOnly              bool          `json:"read_only"`
	NoSuid                bool          `json:"nosuid"`
	NoDev                 bool          `json:"nodev"`
	NoExec                bool          `json:"noexec"`
	FailureKind           string        `json:"failure_kind,omitempty"`
	Failure               string        `json:"failure,omitempty"`
}

type udfMountSession struct {
	Root      *os.File
	closeOnce sync.Once
	closeFunc func() error
	closeErr  error
}

func (session *udfMountSession) Close() error {
	if session == nil {
		return nil
	}
	session.closeOnce.Do(func() {
		if session.closeFunc != nil {
			session.closeErr = session.closeFunc()
		}
	})
	return session.closeErr
}

var (
	verificationWorkspaceRoot = "/run"
	resolveMountUtility       = func() (string, error) { return trustedexec.Resolve("mount") }
	openUDFMount              = openReadOnlyUDFMount
)

// VerifyImage independently mounts the private image as UDF, inventories the
// mounted tree through descriptors, compares complete supported content, then
// unmounts and rehashes the image. It performs no path publication.
func VerifyImage(ctx context.Context, image *os.File, expectedContentSHA256, expectedImageSHA256 string, expectedImageBytes uint64, options ValidationOptions) (report ValidationReport, returnErr error) {
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
	report.Files = mountedInventory.Files
	report.Directories = mountedInventory.Directories
	report.ContentBytes = mountedInventory.TotalBytes
	report.MountedContentSHA256 = mountedInventory.ContentSHA256
	report.ReadOnly = true
	report.NoSuid = true
	report.NoDev = true
	report.NoExec = true
	if mountedInventory.ContentSHA256 != expectedContentSHA256 {
		return validationFailure(report, "content_mismatch", fmt.Errorf("mounted UDF content digest %s does not match source digest %s", mountedInventory.ContentSHA256, expectedContentSHA256))
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

func openReadOnlyUDFMount(ctx context.Context, image *os.File) (*udfMountSession, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("independent UDF validation requires root privileges")
	}
	executable, err := resolveMountUtility()
	if err != nil {
		return nil, fmt.Errorf("resolve trusted mount: %w", err)
	}
	workspaceRoot, err := openSecureWorkspaceRoot(verificationWorkspaceRoot)
	if err != nil {
		return nil, err
	}
	defer workspaceRoot.Close()
	workspaceProc := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), workspaceRoot.Fd())
	created, err := os.MkdirTemp(workspaceProc, "rufusarm64-iso-validate-")
	if err != nil {
		return nil, fmt.Errorf("create ISO validation workspace: %w", err)
	}
	workspaceName := filepath.Base(created)
	workspace := filepath.Join(verificationWorkspaceRoot, workspaceName)
	cleanupWorkspace := true
	mounted := false
	defer func() {
		// Never recurse into a mount that could not be detached. Leaving the
		// private root-owned workspace is safer and preserves failure evidence.
		if cleanupWorkspace && !mounted {
			_ = os.RemoveAll(workspace)
		}
	}()
	if err := os.Chmod(workspace, 0o700); err != nil {
		return nil, fmt.Errorf("secure ISO validation workspace: %w", err)
	}
	mountpoint := filepath.Join(workspace, "udf")
	if err := os.Mkdir(mountpoint, 0o700); err != nil {
		return nil, fmt.Errorf("create UDF validation mountpoint: %w", err)
	}
	preMount, err := os.OpenFile(mountpoint, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open UDF validation mountpoint: %w", err)
	}
	preMountID, mountIDErr := descriptorMountID(preMount.Fd())
	closePreMountErr := preMount.Close()
	if mountIDErr != nil || closePreMountErr != nil {
		return nil, errors.Join(fmt.Errorf("inspect UDF validation mountpoint: %w", mountIDErr), closePreMountErr)
	}

	diagnostics := newBoundedDiagnostic(maxProviderDiagnostic)
	command := exec.Command(
		executable,
		"--no-canonicalize",
		"--no-mtab",
		"-t", "udf",
		"-o", "loop,ro,nosuid,nodev,noexec",
		"--",
		validationImagePath,
		mountpoint,
	)
	command.Dir = "/"
	command.Env = []string{
		"HOME=/nonexistent",
		"LC_ALL=C.UTF-8",
		"LIBMOUNT_FSTAB=/dev/null",
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"TZ=UTC",
	}
	command.ExtraFiles = []*os.File{image}
	command.Stdout = diagnostics
	command.Stderr = diagnostics
	if err := runProcessGroup(ctx, command); err != nil {
		return nil, mountProviderError(err, diagnostics)
	}
	mounted = true
	cleanupMount := func() error {
		if !mounted {
			return nil
		}
		if err := syscall.Unmount(mountpoint, 0); err != nil {
			return fmt.Errorf("unmount UDF validation image: %w", err)
		}
		mounted = false
		return nil
	}
	root, err := os.OpenFile(mountpoint, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		cleanupErr := cleanupMount()
		return nil, errors.Join(fmt.Errorf("open mounted UDF validation root: %w", err), cleanupErr)
	}
	if err := requireVerifiedUDFMount(root, preMountID); err != nil {
		closeErr := root.Close()
		cleanupErr := cleanupMount()
		return nil, errors.Join(err, closeErr, cleanupErr)
	}
	cleanupWorkspace = false
	return &udfMountSession{
		Root: root,
		closeFunc: func() error {
			closeErr := root.Close()
			unmountErr := cleanupMount()
			if unmountErr == nil {
				removeErr := os.RemoveAll(workspace)
				return errors.Join(closeErr, removeErr)
			}
			return errors.Join(closeErr, unmountErr)
		},
	}, nil
}

func mountProviderError(runErr error, diagnostics *boundedDiagnostic) error {
	message := diagnostics.String()
	if message == "" {
		return fmt.Errorf("mount private ISO as UDF: %w", runErr)
	}
	return fmt.Errorf("mount private ISO as UDF: %w: %s", runErr, message)
}

func openSecureWorkspaceRoot(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return nil, fmt.Errorf("invalid ISO validation workspace root %q", path)
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect ISO validation workspace root: %w", err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.IsDir() {
		return nil, errors.New("ISO validation workspace root must be a real directory")
	}
	root, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open ISO validation workspace root: %w", err)
	}
	openInfo, err := root.Stat()
	if err != nil {
		root.Close()
		return nil, fmt.Errorf("inspect open ISO validation workspace root: %w", err)
	}
	if !os.SameFile(pathInfo, openInfo) {
		root.Close()
		return nil, errors.New("ISO validation workspace root changed while it was opened")
	}
	stat, ok := openInfo.Sys().(*syscall.Stat_t)
	if !ok {
		root.Close()
		return nil, errors.New("ISO validation workspace root has no Linux ownership metadata")
	}
	if int(stat.Uid) != os.Geteuid() || openInfo.Mode().Perm()&0o022 != 0 {
		root.Close()
		return nil, errors.New("ISO validation workspace root must be owned by the effective user and not group/world writable")
	}
	return root, nil
}

func requireVerifiedUDFMount(root *os.File, previousMountID uint64) error {
	mountID, err := descriptorMountID(root.Fd())
	if err != nil {
		return fmt.Errorf("inspect mounted UDF identity: %w", err)
	}
	if mountID == previousMountID {
		return errors.New("UDF validation mountpoint did not acquire a distinct mount identity")
	}
	var stat syscall.Statfs_t
	if err := syscall.Fstatfs(int(root.Fd()), &stat); err != nil {
		return fmt.Errorf("inspect mounted UDF filesystem: %w", err)
	}
	if int64(stat.Type) != udfSuperMagic {
		return fmt.Errorf("mounted validation filesystem type %#x is not UDF", stat.Type)
	}
	flags := uint64(stat.Flags)
	required := statfsReadOnly | statfsNoSuid | statfsNoDev | statfsNoExec
	if flags&required != required {
		return fmt.Errorf("mounted UDF validation flags %#x do not include read-only,nosuid,nodev,noexec", flags)
	}
	return nil
}

func validateImageDescriptor(image *os.File, expectedBytes uint64) error {
	info, err := image.Stat()
	if err != nil {
		return fmt.Errorf("inspect ISO image descriptor: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 {
		return errors.New("ISO image descriptor is not a non-empty regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("ISO image descriptor has no Linux identity metadata")
	}
	if stat.Nlink != 1 {
		return fmt.Errorf("ISO image descriptor has %d links; exactly one is required", stat.Nlink)
	}
	if uint64(info.Size()) != expectedBytes {
		return fmt.Errorf("ISO image size %d does not match expected %d", info.Size(), expectedBytes)
	}
	return nil
}

func hashImageExact(ctx context.Context, image *os.File, expectedBytes uint64) (string, error) {
	if _, err := image.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("rewind ISO image: %w", err)
	}
	digest, bytesRead, err := hashFile(ctx, image)
	if err != nil {
		return "", fmt.Errorf("hash ISO image: %w", err)
	}
	if bytesRead != expectedBytes {
		return "", fmt.Errorf("ISO image yielded %d bytes, expected %d", bytesRead, expectedBytes)
	}
	return digest, nil
}

func validateDigest(value string) error {
	if len(value) != 64 || strings.ToLower(value) != value {
		return errors.New("SHA-256 digest must contain exactly 64 lowercase hexadecimal characters")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return errors.New("SHA-256 digest is malformed")
	}
	return nil
}

func validationContextFailure(report ValidationReport, kind string, err error) (ValidationReport, error) {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return validationCancellation(report, err)
	}
	return validationFailure(report, kind, err)
}

func validationFailure(report ValidationReport, kind string, err error) (ValidationReport, error) {
	report.Status = CaptureFailed
	report.FailureKind = kind
	report.Failure = err.Error()
	return report, err
}

func validationCancellation(report ValidationReport, err error) (ValidationReport, error) {
	report.Status = CaptureCancelled
	report.FailureKind = "cancelled"
	report.Failure = err.Error()
	return report, err
}
