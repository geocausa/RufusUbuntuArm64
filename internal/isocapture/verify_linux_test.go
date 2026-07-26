//go:build linux

package isocapture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyImageComparesMountedContentAndRehashesImage(t *testing.T) {
	sourcePath := buildInventoryFixture(t)
	sourceInventory := scanDirectoryPath(t, context.Background(), sourcePath, Limits{})
	mountedPath := buildInventoryFixture(t)
	stubMountedTree(t, mountedPath, nil)
	image, imagePath, imageBytes, imageDigest := createValidationImage(t, []byte("ISO-IMAGE"))
	defer image.Close()

	var events []CaptureProgress
	report, err := VerifyImage(context.Background(), image, sourceInventory.ContentSHA256, imageDigest, imageBytes, ValidationOptions{
		Progress: func(event CaptureProgress) { events = append(events, event) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Schema != ValidationReportSchema || report.Status != CapturePassed || report.Files != sourceInventory.Files || report.Directories != sourceInventory.Directories || report.ContentBytes != sourceInventory.TotalBytes {
		t.Fatalf("unexpected validation report: %+v", report)
	}
	if report.MountedContentSHA256 != sourceInventory.ContentSHA256 || report.ExpectedContentSHA256 != sourceInventory.ContentSHA256 || report.ImageSHA256 != imageDigest || report.ImageBytes != imageBytes {
		t.Fatalf("incomplete validation evidence: %+v", report)
	}
	if !report.ReadOnly || !report.NoSuid || !report.NoDev || !report.NoExec {
		t.Fatalf("missing restrictive mount evidence: %+v", report)
	}
	data, err := os.ReadFile(imagePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "ISO-IMAGE" {
		t.Fatalf("image changed: %q", data)
	}
	phases := make(map[string]bool)
	for _, event := range events {
		phases[event.Phase] = true
	}
	for _, phase := range []string{"validate_mount", "validate_content"} {
		if !phases[phase] {
			t.Fatalf("missing phase %q in %+v", phase, events)
		}
	}
	last := events[len(events)-1]
	if last.Done != last.Total || last.Total != sourceInventory.TotalBytes {
		t.Fatalf("validation completion is not exact: %+v", last)
	}
}

func TestVerifyImageRejectsMountedContentMismatch(t *testing.T) {
	sourcePath := buildInventoryFixture(t)
	sourceInventory := scanDirectoryPath(t, context.Background(), sourcePath, Limits{})
	mountedPath := buildInventoryFixture(t)
	if err := os.WriteFile(filepath.Join(mountedPath, "README.TXT"), []byte("different"), 0o644); err != nil {
		t.Fatal(err)
	}
	stubMountedTree(t, mountedPath, nil)
	image, _, imageBytes, imageDigest := createValidationImage(t, []byte("ISO-IMAGE"))
	defer image.Close()

	report, err := VerifyImage(context.Background(), image, sourceInventory.ContentSHA256, imageDigest, imageBytes, ValidationOptions{})
	if err == nil || report.Status != CaptureFailed || report.FailureKind != "content_mismatch" {
		t.Fatalf("mismatch report=%+v err=%v", report, err)
	}
}

func TestVerifyImageRejectsImageMutationDuringValidation(t *testing.T) {
	sourcePath := buildInventoryFixture(t)
	sourceInventory := scanDirectoryPath(t, context.Background(), sourcePath, Limits{})
	mountedPath := buildInventoryFixture(t)
	image, imagePath, imageBytes, imageDigest := createValidationImage(t, []byte("ISO-IMAGE"))
	defer image.Close()
	stubMountedTree(t, mountedPath, func() error {
		return os.WriteFile(imagePath, []byte("ALTERED!!"), 0o600)
	})

	report, err := VerifyImage(context.Background(), image, sourceInventory.ContentSHA256, imageDigest, imageBytes, ValidationOptions{})
	if err == nil || report.Status != CaptureFailed || report.FailureKind != "image_changed" {
		t.Fatalf("mutation report=%+v err=%v", report, err)
	}
}

func TestVerifyImageRejectsCleanupAndMountFailures(t *testing.T) {
	sourcePath := buildInventoryFixture(t)
	sourceInventory := scanDirectoryPath(t, context.Background(), sourcePath, Limits{})
	image, _, imageBytes, imageDigest := createValidationImage(t, []byte("ISO-IMAGE"))
	defer image.Close()

	mountedPath := buildInventoryFixture(t)
	stubMountedTree(t, mountedPath, func() error { return errors.New("unmount refused") })
	report, err := VerifyImage(context.Background(), image, sourceInventory.ContentSHA256, imageDigest, imageBytes, ValidationOptions{})
	if err == nil || report.Status != CaptureFailed || report.FailureKind != "unmount_validation" || !strings.Contains(err.Error(), "unmount refused") {
		t.Fatalf("cleanup report=%+v err=%v", report, err)
	}

	previous := openUDFMount
	openUDFMount = func(context.Context, *os.File) (*udfMountSession, error) {
		return nil, errors.New("mount refused")
	}
	t.Cleanup(func() { openUDFMount = previous })
	report, err = VerifyImage(context.Background(), image, sourceInventory.ContentSHA256, imageDigest, imageBytes, ValidationOptions{})
	if err == nil || report.FailureKind != "mount_validation" || !strings.Contains(err.Error(), "mount refused") {
		t.Fatalf("mount report=%+v err=%v", report, err)
	}
}

func TestVerifyImageRejectsBadDigestAndPreexistingImageMismatch(t *testing.T) {
	image, _, imageBytes, imageDigest := createValidationImage(t, []byte("ISO-IMAGE"))
	defer image.Close()

	for _, digest := range []string{"", strings.Repeat("A", 64), strings.Repeat("g", 64)} {
		report, err := VerifyImage(context.Background(), image, digest, imageDigest, imageBytes, ValidationOptions{})
		if err == nil || report.FailureKind != "invalid_content_digest" {
			t.Fatalf("digest %q report=%+v err=%v", digest, report, err)
		}
	}

	validContent := hex.EncodeToString(make([]byte, 32))
	wrongImage := hex.EncodeToString(bytesOf(0x11, 32))
	report, err := VerifyImage(context.Background(), image, validContent, wrongImage, imageBytes, ValidationOptions{})
	if err == nil || report.FailureKind != "image_digest_mismatch" {
		t.Fatalf("image mismatch report=%+v err=%v", report, err)
	}
}

func TestOpenSecureWorkspaceRootRejectsWritableAndSymlinkRoots(t *testing.T) {
	rootPath := t.TempDir()
	root, err := openSecureWorkspaceRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	root.Close()
	if err := os.Chmod(rootPath, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := openSecureWorkspaceRoot(rootPath); err == nil || !strings.Contains(err.Error(), "not group/world writable") {
		t.Fatalf("writable root error = %v", err)
	}

	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "run")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := openSecureWorkspaceRoot(link); err == nil || !strings.Contains(err.Error(), "real directory") {
		t.Fatalf("symlink root error = %v", err)
	}
}

func stubMountedTree(t *testing.T, path string, afterClose func() error) {
	t.Helper()
	previous := openUDFMount
	openUDFMount = func(context.Context, *os.File) (*udfMountSession, error) {
		root, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		return &udfMountSession{
			Root: root,
			closeFunc: func() error {
				return errors.Join(root.Close(), callOptional(afterClose))
			},
		}, nil
	}
	t.Cleanup(func() { openUDFMount = previous })
}

func createValidationImage(t *testing.T, content []byte) (*os.File, string, uint64, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "private.iso")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	return file, path, uint64(len(content)), hex.EncodeToString(digest[:])
}

func callOptional(call func() error) error {
	if call == nil {
		return nil
	}
	return call()
}

func bytesOf(value byte, count int) []byte {
	data := make([]byte, count)
	for index := range data {
		data[index] = value
	}
	return data
}
