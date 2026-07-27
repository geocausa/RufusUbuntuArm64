package imaging

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

func TestWriteAndVerifyRegularFiles(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "image.bin")
	dst := filepath.Join(dir, "device.bin")
	payload := make([]byte, 2*1024*1024+37)
	for i := range payload {
		payload[i] = byte((i * 31) % 251)
	}
	if err := os.WriteFile(src, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, make([]byte, len(payload)+4096), 0o600); err != nil {
		t.Fatal(err)
	}

	written, err := WriteImage(context.Background(), src, dst, WriteOptions{BufferSize: 64 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	if written != uint64(len(payload)) {
		t.Fatalf("written=%d want=%d", written, len(payload))
	}
	if _, err := VerifyImage(context.Background(), src, dst, nil); err != nil {
		t.Fatal(err)
	}
}

func TestWriteResultSupportsTargetOnlyDigestVerification(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "image.bin")
	dstPath := filepath.Join(dir, "device.bin")
	payload := make([]byte, 2*1024*1024+37)
	for index := range payload {
		payload[index] = byte((index*17 + 9) % 251)
	}
	if err := os.WriteFile(srcPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dstPath, make([]byte, len(payload)+4096), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(srcPath)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := sourcefile.IdentityOf(source)
	if err != nil {
		source.Close()
		t.Fatal(err)
	}
	result, err := WriteOpenImageWithResult(context.Background(), source, dstPath, WriteOptions{ExpectedSource: identity, TargetSize: uint64(len(payload) + 4096)})
	if closeErr := source.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256(payload)
	if result.BytesWritten != uint64(len(payload)) || result.SHA256 != hex.EncodeToString(expected[:]) {
		t.Fatalf("write result = %#v", result)
	}

	// Verification is bound to the authenticated write digest, not to another
	// read of the source path. Replacing the source after writing must not affect
	// physical target verification.
	if err := os.WriteFile(srcPath, []byte("source changed after the completed write"), 0o600); err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyTargetDigestWithOptions(context.Background(), dstPath, DigestVerifyOptions{
		ExpectedDeviceSize: uint64(len(payload) + 4096),
		ImageSize:          result.BytesWritten,
		ExpectedSHA256:     result.SHA256,
	}, nil)
	if err != nil || verified != result.SHA256 {
		t.Fatalf("target-only verification hash=%q err=%v", verified, err)
	}

	target, err := os.OpenFile(dstPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.WriteAt([]byte{payload[0] ^ 0xff}, 0); err != nil {
		target.Close()
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyTargetDigestWithOptions(context.Background(), dstPath, DigestVerifyOptions{
		ExpectedDeviceSize: uint64(len(payload) + 4096),
		ImageSize:          result.BytesWritten,
		ExpectedSHA256:     result.SHA256,
	}, nil); err == nil {
		t.Fatal("target-only verification accepted a corrupted target")
	}
}

func TestWriteBeforeWriteFailureLeavesTargetUntouched(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "image.bin")
	dst := filepath.Join(dir, "device.bin")
	if err := os.WriteFile(src, []byte("new data"), 0o600); err != nil {
		t.Fatal(err)
	}
	original := []byte("original target")
	if err := os.WriteFile(dst, original, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := WriteImage(context.Background(), src, dst, WriteOptions{BeforeWrite: func(_ *os.File) error {
		return context.Canceled
	}})
	if err == nil {
		t.Fatal("expected before-write error")
	}
	got, readErr := os.ReadFile(dst)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != string(original) {
		t.Fatalf("target changed before safety callback succeeded: %q", got)
	}
}

func TestWriteRejectsImageLargerThanTargetBeforeWrite(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "image.bin")
	dst := filepath.Join(dir, "device.bin")
	if err := os.WriteFile(src, []byte("too large"), 0o600); err != nil {
		t.Fatal(err)
	}
	original := []byte("target remains unchanged")
	if err := os.WriteFile(dst, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteImage(context.Background(), src, dst, WriteOptions{TargetSize: 2}); err == nil {
		t.Fatal("oversized image was accepted")
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatalf("target changed: %q", got)
	}
}

func TestWriteRejectsReplacedSource(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "image.bin")
	dst := filepath.Join(dir, "device.bin")
	if err := os.WriteFile(src, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, identity, err := sourcefile.Inspect(src)
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(dir, "replacement")
	if err := os.WriteFile(replacement, []byte("different"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, src); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteImage(context.Background(), src, dst, WriteOptions{ExpectedSource: identity}); err == nil {
		t.Fatal("replaced source was accepted")
	}
	got, _ := os.ReadFile(dst)
	if string(got) != "untouched" {
		t.Fatalf("target changed: %q", got)
	}
}

func TestWriteOpenImageKeepsPinnedSourceAfterPathReplacement(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "image.bin")
	dstPath := filepath.Join(dir, "device.bin")
	original := []byte("the originally selected image")
	if err := os.WriteFile(srcPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	opened, err := os.Open(srcPath)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	identity, err := sourcefile.IdentityOf(opened)
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(dir, "replacement.bin")
	if err := os.WriteFile(replacement, []byte("a different file at the old path"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Cross a kernel timestamp tick so the rename below reliably updates the
	// pinned inode's ctime; the pinned write must still succeed.
	time.Sleep(25 * time.Millisecond)
	if err := os.Rename(replacement, srcPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dstPath, make([]byte, len(original)), 0o600); err != nil {
		t.Fatal(err)
	}

	written, err := WriteOpenImage(context.Background(), opened, dstPath, WriteOptions{
		ExpectedSource: identity,
		TargetSize:     uint64(len(original)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if written != uint64(len(original)) {
		t.Fatalf("written=%d want=%d", written, len(original))
	}
	got, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatalf("writer reopened the replaced path: got %q", got)
	}
}

func TestVerifyOpenImageKeepsPinnedSourceAfterPathReplacement(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "image.bin")
	dstPath := filepath.Join(dir, "device.bin")
	original := []byte("verified selected image")
	if err := os.WriteFile(srcPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	opened, err := os.Open(srcPath)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	identity, err := sourcefile.IdentityOf(opened)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dstPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(dir, "replacement.bin")
	if err := os.WriteFile(replacement, []byte("not the selected image"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Cross a kernel timestamp tick so the rename below reliably updates the
	// pinned inode's ctime; pinned verification must still succeed.
	time.Sleep(25 * time.Millisecond)
	if err := os.Rename(replacement, srcPath); err != nil {
		t.Fatal(err)
	}

	if _, err := VerifyOpenImageWithOptions(context.Background(), opened, dstPath, VerifyOptions{ExpectedSource: identity}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestClearStaleSignaturesClearsBothTargetEdges(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "image.bin")
	dstPath := filepath.Join(dir, "device.bin")
	payload := make([]byte, 1024*1024)
	for i := range payload {
		payload[i] = byte(i%251 + 1)
	}
	const targetSize = 40 * 1024 * 1024
	if err := os.WriteFile(srcPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	old := make([]byte, targetSize)
	for i := range old {
		old[i] = 0xaa
	}
	if err := os.WriteFile(dstPath, old, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := WriteImage(context.Background(), srcPath, dstPath, WriteOptions{
		TargetSize:           targetSize,
		ClearStaleSignatures: true,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got[:len(payload)]) != string(payload) {
		t.Fatal("image payload was not written at the beginning")
	}
	for _, index := range []int{2 * 1024 * 1024, 15 * 1024 * 1024, 24 * 1024 * 1024, 39 * 1024 * 1024} {
		if got[index] != 0 {
			t.Fatalf("stale target byte remained at offset %d: %#x", index, got[index])
		}
	}
	if got[20*1024*1024] != 0xaa {
		t.Fatalf("middle of target should not be needlessly erased: %#x", got[20*1024*1024])
	}
}

func TestCancelledBeforeSignatureClearLeavesTargetUntouched(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "image.bin")
	dstPath := filepath.Join(dir, "device.bin")
	if err := os.WriteFile(srcPath, []byte("image"), 0o600); err != nil {
		t.Fatal(err)
	}
	original := make([]byte, 2*1024*1024)
	for i := range original {
		original[i] = 0x5a
	}
	if err := os.WriteFile(dstPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := WriteImage(ctx, srcPath, dstPath, WriteOptions{
		TargetSize:           uint64(len(original)),
		ClearStaleSignatures: true,
	}); err == nil {
		t.Fatal("cancelled operation unexpectedly succeeded")
	}
	got, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Fatal("target changed after cancellation before the destructive stage")
	}
}
