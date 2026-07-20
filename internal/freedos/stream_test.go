package freedos

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"testing"
)

func TestMediaImageSourceMatchesReviewedBuilder(t *testing.T) {
	plan, err := NewMediaPlan(testMediaSize, "FREEDOS")
	if err != nil {
		t.Fatal(err)
	}
	want, err := BuildMediaImage(plan)
	if err != nil {
		t.Fatal(err)
	}
	source, err := NewMediaImageSource(plan)
	if err != nil {
		t.Fatal(err)
	}
	if source.Size() != uint64(len(want)) {
		t.Fatalf("sparse source size = %d; want %d", source.Size(), len(want))
	}
	got := make([]byte, len(want))
	if count, err := source.ReadAt(got, 0); err != nil || count != len(got) {
		t.Fatalf("read sparse source: count=%d err=%v", count, err)
	}
	if !bytes.Equal(got, want) {
		for index := range want {
			if got[index] != want[index] {
				t.Fatalf("sparse source differs from reviewed builder at byte %d", index)
			}
		}
	}
	partial := make([]byte, 17)
	count, err := source.ReadAt(partial, int64(source.Size())-7)
	if count != 7 || !errors.Is(err, io.EOF) {
		t.Fatalf("final partial read = %d, %v; want 7, EOF", count, err)
	}
}

func TestStreamMediaImageAndVerifyReadback(t *testing.T) {
	plan, err := NewMediaPlan(testMediaSize, "FREEDOS")
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	lastProgress := uint64(0)
	result, err := StreamMediaImage(context.Background(), &output, plan, func(completed uint64) error {
		if completed <= lastProgress || completed > plan.DiskSizeBytes {
			return fmt.Errorf("invalid progress %d after %d", completed, lastProgress)
		}
		lastProgress = completed
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.BytesWritten != plan.DiskSizeBytes || lastProgress != plan.DiskSizeBytes {
		t.Fatalf("streamed %d bytes with final progress %d; want %d", result.BytesWritten, lastProgress, plan.DiskSizeBytes)
	}
	wantDigest := fmt.Sprintf("%x", sha256.Sum256(output.Bytes()))
	if result.SHA256 != wantDigest {
		t.Fatalf("stream digest = %s; want %s", result.SHA256, wantDigest)
	}
	verified, err := VerifyMediaReadback(context.Background(), bytes.NewReader(output.Bytes()), plan)
	if err != nil {
		t.Fatal(err)
	}
	if verified != result {
		t.Fatalf("readback result = %+v; stream result = %+v", verified, result)
	}
	if err := VerifyMediaImage(output.Bytes(), plan); err != nil {
		t.Fatalf("ordinary verifier rejected streamed image: %v", err)
	}
}

func TestVerifyMediaReadbackRejectsTampering(t *testing.T) {
	plan, err := NewMediaPlan(testMediaSize, "FREEDOS")
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if _, err := StreamMediaImage(context.Background(), &output, plan, nil); err != nil {
		t.Fatal(err)
	}
	altered := append([]byte(nil), output.Bytes()...)
	offset := len(altered) - 4096
	altered[offset] = 0x7f
	result, err := VerifyMediaReadback(context.Background(), bytes.NewReader(altered), plan)
	if err == nil || result.BytesWritten != uint64(offset) {
		t.Fatalf("tampered readback result = %+v, %v; want mismatch at %d", result, err, offset)
	}
}

func TestStreamMediaImageReportsCancellationAfterAcceptedBytes(t *testing.T) {
	plan, err := NewMediaPlan(testMediaSize, "FREEDOS")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	writer := &cancellingMediaWriter{cancel: cancel}
	result, err := StreamMediaImage(ctx, writer, plan, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("stream cancellation error = %v", err)
	}
	if result.BytesWritten != mediaStreamBufferSize || uint64(writer.Len()) != result.BytesWritten {
		t.Fatalf("cancelled stream wrote %d bytes; buffer has %d", result.BytesWritten, writer.Len())
	}
	if result.SHA256 != "" {
		t.Fatal("incomplete stream published a final digest")
	}
}

func TestStreamMediaImageRejectsShortWriter(t *testing.T) {
	plan, err := NewMediaPlan(testMediaSize, "FREEDOS")
	if err != nil {
		t.Fatal(err)
	}
	writer := shortMediaWriter{}
	result, err := StreamMediaImage(context.Background(), writer, plan, nil)
	if !errors.Is(err, io.ErrShortWrite) || result.BytesWritten != 1 {
		t.Fatalf("short writer result = %+v, %v", result, err)
	}
}

type cancellingMediaWriter struct {
	bytes.Buffer
	cancel context.CancelFunc
	calls  int
}

func (writer *cancellingMediaWriter) Write(data []byte) (int, error) {
	writer.calls++
	count, err := writer.Buffer.Write(data)
	if writer.calls == 1 {
		writer.cancel()
	}
	return count, err
}

type shortMediaWriter struct{}

func (shortMediaWriter) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	return 1, nil
}
