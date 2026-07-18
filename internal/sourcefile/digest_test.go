package sourcefile

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDigestsOpenAllAlgorithmsAndRestoresOffset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "image.bin")
	content := []byte("abc")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.Seek(2, 0); err != nil {
		t.Fatal(err)
	}
	var lastDone, lastTotal uint64
	results, err := DigestsOpen(context.Background(), file, SupportedDigestAlgorithms(), func(done, total uint64) {
		lastDone, lastTotal = done, total
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[DigestAlgorithm]string{
		DigestMD5:    "900150983cd24fb0d6963f7d28e17f72",
		DigestSHA1:   "a9993e364706816aba3e25717850c26c9cd0d89d",
		DigestSHA256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		DigestSHA512: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
	}
	algorithms := SupportedDigestAlgorithms()
	if len(results) != len(want) {
		t.Fatalf("results=%d want %d", len(results), len(want))
	}
	for index, result := range results {
		if result.Algorithm != algorithms[index] {
			t.Fatalf("result %d algorithm=%q", index, result.Algorithm)
		}
		if result.Hex != want[result.Algorithm] {
			t.Fatalf("%s=%q want %q", result.Algorithm, result.Hex, want[result.Algorithm])
		}
	}
	position, err := file.Seek(0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if position != 2 {
		t.Fatalf("offset=%d want 2", position)
	}
	if lastDone != uint64(len(content)) || lastTotal != uint64(len(content)) {
		t.Fatalf("progress=%d/%d", lastDone, lastTotal)
	}
}

func TestParseDigestAlgorithm(t *testing.T) {
	cases := map[string]DigestAlgorithm{
		"md5":     DigestMD5,
		" MD5 ":   DigestMD5,
		"sha1":    DigestSHA1,
		"SHA-1":   DigestSHA1,
		"sha-256": DigestSHA256,
		"SHA512":  DigestSHA512,
	}
	for input, want := range cases {
		got, err := ParseDigestAlgorithm(input)
		if err != nil || got != want {
			t.Fatalf("ParseDigestAlgorithm(%q)=%q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"", "sha3", "crc32"} {
		if _, err := ParseDigestAlgorithm(input); err == nil {
			t.Fatalf("unsupported algorithm %q accepted", input)
		}
	}
}

func TestDigestsOpenRejectsInvalidRequests(t *testing.T) {
	path := filepath.Join(t.TempDir(), "image.bin")
	if err := os.WriteFile(path, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	if _, err := DigestsOpen(context.Background(), file, nil, nil); err == nil || !strings.Contains(err.Error(), "algorithm") {
		t.Fatalf("empty-algorithm error = %v", err)
	}
	if _, err := DigestsOpen(context.Background(), file, []DigestAlgorithm{DigestSHA256, DigestSHA256}, nil); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate-algorithm error = %v", err)
	}
	if _, err := DigestsOpen(context.Background(), file, []DigestAlgorithm{"sha3"}, nil); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unsupported-algorithm error = %v", err)
	}
	//lint:ignore SA1012 This regression test deliberately verifies that nil contexts fail closed.
	if _, err := DigestsOpen(nil, file, []DigestAlgorithm{DigestSHA256}, nil); err == nil || !strings.Contains(err.Error(), "context") {
		t.Fatalf("nil-context error = %v", err)
	}
	if _, err := DigestsOpen(context.Background(), nil, []DigestAlgorithm{DigestSHA256}, nil); err == nil || !strings.Contains(err.Error(), "file") {
		t.Fatalf("nil-file error = %v", err)
	}
}

func TestDigestsOpenCancellationRestoresOffset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "image.bin")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := file.Truncate(int64(3 * digestBufferSize)); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(7, 0); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err = DigestsOpen(ctx, file, []DigestAlgorithm{DigestSHA256, DigestSHA512}, func(done, total uint64) {
		if done >= digestBufferSize {
			cancel()
		}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
	position, seekErr := file.Seek(0, 1)
	if seekErr != nil {
		t.Fatal(seekErr)
	}
	if position != 7 {
		t.Fatalf("offset=%d want 7", position)
	}
}

func TestSHA256OpenCompatibility(t *testing.T) {
	path := filepath.Join(t.TempDir(), "image.bin")
	content := []byte("abcdef")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.Seek(3, 0); err != nil {
		t.Fatal(err)
	}
	got, err := SHA256Open(context.Background(), file, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(content)
	if got != want {
		t.Fatalf("digest=%x want %x", got, want)
	}
	position, err := file.Seek(0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if position != 3 {
		t.Fatalf("offset=%d want 3", position)
	}
}

func TestDigestsOpenRejectsShrinkDuringHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "image.bin")
	const originalSize = int64(3 * digestBufferSize)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := file.Truncate(originalSize); err != nil {
		t.Fatal(err)
	}
	mutated := false
	_, err = DigestsOpen(context.Background(), file, []DigestAlgorithm{DigestMD5, DigestSHA256}, func(done, total uint64) {
		if !mutated && done >= digestBufferSize {
			mutated = true
			if truncateErr := os.Truncate(path, int64(digestBufferSize)); truncateErr != nil {
				t.Errorf("truncate during hash: %v", truncateErr)
			}
		}
	})
	if err == nil || !strings.Contains(err.Error(), "size changed") {
		t.Fatalf("shrink error = %v", err)
	}
	if !mutated {
		t.Fatal("test did not mutate the file")
	}
}
