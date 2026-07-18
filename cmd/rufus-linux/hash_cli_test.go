package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

func checksumFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "image.bin")
	if err := os.WriteFile(path, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestHashCLICompatibilityOutput(t *testing.T) {
	path := checksumFixture(t)
	output, err := captureStdout(t, func() error { return runHash([]string{path}) })
	if err != nil {
		t.Fatal(err)
	}
	const digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if want := digest + "  " + path + "\n"; output != want {
		t.Fatalf("output=%q want %q", output, want)
	}
}

func TestHashCLIAllJSON(t *testing.T) {
	path := checksumFixture(t)
	output, err := captureStdout(t, func() error {
		return runHash([]string{"--all", "--json", path})
	})
	if err != nil {
		t.Fatal(err)
	}
	var result hashCommandOutput
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatal(err)
	}
	if result.Path != path || result.Size != 3 {
		t.Fatalf("unexpected hash metadata: %#v", result)
	}
	algorithms := sourcefile.SupportedDigestAlgorithms()
	if len(result.Digests) != len(algorithms) {
		t.Fatalf("digests=%d want %d", len(result.Digests), len(algorithms))
	}
	for index, digest := range result.Digests {
		if digest.Algorithm != algorithms[index] || digest.Hex == "" {
			t.Fatalf("digest %d = %#v", index, digest)
		}
	}
}

func TestHashCLIExplicitOrderAndLabels(t *testing.T) {
	path := checksumFixture(t)
	output, err := captureStdout(t, func() error {
		return runHash([]string{"--algorithm", "sha-1", "--algorithm", "md5", path})
	})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "SHA-1: ") || !strings.HasPrefix(lines[1], "MD5: ") {
		t.Fatalf("unexpected ordered output: %q", output)
	}
}

func TestHashCLIRejectsInvalidArguments(t *testing.T) {
	path := checksumFixture(t)
	for _, args := range [][]string{
		nil,
		{path, path},
		{"--all", "--algorithm", "sha256", path},
		{"--algorithm", "sha-256", "--algorithm", "sha256", path},
		{"--algorithm", "crc32", path},
		{"--json", path, "extra"},
	} {
		if err := runHash(args); err == nil {
			t.Fatalf("invalid arguments accepted: %v", args)
		}
	}
}

func TestHashCLIRejectsEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.img")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runHash([]string{path}); err == nil || !strings.Contains(err.Error(), "non-empty regular file") {
		t.Fatalf("empty-file error = %v", err)
	}
}

func TestHashCLICancellation(t *testing.T) {
	path := checksumFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runHashWithContext(ctx, []string{"--all", path}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
}
