#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one replacement target, found {count}")
    file_path.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_once(
    "cmd/rufus-linux/main.go",
    "  rufusarm64-cli hash FILE\n",
    "  rufusarm64-cli hash [--algorithm ALGORITHM]... [--all] [--json] FILE\n",
)
replace_once(
    "cmd/rufus-linux/main.go",
    '''func runHash(args []string) error {
\tif len(args) != 1 {
\t\treturn errors.New("hash requires exactly one file")
\t}
\th, err := imaging.SHA256File(args[0])
\tif err != nil {
\t\treturn err
\t}
\tfmt.Printf("%s  %s\\n", h, args[0])
\treturn nil
}
''',
    '''func runHash(args []string) error {
\treturn runHashCommand(args)
}
''',
)

Path("cmd/rufus-linux/hash_cli.go").write_text(r'''package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

type digestAlgorithmFlags []sourcefile.DigestAlgorithm

func (values *digestAlgorithmFlags) String() string {
	parts := make([]string, len(*values))
	for index, value := range *values {
		parts[index] = string(value)
	}
	return strings.Join(parts, ",")
}

func (values *digestAlgorithmFlags) Set(value string) error {
	algorithm, err := sourcefile.ParseDigestAlgorithm(value)
	if err != nil {
		return err
	}
	for _, existing := range *values {
		if existing == algorithm {
			return fmt.Errorf("duplicate digest algorithm %q", algorithm)
		}
	}
	*values = append(*values, algorithm)
	return nil
}

type hashCommandOutput struct {
	Path    string                    `json:"path"`
	Size    uint64                    `json:"size"`
	Digests []sourcefile.DigestResult `json:"digests"`
}

func runHashCommand(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return runHashWithContext(ctx, args)
}

func runHashWithContext(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("hash", flag.ContinueOnError)
	var requested digestAlgorithmFlags
	flags.Var(&requested, "algorithm", "checksum algorithm: md5, sha1, sha256, or sha512; repeat to select more than one")
	all := flags.Bool("all", false, "compute MD5, SHA-1, SHA-256, and SHA-512")
	asJSON := flags.Bool("json", false, "output JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("hash requires exactly one file")
	}
	if *all && len(requested) != 0 {
		return errors.New("select either --all or one or more --algorithm values")
	}

	algorithms := []sourcefile.DigestAlgorithm(requested)
	if *all {
		algorithms = sourcefile.SupportedDigestAlgorithms()
	} else if len(algorithms) == 0 {
		algorithms = []sourcefile.DigestAlgorithm{sourcefile.DigestSHA256}
	}

	inputPath := flags.Arg(0)
	resolvedPath, identity, err := sourcefile.Inspect(inputPath)
	if err != nil {
		return err
	}
	file, err := sourcefile.OpenRegular(resolvedPath, identity)
	if err != nil {
		return err
	}
	results, digestErr := sourcefile.DigestsOpen(ctx, file, algorithms, nil)
	closeErr := file.Close()
	if digestErr != nil {
		return digestErr
	}
	if closeErr != nil {
		return fmt.Errorf("close image after hashing: %w", closeErr)
	}

	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(hashCommandOutput{
			Path:    resolvedPath,
			Size:    uint64(identity.Size),
			Digests: results,
		})
	}

	// Preserve the original sha256sum-compatible output for existing scripts.
	if !*all && len(requested) == 0 {
		fmt.Printf("%s  %s\n", results[0].Hex, inputPath)
		return nil
	}
	for _, result := range results {
		fmt.Printf("%s: %s  %s\n", digestDisplayName(result.Algorithm), result.Hex, inputPath)
	}
	return nil
}

func digestDisplayName(algorithm sourcefile.DigestAlgorithm) string {
	switch algorithm {
	case sourcefile.DigestMD5:
		return "MD5"
	case sourcefile.DigestSHA1:
		return "SHA-1"
	case sourcefile.DigestSHA256:
		return "SHA-256"
	case sourcefile.DigestSHA512:
		return "SHA-512"
	default:
		return strings.ToUpper(string(algorithm))
	}
}
''', encoding="utf-8")

Path("cmd/rufus-linux/hash_cli_test.go").write_text(r'''package main

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
''', encoding="utf-8")

replace_once(
    "docs/rufusarm64-cli.1",
    ".PP\n.B sudo rufusarm64-cli write\n",
    '''.PP
.B rufusarm64-cli hash
.RI [ --algorithm " md5|sha1|sha256|sha512" ] ...
.RI [ --all ]
.RI [ --json ]
.I FILE
.PP
.B sudo rufusarm64-cli write
''',
)
replace_once(
    "docs/rufusarm64-cli.1",
    ".SH UEFI MEDIA VALIDATION\n",
    '''.SH IMAGE CHECKSUMS
.B hash
computes checksums from one identity-bound, already-open regular-file descriptor.
With no options it computes SHA-256 and retains the historical
.B sha256sum
compatible output used by existing scripts.
.PP
Repeat
.B --algorithm
with md5, sha1, sha256, or sha512 to select an ordered subset, or use
.B --all
to compute the stable Rufus-compatible four-algorithm set in one pass.
.B --json
emits the resolved path, file size, and ordered lowercase hexadecimal digests.
The command is unprivileged and responds to SIGINT and SIGTERM without opening a
block device or invoking Polkit. MD5 and SHA-1 are provided only to compare with
legacy published checksums; they are not used for trust, signatures, downloads,
or destructive-write assurance.
.SH UEFI MEDIA VALIDATION
''',
)
replace_once(
    "README.md",
    "rufusarm64-cli inspect --image Windows.iso.xz --json\n",
    "rufusarm64-cli inspect --image Windows.iso.xz --json\nrufusarm64-cli hash --all ubuntu.iso\n",
)
replace_once(
    "scripts/test.sh",
    '''expected_hash="$(sha256sum "${native_dir}/sample.img" | awk '{print $1}')"
actual_hash="$("${native_helper}" hash "${native_dir}/sample.img" | awk '{print $1}')"
[[ "${actual_hash}" == "${expected_hash}" ]]
''',
    '''expected_hash="$(sha256sum "${native_dir}/sample.img" | awk '{print $1}')"
actual_hash="$("${native_helper}" hash "${native_dir}/sample.img" | awk '{print $1}')"
[[ "${actual_hash}" == "${expected_hash}" ]]
"${native_helper}" hash --all --json "${native_dir}/sample.img" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["size"] == 16 and [item["algorithm"] for item in d["digests"]] == ["md5", "sha1", "sha256", "sha512"]'
''',
)
