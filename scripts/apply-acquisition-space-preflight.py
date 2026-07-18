#!/usr/bin/env python3
"""Materialize the bounded acquisition storage-preflight tranche."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one replacement target, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


download = ROOT / "internal/acquisition/download.go"
replace_once(
    download,
    """type DownloadOptions struct {
\tDestination string
\tReplace     bool
\tProgress    func(Progress)
\t// AllowHTTP is only for isolated tests. Production callers must leave it false.
\tAllowHTTP bool
}
""",
    """type DownloadOptions struct {
\tDestination string
\tReplace     bool
\tProgress    func(Progress)
\t// AllowHTTP is only for isolated tests. Production callers must leave it false.
\tAllowHTTP bool
\t// spaceAvailable is an isolated-test seam. Production callers always use statfs.
\tspaceAvailable spaceProbe
}
""",
)
replace_once(
    download,
    """\tif err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
\t\treturn DownloadResult{}, fmt.Errorf("create download directory: %w", err)
\t}
\tclient := secureHTTPClient(image, options.AllowHTTP)
""",
    """\tif err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
\t\treturn DownloadResult{}, fmt.Errorf("create download directory: %w", err)
\t}
\tif err := preflightDownloadSpace(destination, image.Size, options.spaceAvailable); err != nil {
\t\treturn DownloadResult{}, err
\t}
\tclient := secureHTTPClient(image, options.AllowHTTP)
""",
)

(ROOT / "internal/acquisition/space.go").write_text(r'''package acquisition

import (
	"fmt"
	"path/filepath"
	"syscall"
)

const downloadSpaceReserve uint64 = 64 * 1024 * 1024

type spaceProbe func(string) (uint64, error)

// InsufficientSpaceError reports the exact destination-filesystem capacity
// decision made before an acquisition request is sent.
type InsufficientSpaceError struct {
	Directory string
	Required  uint64
	Available uint64
}

func (err *InsufficientSpaceError) Error() string {
	return fmt.Sprintf(
		"insufficient free space in %s for verified download: need %d bytes, have %d bytes",
		err.Directory,
		err.Required,
		err.Available,
	)
}

func preflightDownloadSpace(destination string, imageSize uint64, probe spaceProbe) error {
	directory := filepath.Dir(destination)
	required, err := requiredDownloadBytes(imageSize)
	if err != nil {
		return err
	}
	if probe == nil {
		probe = availableDownloadBytes
	}
	available, err := probe(directory)
	if err != nil {
		return fmt.Errorf("query available download space in %s: %w", directory, err)
	}
	if available < required {
		return &InsufficientSpaceError{
			Directory: directory,
			Required:  required,
			Available: available,
		}
	}
	return nil
}

func requiredDownloadBytes(imageSize uint64) (uint64, error) {
	if imageSize == 0 {
		return 0, fmt.Errorf("download image size must be greater than zero")
	}
	const maxUint64 = ^uint64(0)
	if imageSize > maxUint64-downloadSpaceReserve {
		return 0, fmt.Errorf("download storage requirement overflows: image size %d", imageSize)
	}
	return imageSize + downloadSpaceReserve, nil
}

func availableDownloadBytes(path string) (uint64, error) {
	var stats syscall.Statfs_t
	if err := syscall.Statfs(path, &stats); err != nil {
		return 0, err
	}
	if stats.Bsize <= 0 {
		return 0, fmt.Errorf("filesystem reported invalid block size %d", stats.Bsize)
	}
	blockSize := uint64(stats.Bsize)
	const maxUint64 = ^uint64(0)
	if stats.Bavail > maxUint64/blockSize {
		return 0, fmt.Errorf("filesystem available-byte count overflows")
	}
	return stats.Bavail * blockSize, nil
}
''', encoding="utf-8")

(ROOT / "internal/acquisition/space_test.go").write_text(r'''package acquisition

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestDownloadRejectsInsufficientSpaceBeforeNetwork(t *testing.T) {
	data := bytesOf("space-preflight", 1024)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		_, _ = writer.Write(data)
	}))
	defer server.Close()

	image := testImage(server.URL, data)
	directory := t.TempDir()
	required, err := requiredDownloadBytes(image.Size)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Download(context.Background(), image, DownloadOptions{
		Destination: directory,
		AllowHTTP:   true,
		spaceAvailable: func(path string) (uint64, error) {
			if path != directory {
				t.Fatalf("space probe path=%q want %q", path, directory)
			}
			return required - 1, nil
		},
	})
	var spaceErr *InsufficientSpaceError
	if !errors.As(err, &spaceErr) {
		t.Fatalf("insufficient-space error=%v", err)
	}
	if spaceErr.Required != required || spaceErr.Available != required-1 || spaceErr.Directory != directory {
		t.Fatalf("unexpected typed space error: %#v", spaceErr)
	}
	if requests.Load() != 0 {
		t.Fatalf("network request count=%d want 0", requests.Load())
	}
	if _, statErr := os.Stat(filepath.Join(directory, image.Filename)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("destination exists after rejected preflight: %v", statErr)
	}
	partials, globErr := filepath.Glob(filepath.Join(directory, ".rufus-download-*.part"))
	if globErr != nil || len(partials) != 0 {
		t.Fatalf("partial files remain: %v, %v", partials, globErr)
	}
}

func TestDownloadSpaceProbeFailureHappensBeforeNetwork(t *testing.T) {
	data := []byte("probe-failure")
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		_, _ = writer.Write(data)
	}))
	defer server.Close()

	sentinel := errors.New("statfs unavailable")
	image := testImage(server.URL, data)
	_, err := Download(context.Background(), image, DownloadOptions{
		Destination: t.TempDir(),
		AllowHTTP:   true,
		spaceAvailable: func(string) (uint64, error) {
			return 0, sentinel
		},
	})
	if !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "query available download space") {
		t.Fatalf("space-probe error=%v", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("network request count=%d want 0", requests.Load())
	}
}

func TestExistingVerifiedDownloadBypassesSpaceProbe(t *testing.T) {
	data := []byte("already verified")
	image := testImage("http://127.0.0.1:1/not-used", data)
	destination := filepath.Join(t.TempDir(), image.Filename)
	if err := os.WriteFile(destination, data, 0o644); err != nil {
		t.Fatal(err)
	}
	called := false
	result, err := Download(context.Background(), image, DownloadOptions{
		Destination: destination,
		AllowHTTP:   true,
		spaceAvailable: func(string) (uint64, error) {
			called = true
			return 0, errors.New("space probe must not run")
		},
	})
	if err != nil || !result.Reused {
		t.Fatalf("verified reuse result=%+v error=%v", result, err)
	}
	if called {
		t.Fatal("space probe ran for an already verified destination")
	}
}

func TestDownloadSpaceRequirementIncludesReserveAndRejectsOverflow(t *testing.T) {
	required, err := requiredDownloadBytes(1)
	if err != nil || required != 1+downloadSpaceReserve {
		t.Fatalf("required=%d error=%v", required, err)
	}
	if _, err := requiredDownloadBytes(0); err == nil {
		t.Fatal("zero image size accepted")
	}
	if _, err := requiredDownloadBytes(^uint64(0)); err == nil || !strings.Contains(err.Error(), "overflows") {
		t.Fatalf("overflow error=%v", err)
	}
}

func TestDownloadSpacePreflightAcceptsExactRequirement(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "image.iso")
	required, err := requiredDownloadBytes(4096)
	if err != nil {
		t.Fatal(err)
	}
	if err := preflightDownloadSpace(destination, 4096, func(path string) (uint64, error) {
		if path != filepath.Dir(destination) {
			t.Fatalf("space probe path=%q", path)
		}
		return required, nil
	}); err != nil {
		t.Fatal(err)
	}
}
''', encoding="utf-8")

doc = ROOT / "docs/acquisition-catalog.md"
replace_once(
    doc,
    """4. Every entry is validated for a safe filename, absolute HTTPS URL, bounded size, SHA-256 digest, and explicitly signed redirect hosts.
5. The image is written to a private temporary file, size-bounded, hashed while downloading, synchronized, and atomically installed only after the signed size and SHA-256 both match.
6. Existing files are reused only when their complete SHA-256 and size already match. Different files are never overwritten without `--replace`.
""",
    """4. Every entry is validated for a safe filename, absolute HTTPS URL, bounded size, SHA-256 digest, and explicitly signed redirect hosts.
5. Before any image request is sent, the destination filesystem must report enough unprivileged available space for the complete signed image plus a 64 MiB safety reserve. Replacement downloads retain the same full requirement because the old destination remains until atomic installation.
6. The image is written to a private temporary file, size-bounded, hashed while downloading, synchronized, and atomically installed only after the signed size and SHA-256 both match.
7. Existing files are reused only when their complete SHA-256 and size already match. Different files are never overwritten without `--replace`.
""",
)
replace_once(
    doc,
    """`--json-progress` emits the same byte/rate progress events used by the graphical application. `--json` emits the final result object. Cancellation through `SIGINT` or `SIGTERM` removes the temporary partial file.
""",
    """`--json-progress` emits the same byte/rate progress events used by the graphical application. `--json` emits the final result object. CLI and graphical downloads both fail before contacting the image server when the exact destination filesystem cannot prove the signed image size plus the 64 MiB reserve. Cancellation through `SIGINT` or `SIGTERM` removes the temporary partial file.
""",
)
