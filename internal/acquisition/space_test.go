package acquisition

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
	if !errors.Is(err, ErrInsufficientSpace) {
		t.Fatalf("insufficient-space sentinel missing: %v", err)
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
