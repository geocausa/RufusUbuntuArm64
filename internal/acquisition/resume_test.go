package acquisition

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResumableDownloadContinuesExactRange(t *testing.T) {
	data := bytesOf("resume", 4096)
	var seenRange string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenRange = r.Header.Get("Range")
		offset := len(data) / 3
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", offset, len(data)-1, len(data)))
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)-offset))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(data[offset:])
	}))
	defer server.Close()
	image := testImage(server.URL, data)
	dir := t.TempDir()
	destination := filepath.Join(dir, image.Filename)
	partial := resumePartialPath(destination, image)
	offset := len(data) / 3
	if err := os.WriteFile(partial, data[:offset], 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Download(context.Background(), image, DownloadOptions{Destination: destination, Resume: true, AllowHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	if seenRange != fmt.Sprintf("bytes=%d-", offset) || result.Resumed != uint64(offset) {
		t.Fatalf("range=%q result=%+v", seenRange, result)
	}
	stored, _ := os.ReadFile(destination)
	if string(stored) != string(data) {
		t.Fatal("resumed content mismatch")
	}
	if _, err := os.Stat(partial); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial remains: %v", err)
	}
}

func TestResumableDownloadRejectsIgnoredRangeAndRemovesPartial(t *testing.T) {
	data := []byte("complete signed image")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(data) }))
	defer server.Close()
	image := testImage(server.URL, data)
	destination := filepath.Join(t.TempDir(), image.Filename)
	partial := resumePartialPath(destination, image)
	if err := os.WriteFile(partial, data[:5], 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Download(context.Background(), image, DownloadOptions{Destination: destination, Resume: true, AllowHTTP: true})
	if err == nil || !strings.Contains(err.Error(), "did not honor resume range") {
		t.Fatalf("error=%v", err)
	}
	if _, statErr := os.Stat(partial); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("partial remains: %v", statErr)
	}
}

func TestResumableCancellationRetainsPartialButDefaultRemovesIt(t *testing.T) {
	data := bytesOf("cancel-resume", 8192)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, _ := w.(http.Flusher)
		for i := 0; i < len(data); i += 1024 {
			end := i + 1024
			if end > len(data) {
				end = len(data)
			}
			_, _ = w.Write(data[i:end])
			if flusher != nil {
				flusher.Flush()
			}
			time.Sleep(5 * time.Millisecond)
		}
	}))
	defer server.Close()
	image := testImage(server.URL, data)
	for _, resume := range []bool{false, true} {
		dir := t.TempDir()
		ctx, cancel := context.WithCancel(context.Background())
		_, err := Download(ctx, image, DownloadOptions{Destination: dir, Resume: resume, AllowHTTP: true, Progress: func(p Progress) {
			if p.Done > 0 {
				cancel()
			}
		}})
		cancel()
		if err == nil {
			t.Fatal("expected cancellation")
		}
		partials, _ := filepath.Glob(filepath.Join(dir, ".*.part"))
		if resume && len(partials) != 1 {
			t.Fatalf("resume partials=%v", partials)
		}
		if !resume && len(partials) != 0 {
			t.Fatalf("default partials=%v", partials)
		}
	}
}

func TestContentRangeValidation(t *testing.T) {
	start, end, total, err := parseContentRange("bytes 5-9/10")
	if err != nil || start != 5 || end != 9 || total != 10 {
		t.Fatalf("parsed=%d,%d,%d err=%v", start, end, total, err)
	}
	for _, value := range []string{"", "items 5-9/10", "bytes 9-5/10", "bytes 5-10/10"} {
		if _, _, _, err := parseContentRange(value); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
}
