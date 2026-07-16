package acquisition

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testImage(serverURL string, data []byte) Image {
	digest := sha256.Sum256(data)
	return Image{
		ID:           "test-image",
		Name:         "Test Image",
		Version:      "1",
		Architecture: "arm64",
		Filename:     "test.iso",
		URL:          serverURL,
		SHA256:       hex.EncodeToString(digest[:]),
		Size:         uint64(len(data)),
	}
}

func TestDownloadVerifiedImageAndReuse(t *testing.T) {
	data := bytesOf("rufus-download", 4096)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Length", "57344")
		_, _ = writer.Write(data)
	}))
	defer server.Close()
	image := testImage(server.URL, data)
	directory := t.TempDir()
	var progress []Progress
	result, err := Download(context.Background(), image, DownloadOptions{Destination: directory, AllowHTTP: true, Progress: func(value Progress) { progress = append(progress, value) }})
	if err != nil {
		t.Fatal(err)
	}
	if result.Path != filepath.Join(directory, image.Filename) || result.SHA256 != image.SHA256 || result.Reused {
		t.Fatalf("unexpected result: %+v", result)
	}
	stored, err := os.ReadFile(result.Path)
	if err != nil || string(stored) != string(data) {
		t.Fatalf("stored download mismatch: %v", err)
	}
	if len(progress) == 0 || progress[len(progress)-1].Done != image.Size {
		t.Fatalf("missing final progress: %+v", progress)
	}
	reused, err := Download(context.Background(), image, DownloadOptions{Destination: result.Path, AllowHTTP: true})
	if err != nil || !reused.Reused {
		t.Fatalf("existing verified download not reused: %+v, %v", reused, err)
	}
}

func TestDownloadRejectsChecksumMismatchAndPreservesDestination(t *testing.T) {
	data := []byte("downloaded")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) { _, _ = writer.Write(data) }))
	defer server.Close()
	image := testImage(server.URL, data)
	image.SHA256 = strings.Repeat("00", 32)
	destination := filepath.Join(t.TempDir(), "test.iso")
	if err := os.WriteFile(destination, []byte("existing"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Download(context.Background(), image, DownloadOptions{Destination: destination, Replace: true, AllowHTTP: true}); err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("checksum mismatch error = %v", err)
	}
	stored, err := os.ReadFile(destination)
	if err != nil || string(stored) != "existing" {
		t.Fatalf("existing destination was changed: %q, %v", stored, err)
	}
}

func TestDownloadRejectsUnexpectedSize(t *testing.T) {
	data := []byte("short")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) { _, _ = writer.Write(data) }))
	defer server.Close()
	image := testImage(server.URL, append(data, '!'))
	if _, err := Download(context.Background(), image, DownloadOptions{Destination: t.TempDir(), AllowHTTP: true}); err == nil || !strings.Contains(err.Error(), "server size") {
		t.Fatalf("size mismatch error = %v", err)
	}
}

func TestDownloadRejectsUnsignedRedirectHost(t *testing.T) {
	data := []byte("redirect")
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, strings.Replace(server.URL, "127.0.0.1", "localhost", 1)+"/image", http.StatusFound)
	}))
	defer server.Close()
	image := testImage(server.URL, data)
	if _, err := Download(context.Background(), image, DownloadOptions{Destination: t.TempDir(), AllowHTTP: true}); err == nil || !strings.Contains(err.Error(), "unsigned host") {
		t.Fatalf("redirect error = %v", err)
	}
}

func bytesOf(value string, repeats int) []byte {
	return []byte(strings.Repeat(value, repeats))
}
