#!/usr/bin/env python3
import pathlib

root = pathlib.Path(__file__).resolve().parents[1]

def replace_once(path, old, new):
    p = root / path
    text = p.read_text()
    if text.count(old) != 1:
        raise SystemExit(f"{path}: expected one replacement anchor, found {text.count(old)}")
    p.write_text(text.replace(old, new, 1))

replace_once("internal/acquisition/download.go", "\tReplace     bool\n\tProgress    func(Progress)\n", "\tReplace     bool\n\tResume      bool\n\tProgress    func(Progress)\n")
replace_once("internal/acquisition/download.go", "\tReused bool   `json:\"reused\"`\n", "\tReused  bool   `json:\"reused\"`\n\tResumed uint64 `json:\"resumed_bytes,omitempty\"`\n")
start = (root / "internal/acquisition/download.go").read_text().index("func Download(")
end = (root / "internal/acquisition/download.go").read_text().index("func resolveDestination", start)
text = (root / "internal/acquisition/download.go").read_text()
new_download = r'''func Download(ctx context.Context, image Image, options DownloadOptions) (DownloadResult, error) {
	if ctx == nil {
		return DownloadResult{}, errors.New("download context is nil")
	}
	if err := image.validateWithPolicy(options.AllowHTTP); err != nil {
		return DownloadResult{}, err
	}
	destination, err := resolveDestination(options.Destination, image.Filename)
	if err != nil {
		return DownloadResult{}, err
	}
	if result, handled, err := existingDownload(destination, image, options.Replace); handled || err != nil {
		return result, err
	}
	directory := filepath.Dir(destination)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return DownloadResult{}, fmt.Errorf("create download directory: %w", err)
	}

	partial, offset, digest, err := openDownloadPartial(destination, image, options.Resume)
	if err != nil {
		return DownloadResult{}, err
	}
	partialPath := partial.Name()
	keepPartial := options.Resume
	cleanup := func(remove bool) {
		_ = partial.Close()
		if remove {
			_ = os.Remove(partialPath)
		}
	}
	defer func() {
		_ = partial.Close()
		if !keepPartial {
			_ = os.Remove(partialPath)
		}
	}()

	remaining := image.Size - offset
	preflightSize := image.Size
	if options.Resume && !options.Replace {
		preflightSize = remaining
	}
	if remaining > 0 {
		if err := preflightDownloadSpace(destination, preflightSize, options.spaceAvailable); err != nil {
			cleanup(!options.Resume)
			return DownloadResult{}, err
		}
		client := secureHTTPClient(image, options.AllowHTTP)
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, image.URL, nil)
		if err != nil {
			cleanup(!options.Resume)
			return DownloadResult{}, fmt.Errorf("create image request: %w", err)
		}
		request.Header.Set("User-Agent", "RufusUbuntuArm64-acquisition/1")
		request.Header.Set("Accept", "application/octet-stream")
		request.Header.Set("Accept-Encoding", "identity")
		if offset > 0 {
			request.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
		}
		response, err := client.Do(request)
		if err != nil {
			_ = partial.Sync()
			cleanup(!options.Resume)
			return DownloadResult{}, fmt.Errorf("download %s: %w", image.ID, err)
		}
		protocolErr := validateDownloadResponse(response, image.Size, offset)
		if protocolErr != nil {
			_ = response.Body.Close()
			keepPartial = false
			cleanup(true)
			return DownloadResult{}, fmt.Errorf("download %s: %w", image.ID, protocolErr)
		}
		tracker := &progressReader{
			reader:   io.LimitReader(response.Body, int64(remaining)+1),
			total:    image.Size,
			done:     offset,
			callback: options.Progress,
			started:  time.Now(),
			lastEmit: time.Now(),
		}
		writer := io.MultiWriter(partial, digest)
		written, copyErr := io.CopyBuffer(writer, tracker, make([]byte, downloadBufferSize))
		closeErr := response.Body.Close()
		if copyErr != nil {
			_ = partial.Sync()
			cleanup(!options.Resume)
			return DownloadResult{}, fmt.Errorf("download %s: %w", image.ID, copyErr)
		}
		if closeErr != nil {
			_ = partial.Sync()
			cleanup(!options.Resume)
			return DownloadResult{}, fmt.Errorf("close download response: %w", closeErr)
		}
		if uint64(written) != remaining {
			keepPartial = false
			cleanup(true)
			return DownloadResult{}, fmt.Errorf("download %s: received %d resumed bytes, expected %d", image.ID, written, remaining)
		}
	}

	info, err := partial.Stat()
	if err != nil || !info.Mode().IsRegular() || uint64(info.Size()) != image.Size {
		keepPartial = false
		cleanup(true)
		if err != nil {
			return DownloadResult{}, fmt.Errorf("inspect completed partial download: %w", err)
		}
		return DownloadResult{}, fmt.Errorf("download %s: completed partial size %d does not match signed size %d", image.ID, info.Size(), image.Size)
	}
	actual := hex.EncodeToString(digest.Sum(nil))
	if actual != image.SHA256 {
		keepPartial = false
		cleanup(true)
		return DownloadResult{}, fmt.Errorf("download %s: SHA-256 mismatch (expected %s, got %s)", image.ID, image.SHA256, actual)
	}
	if err := partial.Sync(); err != nil {
		cleanup(!options.Resume)
		return DownloadResult{}, fmt.Errorf("sync temporary download: %w", err)
	}
	if err := partial.Chmod(0o644); err != nil {
		cleanup(!options.Resume)
		return DownloadResult{}, fmt.Errorf("set downloaded image permissions: %w", err)
	}
	if err := partial.Close(); err != nil {
		return DownloadResult{}, fmt.Errorf("close temporary download: %w", err)
	}
	if err := installDownloadedFile(partialPath, destination, options.Replace); err != nil {
		return DownloadResult{}, fmt.Errorf("install downloaded image: %w", err)
	}
	keepPartial = true
	if err := syncDirectory(directory); err != nil {
		return DownloadResult{}, err
	}
	if options.Progress != nil {
		options.Progress(Progress{Done: image.Size, Total: image.Size})
	}
	return DownloadResult{Path: destination, URL: image.URL, SHA256: actual, Size: image.Size, Resumed: offset}, nil
}

'''
(root / "internal/acquisition/download.go").write_text(text[:start] + new_download + text[end:])

resume_go = r'''package acquisition

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func resumePartialPath(destination string, image Image) string {
	return filepath.Join(filepath.Dir(destination), "."+filepath.Base(destination)+"."+image.SHA256[:16]+".rufus.part")
}

func openDownloadPartial(destination string, image Image, resume bool) (*os.File, uint64, hash.Hash, error) {
	if !resume {
		file, err := os.CreateTemp(filepath.Dir(destination), ".rufus-download-*.part")
		if err != nil {
			return nil, 0, nil, fmt.Errorf("create temporary download: %w", err)
		}
		if err := file.Chmod(0o600); err != nil {
			_ = file.Close()
			_ = os.Remove(file.Name())
			return nil, 0, nil, fmt.Errorf("secure temporary download: %w", err)
		}
		return file, 0, sha256.New(), nil
	}
	path := resumePartialPath(destination, image)
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("open resumable partial without following links: %w", err)
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = syscall.Close(fd)
		return nil, 0, nil, fmt.Errorf("lock resumable partial: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, 0, nil, errors.New("open resumable partial returned an invalid file handle")
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, 0, nil, fmt.Errorf("inspect resumable partial: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		_ = file.Close()
		return nil, 0, nil, errors.New("resumable partial must be an owner-only regular file")
	}
	if info.Size() < 0 || uint64(info.Size()) > image.Size {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, 0, nil, fmt.Errorf("resumable partial size %d exceeds signed image size %d", info.Size(), image.Size)
	}
	digest := sha256.New()
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, 0, nil, fmt.Errorf("rewind resumable partial: %w", err)
	}
	if _, err := io.CopyBuffer(digest, file, make([]byte, downloadBufferSize)); err != nil {
		_ = file.Close()
		return nil, 0, nil, fmt.Errorf("hash resumable partial: %w", err)
	}
	current, err := file.Stat()
	if err != nil || current.Size() != info.Size() || !current.ModTime().Equal(info.ModTime()) {
		_ = file.Close()
		return nil, 0, nil, errors.New("resumable partial changed while it was being verified")
	}
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		_ = file.Close()
		return nil, 0, nil, fmt.Errorf("seek resumable partial end: %w", err)
	}
	return file, uint64(info.Size()), digest, nil
}

func validateDownloadResponse(response *http.Response, total, offset uint64) error {
	encoding := strings.TrimSpace(strings.ToLower(response.Header.Get("Content-Encoding")))
	if encoding != "" && encoding != "identity" {
		return fmt.Errorf("server returned unsupported content encoding %q", encoding)
	}
	remaining := total - offset
	if offset == 0 {
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("HTTP %s", response.Status)
		}
		if response.ContentLength >= 0 && uint64(response.ContentLength) != total {
			return fmt.Errorf("server size %d does not match signed catalog size %d", response.ContentLength, total)
		}
		return nil
	}
	if response.StatusCode != http.StatusPartialContent {
		return fmt.Errorf("server did not honor resume range: HTTP %s", response.Status)
	}
	start, end, responseTotal, err := parseContentRange(response.Header.Get("Content-Range"))
	if err != nil {
		return err
	}
	if start != offset || responseTotal != total || end+1 != total {
		return fmt.Errorf("server Content-Range %d-%d/%d does not match requested %d-%d/%d", start, end, responseTotal, offset, total-1, total)
	}
	if response.ContentLength >= 0 && uint64(response.ContentLength) != remaining {
		return fmt.Errorf("server remaining size %d does not match expected %d", response.ContentLength, remaining)
	}
	return nil
}

func parseContentRange(value string) (uint64, uint64, uint64, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "bytes ") {
		return 0, 0, 0, errors.New("server returned a missing or invalid Content-Range")
	}
	parts := strings.Split(strings.TrimPrefix(value, "bytes "), "/")
	if len(parts) != 2 {
		return 0, 0, 0, errors.New("server returned an invalid Content-Range")
	}
	bounds := strings.Split(parts[0], "-")
	if len(bounds) != 2 {
		return 0, 0, 0, errors.New("server returned invalid Content-Range bounds")
	}
	start, err1 := strconv.ParseUint(bounds[0], 10, 64)
	end, err2 := strconv.ParseUint(bounds[1], 10, 64)
	total, err3 := strconv.ParseUint(parts[1], 10, 64)
	if err1 != nil || err2 != nil || err3 != nil || start > end || end >= total {
		return 0, 0, 0, errors.New("server returned invalid Content-Range numbers")
	}
	return start, end, total, nil
}
'''
(root / "internal/acquisition/resume.go").write_text(resume_go)

resume_test = r'''package acquisition

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
	if err := os.WriteFile(partial, data[:offset], 0o600); err != nil { t.Fatal(err) }
	result, err := Download(context.Background(), image, DownloadOptions{Destination: destination, Resume: true, AllowHTTP: true})
	if err != nil { t.Fatal(err) }
	if seenRange != fmt.Sprintf("bytes=%d-", offset) || result.Resumed != uint64(offset) { t.Fatalf("range=%q result=%+v", seenRange, result) }
	stored, _ := os.ReadFile(destination)
	if string(stored) != string(data) { t.Fatal("resumed content mismatch") }
	if _, err := os.Stat(partial); !errors.Is(err, os.ErrNotExist) { t.Fatalf("partial remains: %v", err) }
}

func TestResumableDownloadRejectsIgnoredRangeAndRemovesPartial(t *testing.T) {
	data := []byte("complete signed image")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(data) }))
	defer server.Close()
	image := testImage(server.URL, data)
	destination := filepath.Join(t.TempDir(), image.Filename)
	partial := resumePartialPath(destination, image)
	if err := os.WriteFile(partial, data[:5], 0o600); err != nil { t.Fatal(err) }
	_, err := Download(context.Background(), image, DownloadOptions{Destination: destination, Resume: true, AllowHTTP: true})
	if err == nil || !strings.Contains(err.Error(), "did not honor resume range") { t.Fatalf("error=%v", err) }
	if _, statErr := os.Stat(partial); !errors.Is(statErr, os.ErrNotExist) { t.Fatalf("partial remains: %v", statErr) }
}

func TestResumableCancellationRetainsPartialButDefaultRemovesIt(t *testing.T) {
	data := bytesOf("cancel-resume", 8192)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, _ := w.(http.Flusher)
		for i := 0; i < len(data); i += 1024 {
			end := i+1024; if end > len(data) { end = len(data) }
			_, _ = w.Write(data[i:end]); if flusher != nil { flusher.Flush() }
		}
	}))
	defer server.Close()
	image := testImage(server.URL, data)
	for _, resume := range []bool{false, true} {
		dir := t.TempDir(); ctx, cancel := context.WithCancel(context.Background())
		_, err := Download(ctx, image, DownloadOptions{Destination: dir, Resume: resume, AllowHTTP: true, Progress: func(p Progress) { if p.Done > 0 { cancel() } }})
		cancel()
		if err == nil { t.Fatal("expected cancellation") }
		partials, _ := filepath.Glob(filepath.Join(dir, ".*.part"))
		if resume && len(partials) != 1 { t.Fatalf("resume partials=%v", partials) }
		if !resume && len(partials) != 0 { t.Fatalf("default partials=%v", partials) }
	}
}

func TestContentRangeValidation(t *testing.T) {
	start, end, total, err := parseContentRange("bytes 5-9/10")
	if err != nil || start != 5 || end != 9 || total != 10 { t.Fatalf("parsed=%d,%d,%d err=%v", start,end,total,err) }
	for _, value := range []string{"", "items 5-9/10", "bytes 9-5/10", "bytes 5-10/10"} {
		if _, _, _, err := parseContentRange(value); err == nil { t.Fatalf("accepted %q", value) }
	}
}
'''
(root / "internal/acquisition/resume_test.go").write_text(resume_test)

# CLI: add --resume to both download commands and pass through.
for anchor in [
    'replace := fs.Bool("replace", false, "replace an existing different regular file")\n\tasJSON := fs.Bool("json", false, "output final JSON result")',
]:
    p = root / "cmd/rufus-linux/main.go"
    text = p.read_text()
    count = text.count(anchor)
    if count != 2:
        raise SystemExit(f"main.go: expected two download flag anchors, found {count}")
    text = text.replace(anchor, 'replace := fs.Bool("replace", false, "replace an existing different regular file")\n\tresume := fs.Bool("resume", false, "retain and resume a signed-identity partial download")\n\tasJSON := fs.Bool("json", false, "output final JSON result")')
    text = text.replace('Destination: *output,\n\t\tReplace:     *replace,', 'Destination: *output,\n\t\tReplace:     *replace,\n\t\tResume:      *resume,')
    p.write_text(text)

# Human output reports resumed bytes when applicable.
replace_once("cmd/rufus-linux/main.go", 'fmt.Printf("%s: %s\\nSource: %s\\nSize: %s\\nSHA-256: %s\\n", status, result.Path, result.URL, humanBytes(result.Size), result.SHA256)', 'if result.Resumed > 0 {\n\t\tfmt.Printf("Resumed from: %s\\n", humanBytes(result.Resumed))\n\t}\n\tfmt.Printf("%s: %s\\nSource: %s\\nSize: %s\\nSHA-256: %s\\n", status, result.Path, result.URL, humanBytes(result.Size), result.SHA256)')
# second occurrence
replace_once("cmd/rufus-linux/main.go", 'fmt.Printf("%s: %s\\nSource: %s\\nSize: %s\\nSHA-256: %s\\n", status, result.Path, result.URL, humanBytes(result.Size), result.SHA256)', 'if result.Resumed > 0 {\n\t\tfmt.Printf("Resumed from: %s\\n", humanBytes(result.Resumed))\n\t}\n\tfmt.Printf("%s: %s\\nSource: %s\\nSize: %s\\nSHA-256: %s\\n", status, result.Path, result.URL, humanBytes(result.Size), result.SHA256)')

replace_once("docs/acquisition-catalog.md", '`--json-progress` emits the same byte/rate progress events used by the graphical application. `--json` emits the final result object.', '`--resume` opts into a deterministic owner-only partial file keyed by the signed image SHA-256. A resumed server must return an exact HTTP 206 range; the complete file is rehashed before atomic installation. Without `--resume`, cancellation continues to remove temporary partials. `--json-progress` emits the same byte/rate progress events used by the graphical application. `--json` emits the final result object, including `resumed_bytes` when applicable.')
