package acquisition

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const downloadBufferSize = 1024 * 1024

type Progress struct {
	Done        uint64
	Total       uint64
	BytesPerSec float64
}

type DownloadOptions struct {
	Destination string
	Replace     bool
	Resume      bool
	Progress    func(Progress)
	// AllowHTTP is only for isolated tests. Production callers must leave it false.
	AllowHTTP bool
	// spaceAvailable is an isolated-test seam. Production callers always use statfs.
	spaceAvailable spaceProbe
}

type DownloadResult struct {
	Path    string `json:"path"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
	Size    uint64 `json:"size"`
	Reused  bool   `json:"reused"`
	Resumed uint64 `json:"resumed_bytes,omitempty"`
}

func Download(ctx context.Context, image Image, options DownloadOptions) (DownloadResult, error) {
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
	currentPartial, err := os.Lstat(partialPath)
	if err != nil || !currentPartial.Mode().IsRegular() || !os.SameFile(info, currentPartial) {
		keepPartial = false
		cleanup(true)
		if err != nil {
			return DownloadResult{}, fmt.Errorf("reinspect completed partial path: %w", err)
		}
		return DownloadResult{}, errors.New("resumable partial path changed before atomic installation")
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
	_ = os.Remove(partialPath)
	keepPartial = true
	if err := syncDirectory(directory); err != nil {
		return DownloadResult{}, err
	}
	if options.Progress != nil {
		options.Progress(Progress{Done: image.Size, Total: image.Size})
	}
	return DownloadResult{Path: destination, URL: image.URL, SHA256: actual, Size: image.Size, Resumed: offset}, nil
}

func resolveDestination(value, filename string) (string, error) {
	if err := validateFilename(filename); err != nil {
		return "", err
	}
	if strings.TrimSpace(value) == "" {
		value = filename
	} else if info, err := os.Stat(value); err == nil && info.IsDir() {
		value = filepath.Join(value, filename)
	}
	absolute, err := filepath.Abs(value)
	if err != nil {
		return "", fmt.Errorf("resolve download destination: %w", err)
	}
	return absolute, nil
}

func existingDownload(path string, image Image, replace bool) (DownloadResult, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return DownloadResult{}, false, nil
	}
	if err != nil {
		return DownloadResult{}, true, fmt.Errorf("inspect existing destination: %w", err)
	}
	if !info.Mode().IsRegular() {
		return DownloadResult{}, true, errors.New("download destination exists and is not a regular file")
	}
	if uint64(info.Size()) == image.Size {
		digest, hashErr := hashExistingDownload(path, info)
		if hashErr != nil {
			return DownloadResult{}, true, hashErr
		}
		if digest == image.SHA256 {
			return DownloadResult{Path: path, URL: image.URL, SHA256: digest, Size: image.Size, Reused: true}, true, nil
		}
	}
	if !replace {
		return DownloadResult{}, true, errors.New("download destination already exists with different content; use --replace to overwrite it")
	}
	return DownloadResult{}, false, nil
}

// installDownloadedFile preserves the no-replace contract at the final atomic
// boundary. The temporary file is created in the destination directory, so a
// hard link installs the verified inode without a cross-filesystem copy and
// fails atomically if another process created the destination during transfer.
func installDownloadedFile(tempName, destination string, replace bool) error {
	if replace {
		return os.Rename(tempName, destination)
	}
	if err := os.Link(tempName, destination); err != nil {
		if errors.Is(err, os.ErrExist) {
			return errors.New("download destination was created while the image was downloading; refusing to replace it")
		}
		return err
	}
	return nil
}

func secureHTTPClient(image Image, allowHTTP bool) *http.Client {
	allowed := make(map[string]struct{}, len(image.RedirectHosts)+1)
	if parsed, err := url.Parse(image.URL); err == nil {
		allowed[strings.ToLower(parsed.Hostname())] = struct{}{}
	}
	for _, host := range image.RedirectHosts {
		allowed[strings.ToLower(host)] = struct{}{}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyFromEnvironment
	transport.DisableCompression = true
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	transport.DialContext = (&net.Dialer{Timeout: 20 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	transport.ResponseHeaderTimeout = 30 * time.Second
	transport.IdleConnTimeout = 90 * time.Second
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 8 {
				return errors.New("too many image download redirects")
			}
			if request.URL.Scheme != "https" && !allowHTTP {
				return errors.New("refusing image redirect to a non-HTTPS URL")
			}
			if request.URL.Scheme == "https" && request.URL.Port() != "" && request.URL.Port() != "443" {
				return errors.New("refusing image redirect to a non-default HTTPS port")
			}
			host := strings.ToLower(request.URL.Hostname())
			if _, ok := allowed[host]; !ok {
				return fmt.Errorf("refusing image redirect to unsigned host %q", host)
			}
			return nil
		},
	}
}

func hashExistingDownload(path string, expected os.FileInfo) (string, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", fmt.Errorf("open existing download without following links: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return "", errors.New("open existing download returned an invalid file handle")
	}
	defer file.Close()

	before, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("inspect opened existing download: %w", err)
	}
	if !before.Mode().IsRegular() || !os.SameFile(expected, before) {
		return "", errors.New("existing download changed before it could be verified")
	}
	digest := sha256.New()
	if _, err := io.CopyBuffer(digest, file, make([]byte, downloadBufferSize)); err != nil {
		return "", fmt.Errorf("hash existing download: %w", err)
	}
	after, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("reinspect opened existing download: %w", err)
	}
	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return "", errors.New("existing download changed while it was being verified")
	}
	current, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("reinspect existing download path: %w", err)
	}
	if !current.Mode().IsRegular() || !os.SameFile(after, current) {
		return "", errors.New("existing download path changed while it was being verified")
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open download directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync download directory: %w", err)
	}
	return nil
}

type progressReader struct {
	reader   io.Reader
	total    uint64
	done     uint64
	callback func(Progress)
	started  time.Time
	lastEmit time.Time
}

func (reader *progressReader) Read(buffer []byte) (int, error) {
	count, err := reader.reader.Read(buffer)
	reader.done += uint64(count)
	if reader.callback != nil && (time.Since(reader.lastEmit) >= 250*time.Millisecond || err == io.EOF) {
		reader.callback(Progress{Done: reader.done, Total: reader.total, BytesPerSec: reader.rate()})
		reader.lastEmit = time.Now()
	}
	return count, err
}

func (reader *progressReader) rate() float64 {
	elapsed := time.Since(reader.started).Seconds()
	if elapsed <= 0 {
		return 0
	}
	return float64(reader.done) / elapsed
}
