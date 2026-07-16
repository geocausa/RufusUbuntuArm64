package acquisition

import (
	"context"
	"crypto/sha256"
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
	Progress    func(Progress)
	// AllowHTTP is only for isolated tests. Production callers must leave it false.
	AllowHTTP bool
}

type DownloadResult struct {
	Path   string `json:"path"`
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   uint64 `json:"size"`
	Reused bool   `json:"reused"`
}

func Download(ctx context.Context, image Image, options DownloadOptions) (DownloadResult, error) {
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
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return DownloadResult{}, fmt.Errorf("create download directory: %w", err)
	}
	client := secureHTTPClient(image, options.AllowHTTP)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, image.URL, nil)
	if err != nil {
		return DownloadResult{}, fmt.Errorf("create image request: %w", err)
	}
	request.Header.Set("User-Agent", "RufusUbuntuArm64-acquisition/1")
	request.Header.Set("Accept", "application/octet-stream")
	response, err := client.Do(request)
	if err != nil {
		return DownloadResult{}, fmt.Errorf("download %s: %w", image.ID, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return DownloadResult{}, fmt.Errorf("download %s: HTTP %s", image.ID, response.Status)
	}
	if response.ContentLength >= 0 && uint64(response.ContentLength) != image.Size {
		return DownloadResult{}, fmt.Errorf("download %s: server size %d does not match signed catalog size %d", image.ID, response.ContentLength, image.Size)
	}
	temp, err := os.CreateTemp(filepath.Dir(destination), ".rufus-download-*.part")
	if err != nil {
		return DownloadResult{}, fmt.Errorf("create temporary download: %w", err)
	}
	tempName := temp.Name()
	cleanup := func() {
		_ = temp.Close()
		_ = os.Remove(tempName)
	}
	if err := temp.Chmod(0o600); err != nil {
		cleanup()
		return DownloadResult{}, fmt.Errorf("secure temporary download: %w", err)
	}
	digest := sha256.New()
	writer := io.MultiWriter(temp, digest)
	tracker := &progressReader{
		reader:   io.LimitReader(response.Body, int64(image.Size)+1),
		total:    image.Size,
		callback: options.Progress,
		started:  time.Now(),
		lastEmit: time.Now(),
	}
	written, err := io.CopyBuffer(writer, tracker, make([]byte, downloadBufferSize))
	if err != nil {
		cleanup()
		return DownloadResult{}, fmt.Errorf("download %s: %w", image.ID, err)
	}
	if uint64(written) != image.Size {
		cleanup()
		return DownloadResult{}, fmt.Errorf("download %s: received %d bytes, expected %d", image.ID, written, image.Size)
	}
	actual := hex.EncodeToString(digest.Sum(nil))
	if actual != image.SHA256 {
		cleanup()
		return DownloadResult{}, fmt.Errorf("download %s: SHA-256 mismatch (expected %s, got %s)", image.ID, image.SHA256, actual)
	}
	if err := temp.Sync(); err != nil {
		cleanup()
		return DownloadResult{}, fmt.Errorf("sync temporary download: %w", err)
	}
	if err := temp.Chmod(0o644); err != nil {
		cleanup()
		return DownloadResult{}, fmt.Errorf("set downloaded image permissions: %w", err)
	}
	if err := temp.Close(); err != nil {
		_ = os.Remove(tempName)
		return DownloadResult{}, fmt.Errorf("close temporary download: %w", err)
	}
	if err := os.Rename(tempName, destination); err != nil {
		_ = os.Remove(tempName)
		return DownloadResult{}, fmt.Errorf("install downloaded image: %w", err)
	}
	if err := syncDirectory(filepath.Dir(destination)); err != nil {
		return DownloadResult{}, err
	}
	if options.Progress != nil {
		options.Progress(Progress{Done: image.Size, Total: image.Size, BytesPerSec: tracker.rate()})
	}
	return DownloadResult{Path: destination, URL: image.URL, SHA256: actual, Size: image.Size}, nil
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
		digest, hashErr := hashFile(path)
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
			host := strings.ToLower(request.URL.Hostname())
			if _, ok := allowed[host]; !ok {
				return fmt.Errorf("refusing image redirect to unsigned host %q", host)
			}
			return nil
		},
	}
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open existing download: %w", err)
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.CopyBuffer(digest, file, make([]byte, downloadBufferSize)); err != nil {
		return "", fmt.Errorf("hash existing download: %w", err)
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
