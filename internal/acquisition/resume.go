package acquisition

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
