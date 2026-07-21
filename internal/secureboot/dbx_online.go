package secureboot

import (
	"context"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const microsoftDBXRepositoryCommit = "06fe58a31d2da381fb68c6d9f30af0dfb91cbe3a"

var microsoftDBXBlobSHA1 = map[string]string{
	"x86":   "142584cbd3ac2045aa6936e3c5e1814fc8b28149",
	"amd64": "f6ccec74a078267d56222b44d31ad30757ee8717",
	"arm":   "feb134b01b59c0d95730466ca75a31d326848c99",
	"arm64": "33520068f2602fbd2c739b7f71e8946f5ba6ccd4",
}

// MicrosoftDBXPin identifies one reviewed immutable file in Microsoft's
// secureboot_objects repository. GitBlobSHA1 is a Git object identity, not a
// general-purpose cryptographic trust claim. The reviewed commit and blob pair
// is the online trust anchor because this package validates the authenticated
// update structure but does not independently verify its PKCS#7 signer chain.
type MicrosoftDBXPin struct {
	Architecture     string `json:"architecture"`
	RepositoryCommit string `json:"repository_commit"`
	GitBlobSHA1      string `json:"git_blob_sha1"`
	URL              string `json:"url"`
}

func MicrosoftDBXPinForArchitecture(arch string) (MicrosoftDBXPin, error) {
	normalized, err := ArchitectureName(arch)
	if err != nil {
		return MicrosoftDBXPin{}, err
	}
	blob, ok := microsoftDBXBlobSHA1[normalized]
	if !ok {
		return MicrosoftDBXPin{}, fmt.Errorf("Microsoft publishes no reviewed pinned DBX object for architecture %q", normalized)
	}
	pin := MicrosoftDBXPin{
		Architecture:     normalized,
		RepositoryCommit: microsoftDBXRepositoryCommit,
		GitBlobSHA1:      blob,
		URL: "https://raw.githubusercontent.com/microsoft/secureboot_objects/" + microsoftDBXRepositoryCommit +
			"/PostSignedObjects/DBX/" + normalized + "/DBXUpdate.bin",
	}
	if err := validateMicrosoftDBXPin(pin); err != nil {
		return MicrosoftDBXPin{}, err
	}
	return pin, nil
}

func MicrosoftDBXURL(arch string) (string, error) {
	pin, err := MicrosoftDBXPinForArchitecture(arch)
	if err != nil {
		return "", err
	}
	return pin.URL, nil
}

func validateMicrosoftDBXPin(pin MicrosoftDBXPin) error {
	architecture, err := ArchitectureName(pin.Architecture)
	if err != nil {
		return err
	}
	if architecture != pin.Architecture {
		return errors.New("Microsoft DBX pin architecture must use its canonical name")
	}
	commit, err := decodeGitObjectID(pin.RepositoryCommit, "repository commit")
	if err != nil {
		return err
	}
	blob, err := decodeGitObjectID(pin.GitBlobSHA1, "Git blob")
	if err != nil {
		return err
	}
	if len(commit) != sha1.Size || len(blob) != sha1.Size {
		return errors.New("Microsoft DBX pin object IDs must be complete SHA-1 values")
	}
	expectedURL := "https://raw.githubusercontent.com/microsoft/secureboot_objects/" + strings.ToLower(pin.RepositoryCommit) +
		"/PostSignedObjects/DBX/" + architecture + "/DBXUpdate.bin"
	if pin.URL != expectedURL {
		return errors.New("Microsoft DBX pin URL does not match its immutable commit and architecture")
	}
	return nil
}

func decodeGitObjectID(value, label string) ([]byte, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed != strings.ToLower(trimmed) || len(trimmed) != sha1.Size*2 {
		return nil, fmt.Errorf("%s must be a 40-character lowercase Git object ID", label)
	}
	decoded, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", label, err)
	}
	return decoded, nil
}

func gitBlobSHA1(data []byte) []byte {
	hash := sha1.New() // Git's object format requires SHA-1 for this repository identity.
	_, _ = fmt.Fprintf(hash, "blob %d%c", len(data), byte(0))
	_, _ = hash.Write(data)
	return hash.Sum(nil)
}

func verifyGitBlobSHA1(data []byte, expected string) (string, error) {
	expectedBytes, err := decodeGitObjectID(expected, "Git blob")
	if err != nil {
		return "", err
	}
	actualBytes := gitBlobSHA1(data)
	actual := hex.EncodeToString(actualBytes)
	if subtle.ConstantTimeCompare(actualBytes, expectedBytes) != 1 {
		return actual, fmt.Errorf("downloaded DBX Git blob identity mismatch: expected %s, got %s", expected, actual)
	}
	return actual, nil
}

type DownloadResult struct {
	Path             string  `json:"path"`
	URL              string  `json:"url"`
	SHA256           string  `json:"sha256"`
	RepositoryCommit string  `json:"repository_commit"`
	GitBlobSHA1      string  `json:"git_blob_sha1"`
	Summary          Summary `json:"summary"`
}

func validateDBXRedirect(req *http.Request, via []*http.Request) error {
	if req == nil || req.URL == nil {
		return errors.New("invalid DBX download redirect")
	}
	if len(via) >= 5 {
		return errors.New("too many DBX download redirects")
	}
	if !strings.EqualFold(req.URL.Scheme, "https") {
		return fmt.Errorf("refusing DBX redirect to non-HTTPS URL %q", req.URL.String())
	}
	if req.URL.User != nil {
		return errors.New("refusing DBX redirect with URL credentials")
	}
	host := strings.ToLower(req.URL.Hostname())
	if host != "raw.githubusercontent.com" && host != "github.com" && host != "objects.githubusercontent.com" {
		return fmt.Errorf("refusing DBX redirect to untrusted host %q", host)
	}
	return nil
}

func DownloadMicrosoftDBX(ctx context.Context, arch, destination string) (DownloadResult, error) {
	if ctx == nil {
		return DownloadResult{}, errors.New("DBX download context is required")
	}
	pin, err := MicrosoftDBXPinForArchitecture(arch)
	if err != nil {
		return DownloadResult{}, err
	}
	client := &http.Client{
		Timeout:       60 * time.Second,
		CheckRedirect: validateDBXRedirect,
	}
	return downloadPinnedMicrosoftDBX(ctx, pin, destination, client)
}

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

func downloadPinnedMicrosoftDBX(ctx context.Context, pin MicrosoftDBXPin, destination string, client httpDoer) (DownloadResult, error) {
	if ctx == nil {
		return DownloadResult{}, errors.New("DBX download context is required")
	}
	if client == nil {
		return DownloadResult{}, errors.New("DBX HTTP client is required")
	}
	if err := validateMicrosoftDBXPin(pin); err != nil {
		return DownloadResult{}, fmt.Errorf("validate Microsoft DBX pin: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, pin.URL, nil)
	if err != nil {
		return DownloadResult{}, err
	}
	request.Header.Set("User-Agent", "RufusArm64-secureboot/1")
	response, err := client.Do(request)
	if err != nil {
		return DownloadResult{}, fmt.Errorf("download Microsoft DBX: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return DownloadResult{}, fmt.Errorf("download Microsoft DBX: HTTP %s", response.Status)
	}
	if response.ContentLength > maxDBXDownload {
		return DownloadResult{}, errors.New("downloaded DBX response is unexpectedly large")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxDBXDownload+1))
	if err != nil {
		return DownloadResult{}, fmt.Errorf("read Microsoft DBX response: %w", err)
	}
	if int64(len(data)) > maxDBXDownload {
		return DownloadResult{}, errors.New("downloaded DBX response is unexpectedly large")
	}
	return validateAndCachePinnedDBX(data, pin, destination)
}

func validateAndCachePinnedDBX(data []byte, pin MicrosoftDBXPin, destination string) (DownloadResult, error) {
	if err := validateMicrosoftDBXPin(pin); err != nil {
		return DownloadResult{}, fmt.Errorf("validate Microsoft DBX pin: %w", err)
	}
	actualBlob, err := verifyGitBlobSHA1(data, pin.GitBlobSHA1)
	if err != nil {
		return DownloadResult{}, err
	}
	db, err := Parse(data, pin.URL)
	if err != nil {
		return DownloadResult{}, fmt.Errorf("validate downloaded Microsoft DBX: %w", err)
	}
	if !db.Authenticated {
		return DownloadResult{}, errors.New("downloaded DBX does not use the authenticated UEFI variable-update format")
	}
	if destination == "" {
		cacheRoot, err := os.UserCacheDir()
		if err != nil {
			return DownloadResult{}, fmt.Errorf("locate user cache: %w", err)
		}
		destination = filepath.Join(cacheRoot, "rufusarm64", "dbx", pin.Architecture+"-DBXUpdate.bin")
	}
	destination, err = filepath.Abs(destination)
	if err != nil {
		return DownloadResult{}, fmt.Errorf("resolve DBX destination: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return DownloadResult{}, fmt.Errorf("create DBX cache directory: %w", err)
	}
	temp, err := os.CreateTemp(filepath.Dir(destination), ".dbx-download-")
	if err != nil {
		return DownloadResult{}, fmt.Errorf("create DBX temporary file: %w", err)
	}
	tempName := temp.Name()
	cleanup := func() {
		_ = temp.Close()
		_ = os.Remove(tempName)
	}
	if err := temp.Chmod(0o600); err != nil {
		cleanup()
		return DownloadResult{}, err
	}
	if _, err := temp.Write(data); err != nil {
		cleanup()
		return DownloadResult{}, fmt.Errorf("write DBX temporary file: %w", err)
	}
	if err := temp.Sync(); err != nil {
		cleanup()
		return DownloadResult{}, fmt.Errorf("sync DBX temporary file: %w", err)
	}
	if err := temp.Close(); err != nil {
		_ = os.Remove(tempName)
		return DownloadResult{}, fmt.Errorf("close DBX temporary file: %w", err)
	}
	if err := os.Rename(tempName, destination); err != nil {
		_ = os.Remove(tempName)
		return DownloadResult{}, fmt.Errorf("install DBX cache: %w", err)
	}
	return DownloadResult{
		Path:             destination,
		URL:              pin.URL,
		SHA256:           db.FileSHA256,
		RepositoryCommit: pin.RepositoryCommit,
		GitBlobSHA1:      actualBlob,
		Summary:          db.Summary(),
	}, nil
}
