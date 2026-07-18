//go:build linux

package linuxmedia

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/geocausa/RufusArm64/internal/runtimeintegrity"
	"github.com/geocausa/RufusArm64/internal/secureboot"
	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

const persistentRuntimeMaximumLoaderSize = int64(32 * 1024 * 1024)

// RuntimeIntegrityResult reports the exact installed boot-time media validation
// state. SecureBootCompatible is disclosure metadata and is false for the
// current reproducibly built upstream loader.
type RuntimeIntegrityResult struct {
	OriginalSHA256       string `json:"original_sha256"`
	WrapperSHA256        string `json:"wrapper_sha256"`
	ManifestSHA256       string `json:"manifest_sha256"`
	SourceCommit         string `json:"source_commit"`
	SecureBootCompatible bool   `json:"secure_boot_compatible"`
	VerificationValid    bool   `json:"verification_valid"`
}

type preparedPersistentRuntimeIntegrity struct {
	asset runtimeintegrity.LoaderAsset
}

func preparePersistentRuntimeIntegrity(ctx context.Context, opts PersistentCreateOptions) (*preparedPersistentRuntimeIntegrity, error) {
	if !opts.RuntimeUEFIValidation {
		return nil, nil
	}
	if ctx == nil {
		return nil, errors.New("runtime UEFI validation context is nil")
	}
	architecture := strings.ToLower(strings.TrimSpace(opts.Architecture))
	if architecture != "arm64" && architecture != "aarch64" {
		return nil, fmt.Errorf("runtime UEFI validation requires ARM64 media, not %q", opts.Architecture)
	}
	if !opts.RuntimeUEFIUnsignedAcknowledged {
		return nil, errors.New("runtime UEFI validation requires explicit acknowledgement that the current loader is unsigned")
	}
	path := strings.TrimSpace(opts.RuntimeUEFILoaderPath)
	if path == "" {
		return nil, errors.New("runtime UEFI validation requires an exact loader path")
	}
	expected := strings.ToLower(strings.TrimSpace(opts.RuntimeUEFILoaderSHA256))
	decoded, err := hex.DecodeString(expected)
	if err != nil || len(decoded) != sha256.Size {
		return nil, errors.New("runtime UEFI loader SHA-256 is invalid")
	}
	sourceCommit := strings.TrimSpace(opts.RuntimeUEFILoaderSourceCommit)
	provenance := strings.TrimSpace(opts.RuntimeUEFILoaderProvenance)
	if sourceCommit == "" || provenance == "" {
		return nil, errors.New("runtime UEFI loader source commit and provenance are required")
	}
	_, identity, err := sourcefile.Inspect(path)
	if err != nil {
		return nil, fmt.Errorf("inspect runtime UEFI loader: %w", err)
	}
	if identity.Size <= 0 || identity.Size > persistentRuntimeMaximumLoaderSize {
		return nil, fmt.Errorf("runtime UEFI loader must be between 1 and %d bytes", persistentRuntimeMaximumLoaderSize)
	}
	file, err := sourcefile.OpenRegular(path, identity)
	if err != nil {
		return nil, fmt.Errorf("open runtime UEFI loader: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, persistentRuntimeMaximumLoaderSize+1))
	if err != nil {
		return nil, fmt.Errorf("read runtime UEFI loader: %w", err)
	}
	if int64(len(data)) != identity.Size {
		return nil, errors.New("runtime UEFI loader changed while it was being read")
	}
	if err := sourcefile.VerifyPinned(file, identity); err != nil {
		return nil, fmt.Errorf("revalidate runtime UEFI loader: %w", err)
	}
	digest := sha256.Sum256(data)
	actual := hex.EncodeToString(digest[:])
	if actual != expected {
		return nil, fmt.Errorf("runtime UEFI loader SHA-256 is %s, expected %s", actual, expected)
	}
	image, err := secureboot.InspectEFIImage(data)
	if err != nil {
		return nil, fmt.Errorf("inspect runtime UEFI loader PE image: %w", err)
	}
	if image.Machine != secureboot.MachineARM64 || image.Subsystem != secureboot.SubsystemEFIApplication {
		return nil, fmt.Errorf("runtime UEFI loader is %s/%s, expected ARM64 EFI application", image.MachineName, image.SubsystemName)
	}
	return &preparedPersistentRuntimeIntegrity{asset: runtimeintegrity.LoaderAsset{
		Data:                 data,
		ExpectedSHA256:       expected,
		SourceCommit:         sourceCommit,
		Provenance:           provenance,
		SecureBootCompatible: false,
	}}, nil
}

func hashPersistentRuntimeFallback(ctx context.Context, root string) (string, error) {
	path := filepath.Join(root, filepath.FromSlash(runtimeintegrity.ARM64FallbackPath))
	_, identity, err := sourcefile.Inspect(path)
	if err != nil {
		return "", fmt.Errorf("inspect original ARM64 fallback loader: %w", err)
	}
	file, err := sourcefile.OpenRegular(path, identity)
	if err != nil {
		return "", fmt.Errorf("open original ARM64 fallback loader: %w", err)
	}
	defer file.Close()
	digest, err := sourcefile.SHA256Open(ctx, file, nil)
	if err != nil {
		return "", fmt.Errorf("hash original ARM64 fallback loader: %w", err)
	}
	if err := sourcefile.VerifyPinned(file, identity); err != nil {
		return "", fmt.Errorf("revalidate original ARM64 fallback loader: %w", err)
	}
	return hex.EncodeToString(digest[:]), nil
}

func installPersistentRuntimeIntegrity(ctx context.Context, root string, prepared *preparedPersistentRuntimeIntegrity, maxFiles int) (runtimeintegrity.InstallResult, error) {
	if prepared == nil {
		return runtimeintegrity.InstallResult{}, errors.New("runtime UEFI validation was not prepared")
	}
	return runtimeintegrity.InstallARM64(ctx, root, prepared.asset, runtimeintegrity.TransactionOptions{MaxFiles: maxFiles})
}
