package runtimeintegrity

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	ARM64FallbackPath       = "EFI/BOOT/BOOTAA64.EFI"
	ARM64OriginalPath       = "EFI/BOOT/bootaa64_original.efi"
	installationCommentKey  = "rufusarm64_installation"
	installationCommentHead = "# " + installationCommentKey + " = "
	maximumLoaderSize       = 32 * 1024 * 1024
)

// LoaderAsset is an explicitly pinned runtime-integrity loader. ExpectedSHA256
// is mandatory; SecureBootCompatible is disclosure metadata, not a trust input.
type LoaderAsset struct {
	Data                 []byte `json:"-"`
	ExpectedSHA256       string `json:"expected_sha256"`
	SourceCommit         string `json:"source_commit,omitempty"`
	Provenance           string `json:"provenance,omitempty"`
	SecureBootCompatible bool   `json:"secure_boot_compatible"`
}

// TransactionOptions bounds the manifest scan. The hook is used only by
// package tests to inject deterministic failures at transaction boundaries.
type TransactionOptions struct {
	MaxFiles int
	hook     func(stage string) error
}

// InstallationRecord is embedded as a comment inside md5sum.txt. The records
// hash covers the canonical manifest without this comment, avoiding a
// self-referential digest while binding every listed file and total byte count.
type InstallationRecord struct {
	Schema                       int    `json:"schema"`
	Architecture                 string `json:"architecture"`
	FallbackPath                 string `json:"fallback_path"`
	OriginalPath                 string `json:"original_path"`
	OriginalSHA256               string `json:"original_sha256"`
	OriginalSize                 uint64 `json:"original_size"`
	OriginalMode                 uint32 `json:"original_mode"`
	WrapperSHA256                string `json:"wrapper_sha256"`
	WrapperSize                  uint64 `json:"wrapper_size"`
	WrapperSourceCommit          string `json:"wrapper_source_commit,omitempty"`
	WrapperProvenance            string `json:"wrapper_provenance,omitempty"`
	WrapperSecureBootCompatible  bool   `json:"wrapper_secure_boot_compatible"`
	ManifestRecordsSHA256        string `json:"manifest_records_sha256"`
}

// InstallResult reports the exact post-transaction state.
type InstallResult struct {
	Root           string             `json:"root"`
	Record         InstallationRecord `json:"record"`
	ManifestSHA256 string             `json:"manifest_sha256"`
	Verification   VerificationResult `json:"verification"`
}

// RemovalResult reports restoration of the original fallback loader.
type RemovalResult struct {
	Root                  string `json:"root"`
	RestoredSHA256        string `json:"restored_sha256"`
	RemovedManifestSHA256 string `json:"removed_manifest_sha256"`
}

func normalizedSHA256(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) != 64 {
		return "", errors.New("SHA-256 digest must contain exactly 64 hexadecimal characters")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return "", errors.New("SHA-256 digest contains non-hexadecimal data")
	}
	return value, nil
}

func sha256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func marshalInstalledManifest(standard []byte, record InstallationRecord) ([]byte, error) {
	if len(standard) == 0 || standard[len(standard)-1] != '\n' {
		return nil, errors.New("canonical manifest must end with a newline")
	}
	firstEnd := bytes.IndexByte(standard, '\n')
	if firstEnd < 0 {
		return nil, errors.New("canonical manifest is missing its first line")
	}
	encodedRecord, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	encoded := base64.RawURLEncoding.EncodeToString(encodedRecord)
	comment := []byte(installationCommentHead + encoded + "\n")
	if len(standard)+len(comment) > MaximumManifestSize {
		return nil, fmt.Errorf("installed manifest exceeds the %d-byte safety limit", MaximumManifestSize)
	}
	result := make([]byte, 0, len(standard)+len(comment))
	result = append(result, standard[:firstEnd+1]...)
	result = append(result, comment...)
	result = append(result, standard[firstEnd+1:]...)
	return result, nil
}

func parseInstallationRecord(data []byte) (InstallationRecord, []byte, error) {
	if len(data) == 0 || len(data) > MaximumManifestSize {
		return InstallationRecord{}, nil, errors.New("installed manifest is empty or oversized")
	}
	lines := bytes.Split(data, []byte{'\n'})
	var record InstallationRecord
	found := false
	canonical := make([]byte, 0, len(data))
	for index, line := range lines {
		if bytes.HasPrefix(line, []byte(installationCommentHead)) {
			if found {
				return InstallationRecord{}, nil, errors.New("manifest contains multiple RufusArm64 installation records")
			}
			encoded := strings.TrimSpace(strings.TrimPrefix(string(line), installationCommentHead))
			decoded, err := base64.RawURLEncoding.DecodeString(encoded)
			if err != nil {
				return InstallationRecord{}, nil, errors.New("manifest installation record is not valid base64url")
			}
			decoder := json.NewDecoder(bytes.NewReader(decoded))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&record); err != nil {
				return InstallationRecord{}, nil, fmt.Errorf("parse manifest installation record: %w", err)
			}
			if decoder.More() {
				return InstallationRecord{}, nil, errors.New("manifest installation record contains trailing JSON")
			}
			found = true
			continue
		}
		canonical = append(canonical, line...)
		if index != len(lines)-1 {
			canonical = append(canonical, '\n')
		}
	}
	if !found {
		return InstallationRecord{}, nil, errors.New("manifest does not contain a RufusArm64 installation record")
	}
	if record.Schema != 1 || record.Architecture != "arm64" || record.FallbackPath != ARM64FallbackPath || record.OriginalPath != ARM64OriginalPath {
		return InstallationRecord{}, nil, errors.New("manifest installation record has an unsupported schema or path contract")
	}
	if _, err := normalizedSHA256(record.OriginalSHA256); err != nil {
		return InstallationRecord{}, nil, fmt.Errorf("invalid original loader digest: %w", err)
	}
	if _, err := normalizedSHA256(record.WrapperSHA256); err != nil {
		return InstallationRecord{}, nil, fmt.Errorf("invalid wrapper digest: %w", err)
	}
	recordHash, err := normalizedSHA256(record.ManifestRecordsSHA256)
	if err != nil {
		return InstallationRecord{}, nil, fmt.Errorf("invalid canonical manifest digest: %w", err)
	}
	if sha256Hex(canonical) != recordHash {
		return InstallationRecord{}, nil, errors.New("canonical manifest records do not match the embedded installation record")
	}
	return record, canonical, nil
}
