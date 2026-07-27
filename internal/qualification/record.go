//go:build linux

package qualification

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	CreationSchema  = 1
	EvidenceSchema  = 1
	maxRecordBytes  = 256 * 1024
	metadataDirName = ".rufusarm64"
	RecordFileName  = "creation.json"
)

type PartitionRecord struct {
	Number     int    `json:"number"`
	StartBytes uint64 `json:"start_bytes"`
	SizeBytes  uint64 `json:"size_bytes"`
	Filesystem string `json:"filesystem"`
	Label      string `json:"label"`
}

type CreationRecord struct {
	Schema          int               `json:"schema"`
	Creator         string            `json:"creator"`
	CreatedAt       time.Time         `json:"created_at"`
	SourceSHA256    string            `json:"source_sha256"`
	SourceSize      uint64            `json:"source_size"`
	Architecture    string            `json:"architecture"`
	Family          string            `json:"family"`
	DisplayName     string            `json:"display_name"`
	TargetSize      uint64            `json:"target_size"`
	LogicalSector   uint64            `json:"logical_sector_size"`
	Boot            PartitionRecord   `json:"boot_partition"`
	Persistence     PartitionRecord   `json:"persistence_partition"`
	BootParameter   string            `json:"boot_parameter"`
	ManifestEntries int               `json:"manifest_entries"`
	ManifestBytes   uint64            `json:"manifest_bytes"`
	PatchedPaths    []string          `json:"patched_paths"`
	Properties      map[string]string `json:"properties,omitempty"`
}

type StoredRecord struct {
	Record CreationRecord
	SHA256 string
	Path   string
}

func NormalizeRecord(record CreationRecord) (CreationRecord, error) {
	record.Schema = CreationSchema
	record.Creator = strings.TrimSpace(record.Creator)
	record.Architecture = strings.ToLower(strings.TrimSpace(record.Architecture))
	record.Family = strings.ToLower(strings.TrimSpace(record.Family))
	record.DisplayName = strings.TrimSpace(record.DisplayName)
	record.BootParameter = strings.TrimSpace(record.BootParameter)
	record.SourceSHA256 = strings.ToLower(strings.TrimSpace(record.SourceSHA256))
	record.CreatedAt = record.CreatedAt.UTC().Truncate(time.Second)
	if record.CreatedAt.IsZero() {
		return record, errors.New("creation timestamp is required")
	}
	if record.Creator == "" || record.Architecture == "" || record.Family == "" || record.DisplayName == "" {
		return record, errors.New("creator, architecture, family, and display name are required")
	}
	if len(record.SourceSHA256) != sha256.Size*2 {
		return record, errors.New("source SHA-256 has the wrong length")
	}
	if _, err := hex.DecodeString(record.SourceSHA256); err != nil {
		return record, errors.New("source SHA-256 is invalid")
	}
	if record.SourceSize == 0 || record.TargetSize == 0 || record.LogicalSector < 512 || record.LogicalSector&(record.LogicalSector-1) != 0 {
		return record, errors.New("creation record has invalid source or target geometry")
	}
	if err := validatePartition(record.Boot, 1); err != nil {
		return record, fmt.Errorf("boot partition: %w", err)
	}
	if err := validatePartition(record.Persistence, 2); err != nil {
		return record, fmt.Errorf("persistence partition: %w", err)
	}
	bootEnd, err := partitionExtentEnd(record.Boot.StartBytes, record.Boot.SizeBytes)
	if err != nil {
		return record, fmt.Errorf("boot partition extent: %w", err)
	}
	persistenceEnd, err := partitionExtentEnd(record.Persistence.StartBytes, record.Persistence.SizeBytes)
	if err != nil {
		return record, fmt.Errorf("persistence partition extent: %w", err)
	}
	if bootEnd > record.TargetSize || persistenceEnd > record.TargetSize || bootEnd > record.Persistence.StartBytes {
		return record, errors.New("creation record partitions overlap or exceed the target")
	}
	if record.BootParameter == "" || record.ManifestEntries <= 0 || record.ManifestBytes == 0 {
		return record, errors.New("creation record has incomplete media evidence")
	}
	paths := append([]string(nil), record.PatchedPaths...)
	for index := range paths {
		paths[index] = filepath.ToSlash(filepath.Clean(strings.TrimSpace(paths[index])))
		if paths[index] == "." || !filepath.IsLocal(filepath.FromSlash(paths[index])) {
			return record, fmt.Errorf("unsafe patched path %q", paths[index])
		}
	}
	sort.Strings(paths)
	record.PatchedPaths = paths[:0]
	for _, value := range paths {
		if len(record.PatchedPaths) == 0 || record.PatchedPaths[len(record.PatchedPaths)-1] != value {
			record.PatchedPaths = append(record.PatchedPaths, value)
		}
	}
	properties, err := normalizeRecordProperties(record.Properties)
	if err != nil {
		return record, err
	}
	record.Properties = properties
	return record, nil
}

func validatePartition(partition PartitionRecord, expectedNumber int) error {
	if partition.Number != expectedNumber || partition.StartBytes == 0 || partition.SizeBytes == 0 {
		return errors.New("invalid number or extent")
	}
	if strings.TrimSpace(partition.Filesystem) == "" || strings.TrimSpace(partition.Label) == "" {
		return errors.New("filesystem and label are required")
	}
	return nil
}

func MarshalRecord(record CreationRecord) ([]byte, string, error) {
	normalized, err := NormalizeRecord(record)
	if err != nil {
		return nil, "", err
	}
	data, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		return nil, "", err
	}
	data = append(data, '\n')
	digest := sha256.Sum256(data)
	return data, hex.EncodeToString(digest[:]), nil
}

func ParseRecord(data []byte) (CreationRecord, string, error) {
	if len(data) == 0 || len(data) > maxRecordBytes {
		return CreationRecord{}, "", errors.New("creation record is empty or too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var record CreationRecord
	if err := decoder.Decode(&record); err != nil {
		return record, "", fmt.Errorf("decode creation record: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return record, "", err
	}
	normalized, err := NormalizeRecord(record)
	if err != nil {
		return record, "", err
	}
	canonical, digest, err := MarshalRecord(normalized)
	if err != nil {
		return record, "", err
	}
	if !bytes.Equal(canonical, data) {
		return record, "", errors.New("creation record is not in canonical form")
	}
	return normalized, digest, nil
}

func WriteRecord(root string, record CreationRecord) (StoredRecord, error) {
	normalized, err := NormalizeRecord(record)
	if err != nil {
		return StoredRecord{}, err
	}
	data, digest, err := MarshalRecord(normalized)
	if err != nil {
		return StoredRecord{}, err
	}
	root, err = realDirectory(root)
	if err != nil {
		return StoredRecord{}, err
	}
	metadata := filepath.Join(root, metadataDirName)
	if err := ensureRealDirectory(metadata, 0o700); err != nil {
		return StoredRecord{}, err
	}
	recordPath := filepath.Join(metadata, RecordFileName)
	if err := writeRecordPair(recordPath, data, digest); err != nil {
		return StoredRecord{}, err
	}
	return StoredRecord{Record: normalized, SHA256: digest, Path: filepath.ToSlash(filepath.Join(metadataDirName, RecordFileName))}, nil
}

func LoadVerifiedRecord(path string) (StoredRecord, error) {
	data, err := readRegularNoFollow(path, maxRecordBytes)
	if err != nil {
		return StoredRecord{}, fmt.Errorf("read creation record: %w", err)
	}
	record, digest, err := ParseRecord(data)
	if err != nil {
		return StoredRecord{}, err
	}
	checksumData, err := readRegularNoFollow(path+".sha256", 4096)
	if err != nil {
		return StoredRecord{}, fmt.Errorf("read creation record checksum: %w", err)
	}
	scanner := bufio.NewScanner(bytes.NewReader(checksumData))
	if !scanner.Scan() {
		return StoredRecord{}, errors.New("creation record checksum file is malformed")
	}
	line := scanner.Text()
	if scanner.Scan() || scanner.Err() != nil {
		return StoredRecord{}, errors.New("creation record checksum file is malformed")
	}
	fields := strings.Fields(line)
	if len(fields) != 2 || fields[0] != digest || fields[1] != filepath.Base(path) {
		return StoredRecord{}, errors.New("creation record checksum mismatch")
	}
	return StoredRecord{Record: record, SHA256: digest, Path: path}, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON input contains more than one value")
		}
		return fmt.Errorf("decode trailing JSON: %w", err)
	}
	return nil
}

func realDirectory(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", errors.New("metadata root must be a real directory")
	}
	return absolute, nil
}

func ensureRealDirectory(path string, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return os.Mkdir(path, mode)
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("metadata directory must be a real directory")
	}
	return nil
}

func writeAtomicNoFollow(path string, data []byte, mode os.FileMode) (returnErr error) {
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("metadata parent must be a real directory")
	}
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("metadata file %s already exists", filepath.Base(path))
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(parent, ".rufusarm64-metadata-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer func() {
		if temporary != nil {
			returnErr = errors.Join(returnErr, temporary.Close())
		}
		_ = os.Remove(name)
	}()
	if err := temporary.Chmod(mode); err != nil {
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		temporary = nil
		return err
	}
	temporary = nil
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return errors.New("metadata destination appeared during write")
		}
		return err
	}
	if err := renameMetadataNoReplace(name, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return errors.New("metadata destination appeared during write")
		}
		return err
	}
	directory, err := os.Open(parent)
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		directory.Close()
		return err
	}
	return directory.Close()
}

type metadataOpenFunc func(string) (*os.File, error)

func openMetadataNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

func readRegularNoFollow(path string, limit int64) ([]byte, error) {
	return readRegularNoFollowWithOpen(path, limit, openMetadataNoFollow)
}

func readRegularNoFollowWithOpen(path string, limit int64, open metadataOpenFunc) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > limit {
		return nil, errors.New("metadata input must be a bounded real regular file")
	}
	file, err := open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !openedInfo.Mode().IsRegular() || openedInfo.Size() < 0 || openedInfo.Size() > limit {
		return nil, errors.New("metadata input must be a bounded real regular file")
	}
	if !os.SameFile(info, openedInfo) {
		return nil, errors.New("metadata input changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("metadata input exceeds the size limit")
	}
	return data, nil
}
