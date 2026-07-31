//go:build linux

// Package uefintfs owns admission and exact publication of the pinned
// UEFI:NTFS boot image shared by Windows and Linux installation media.
package uefintfs

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	ImageSize       = uint64(1024 * 1024)
	ImageSHA256     = "72683fa1250eeea772d3399277b434d4e55ba8dd0dc926e52d817e701fc2eb9e"
	BundledImage    = "/usr/lib/rufusarm64/uefi-ntfs.img"
	ImageEnv        = "RUFUSARM64_UEFI_NTFS_IMAGE"
	copyBufferBytes = 4 * 1024 * 1024
)

// Asset is an already verified UEFI:NTFS image. Its evidence fields are kept
// private so callers cannot construct an unverified asset literal.
type Asset struct {
	path   string
	size   uint64
	digest [sha256.Size]byte
	report ArchitectureReport
}

func (asset Asset) Path() string { return asset.path }
func (asset Asset) Size() uint64 { return asset.size }
func (asset Asset) SHA256() string {
	return fmt.Sprintf("%x", asset.digest)
}

// ArchitectureReport returns a detached copy of the structurally verified
// multi-architecture loader manifest carried by the pinned image.
func (asset Asset) ArchitectureReport() (ArchitectureReport, error) {
	if asset.report.Schema != architectureReportSchema || asset.report.ManifestSHA256 == "" {
		return ArchitectureReport{}, errors.New("UEFI:NTFS architecture evidence is unavailable")
	}
	report := asset.report
	report.Architectures = append([]ArchitectureEvidence(nil), asset.report.Architectures...)
	return report, nil
}

// Partition identifies the exact whole-disk extent reserved for UEFI:NTFS.
type Partition struct {
	StartBytes uint64
	SizeBytes  uint64
}

// Target is the held whole-disk descriptor contract needed for publication.
type Target interface {
	io.ReaderAt
	io.WriterAt
	Sync() error
}

// Locate finds and verifies the pinned UEFI:NTFS image. An explicit environment
// override is authoritative and fails closed rather than falling back.
func Locate() (Asset, error) {
	if envPath := strings.TrimSpace(os.Getenv(ImageEnv)); envPath != "" {
		asset, err := verifyAsset(envPath, ImageSize, ImageSHA256)
		if err != nil {
			return Asset{}, fmt.Errorf("verify %s override: %w", ImageEnv, err)
		}
		return asset, nil
	}

	candidates := make([]string, 0, 3)
	if executable, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(executable), "uefi-ntfs.img"))
	}
	candidates = append(candidates, BundledImage, filepath.Join("vendor", "uefi-ntfs", "uefi-ntfs.img"))
	for _, candidate := range candidates {
		_, err := os.Lstat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return Asset{}, fmt.Errorf("inspect UEFI:NTFS image %s: %w", candidate, err)
		}
		asset, err := verifyAsset(candidate, ImageSize, ImageSHA256)
		if err != nil {
			return Asset{}, err
		}
		return asset, nil
	}
	return Asset{}, errors.New("NTFS boot support is unavailable because the verified UEFI:NTFS image is missing")
}

// WriteAndVerify copies the complete verified image to the held whole-disk
// descriptor, flushes it, and compares the full target extent by SHA-256.
func WriteAndVerify(target Target, asset Asset, partition Partition) error {
	if target == nil {
		return errors.New("nil UEFI:NTFS target")
	}
	if err := validatePartition(asset, partition); err != nil {
		return err
	}
	image, current, err := openVerifiedAsset(asset.path, asset.size, asset.SHA256())
	if err != nil {
		return fmt.Errorf("reverify UEFI:NTFS image before writing: %w", err)
	}
	defer image.Close()
	if current.digest != asset.digest {
		return errors.New("UEFI:NTFS image evidence changed before writing")
	}
	if asset.report.Schema != 0 && current.report.ManifestSHA256 != asset.report.ManifestSHA256 {
		return errors.New("UEFI:NTFS architecture evidence changed before writing")
	}

	writer := io.NewOffsetWriter(target, int64(partition.StartBytes))
	written, err := io.CopyBuffer(writer, image, make([]byte, copyBufferBytes))
	if err != nil {
		return fmt.Errorf("write UEFI:NTFS partition image: %w", err)
	}
	if uint64(written) != partition.SizeBytes {
		return fmt.Errorf("short UEFI:NTFS image write: wrote %d of %d bytes", written, partition.SizeBytes)
	}
	if err := target.Sync(); err != nil {
		return fmt.Errorf("flush UEFI:NTFS partition image: %w", err)
	}

	hash := sha256.New()
	reader := io.NewSectionReader(target, int64(partition.StartBytes), int64(partition.SizeBytes))
	if _, err := io.CopyBuffer(hash, reader, make([]byte, copyBufferBytes)); err != nil {
		return fmt.Errorf("read back UEFI:NTFS partition image: %w", err)
	}
	if !bytes.Equal(asset.digest[:], hash.Sum(nil)) {
		return errors.New("UEFI:NTFS partition image verification failed: SHA-256 mismatch")
	}
	return nil
}

// VerifyPartitionPath compares a kernel partition node or synthetic regular
// partition file against the admitted asset after partition-table reread.
func VerifyPartitionPath(partitionPath string, asset Asset) error {
	if asset.path == "" || asset.size == 0 {
		return errors.New("invalid UEFI:NTFS asset evidence")
	}
	partition, err := os.OpenFile(partitionPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open UEFI:NTFS boot partition: %w", err)
	}
	defer partition.Close()
	info, err := partition.Stat()
	if err != nil {
		return fmt.Errorf("stat UEFI:NTFS boot partition: %w", err)
	}
	if info.Mode().IsRegular() && uint64(info.Size()) != asset.size {
		return fmt.Errorf("UEFI:NTFS boot partition is %d bytes, expected %d", info.Size(), asset.size)
	}
	hash := sha256.New()
	if _, err := io.CopyN(hash, partition, int64(asset.size)); err != nil {
		return fmt.Errorf("read back UEFI:NTFS boot partition: %w", err)
	}
	if !bytes.Equal(asset.digest[:], hash.Sum(nil)) {
		return errors.New("UEFI:NTFS boot partition verification failed: SHA-256 mismatch")
	}
	return nil
}

func verifyAsset(path string, expectedSize uint64, expectedSHA256 string) (Asset, error) {
	file, asset, err := openVerifiedAsset(path, expectedSize, expectedSHA256)
	if file != nil {
		err = errors.Join(err, file.Close())
	}
	return asset, err
}

func openVerifiedAsset(path string, expectedSize uint64, expectedSHA256 string) (*os.File, Asset, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, Asset{}, errors.New("UEFI:NTFS image path is empty")
	}
	if expectedSize == 0 || expectedSize > uint64(math.MaxInt64) {
		return nil, Asset{}, errors.New("invalid expected UEFI:NTFS image size")
	}
	expected, err := parseDigest(expectedSHA256)
	if err != nil {
		return nil, Asset{}, err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, Asset{}, fmt.Errorf("open UEFI:NTFS image %s: %w", path, err)
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, Asset{}, fmt.Errorf("stat UEFI:NTFS image %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, Asset{}, fmt.Errorf("UEFI:NTFS image %s is not a regular file", path)
	}
	if uint64(info.Size()) != expectedSize {
		file.Close()
		return nil, Asset{}, fmt.Errorf("UEFI:NTFS image %s is %d bytes, expected exactly %d", path, info.Size(), expectedSize)
	}
	hash := sha256.New()
	if _, err := io.CopyBuffer(hash, file, make([]byte, copyBufferBytes)); err != nil {
		file.Close()
		return nil, Asset{}, fmt.Errorf("hash UEFI:NTFS image %s: %w", path, err)
	}
	var actual [sha256.Size]byte
	copy(actual[:], hash.Sum(nil))
	if actual != expected {
		file.Close()
		return nil, Asset{}, fmt.Errorf("refusing modified UEFI:NTFS image %s: SHA-256 mismatch", path)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		file.Close()
		return nil, Asset{}, fmt.Errorf("rewind UEFI:NTFS image %s: %w", path, err)
	}
	asset := Asset{path: path, size: expectedSize, digest: actual}
	pinnedDigest, digestErr := parseDigest(ImageSHA256)
	if digestErr != nil {
		file.Close()
		return nil, Asset{}, fmt.Errorf("parse pinned UEFI:NTFS digest: %w", digestErr)
	}
	if actual == pinnedDigest {
		report, err := inspectPinnedArchitectureManifest(file, asset.SHA256())
		if err != nil {
			file.Close()
			return nil, Asset{}, fmt.Errorf("verify pinned UEFI:NTFS architecture manifest: %w", err)
		}
		asset.report = report
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			file.Close()
			return nil, Asset{}, fmt.Errorf("rewind UEFI:NTFS image after architecture inspection: %w", err)
		}
	}
	return file, asset, nil
}

func parseDigest(value string) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	value = strings.TrimSpace(value)
	if len(value) != sha256.Size*2 {
		return digest, errors.New("invalid UEFI:NTFS SHA-256 length")
	}
	for index := range digest {
		var decoded byte
		if _, err := fmt.Sscanf(value[index*2:index*2+2], "%02x", &decoded); err != nil {
			return digest, errors.New("invalid UEFI:NTFS SHA-256")
		}
		digest[index] = decoded
	}
	return digest, nil
}

func validatePartition(asset Asset, partition Partition) error {
	if asset.path == "" || asset.size != ImageSize {
		return errors.New("invalid UEFI:NTFS asset evidence")
	}
	if partition.SizeBytes != asset.size {
		return fmt.Errorf("UEFI:NTFS image is %d bytes but its partition is %d bytes", asset.size, partition.SizeBytes)
	}
	if partition.StartBytes > uint64(math.MaxInt64) || partition.SizeBytes > uint64(math.MaxInt64)-partition.StartBytes {
		return errors.New("UEFI:NTFS partition exceeds the supported signed file-offset range")
	}
	return nil
}
