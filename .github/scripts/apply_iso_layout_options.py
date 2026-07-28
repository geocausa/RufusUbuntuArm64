#!/usr/bin/env python3
"""Apply the reviewed ISO Image mode layout-options tranche to a checked-out branch."""

from __future__ import annotations

import json
from pathlib import Path
import sys


ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path.cwd()


def replace(path: str, old: str, new: str) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    if new in text:
        return
    if old not in text:
        raise SystemExit(f"expected patch context not found in {path}: {old[:120]!r}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


def write(path: str, content: str) -> None:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


# Backend option/result contracts.
replace(
    "internal/linuxmedia/extracted.go",
    "\tVolumeLabel        string\n\tWorkDirectory      string\n",
    "\tVolumeLabel        string\n\tPartitionScheme    string\n\tClusterSize        uint64\n\tWorkDirectory      string\n",
)
replace(
    "internal/linuxmedia/extracted.go",
    "\tSourceSHA256 string          `json:\"source_sha256\"`\n\tUEFIBootPath string          `json:\"uefi_boot_path\"`\n",
    "\tSourceSHA256    string          `json:\"source_sha256\"`\n\tUEFIBootPath    string          `json:\"uefi_boot_path\"`\n\tPartitionScheme string          `json:\"partition_scheme\"`\n\tClusterSize     uint64          `json:\"cluster_size\"`\n",
)
replace(
    "internal/linuxmedia/extracted.go",
    "\tlabel, err := normalizePersistentLabel(opts.VolumeLabel)\n\tif err != nil {\n\t\treturn result, err\n\t}\n\n\tworkRoot := opts.WorkDirectory\n",
    "\tlabel, err := normalizePersistentLabel(opts.VolumeLabel)\n\tif err != nil {\n\t\treturn result, err\n\t}\n\tpartitionScheme, err := normalizeExtractedPartitionScheme(opts.PartitionScheme)\n\tif err != nil {\n\t\treturn result, err\n\t}\n\tclusterBytes, err := normalizeExtractedClusterSize(opts.ClusterSize, sectorSize)\n\tif err != nil {\n\t\treturn result, err\n\t}\n\n\tworkRoot := opts.WorkDirectory\n",
)
replace(
    "internal/linuxmedia/extracted.go",
    "\tsendPersistent(emit, PersistentEvent{Stage: \"inspect\", Message: \"Checking ISO Image mode UEFI, FAT32, filename, and capacity compatibility…\"})\n",
    "\tsendPersistent(emit, PersistentEvent{Stage: \"inspect\", Message: fmt.Sprintf(\"Checking ISO Image mode %s/UEFI/FAT32, cluster, filename, and capacity compatibility…\", strings.ToUpper(partitionScheme))})\n",
)
replace(
    "internal/linuxmedia/extracted.go",
    "\tfat32Bytes, err := EstimateFAT32Bytes(manifest)\n\tif err != nil {\n\t\treturn result, err\n\t}\n\tlayout, err := PlanExtractedLayout(opts.TargetSize, sectorSize, fat32Bytes)\n\tif err != nil {\n\t\treturn result, err\n\t}\n\tresult = ExtractedCreateResult{\n\t\tLayout:       layout,\n\t\tManifest:     manifest,\n\t\tSourceSHA256: hex.EncodeToString(sourceDigest[:]),\n\t\tUEFIBootPath: manifest.UEFIBootPath,\n\t}\n",
    "\tfat32Bytes, err := EstimateFAT32BytesForCluster(manifest, clusterBytes)\n\tif err != nil {\n\t\treturn result, err\n\t}\n\tlayout, err := PlanExtractedLayoutForScheme(opts.TargetSize, sectorSize, fat32Bytes, partitionScheme)\n\tif err != nil {\n\t\treturn result, err\n\t}\n\tresult = ExtractedCreateResult{\n\t\tLayout:          layout,\n\t\tManifest:        manifest,\n\t\tSourceSHA256:    hex.EncodeToString(sourceDigest[:]),\n\t\tUEFIBootPath:    manifest.UEFIBootPath,\n\t\tPartitionScheme: partitionScheme,\n\t\tClusterSize:     clusterBytes,\n\t}\n",
)
replace(
    "internal/linuxmedia/extracted.go",
    "\ttargetChanged = true\n\tsendPersistent(emit, PersistentEvent{Stage: \"partition\", Message: \"Creating one writable FAT32 partition for ISO Image mode…\"})\n",
    "\ttargetChanged = true\n\tsendPersistent(emit, PersistentEvent{Stage: \"partition\", Message: fmt.Sprintf(\"Creating one writable %s/UEFI/FAT32 partition for ISO Image mode…\", strings.ToUpper(partitionScheme))})\n",
)
replace(
    "internal/linuxmedia/extracted.go",
    "\tif err := WriteExtractedMBR(target, layout); err != nil {\n\t\treturn result, err\n\t}\n",
    "\tif err := WriteExtractedPartitionTable(target, layout, partitionScheme, label); err != nil {\n\t\treturn result, err\n\t}\n",
)
replace(
    "internal/linuxmedia/extracted.go",
    "\tclusterSectors := fat32ClusterBytes / sectorSize\n",
    "\tclusterSectors := clusterBytes / sectorSize\n",
)
replace(
    "internal/linuxmedia/extracted.go",
    "\tsendPersistent(emit, PersistentEvent{Stage: \"complete\", Message: \"ISO Image mode USB created and verified.\"})\n",
    "\tsendPersistent(emit, PersistentEvent{Stage: \"complete\", Message: fmt.Sprintf(\"ISO Image mode USB created and verified (%s/UEFI/FAT32, %d-byte clusters).\", strings.ToUpper(partitionScheme), clusterBytes)})\n",
)
replace(
    "internal/linuxmedia/extracted.go",
    '"strconv"\n\t"syscall"',
    '"strconv"\n\t"strings"\n\t"syscall"',
)

write(
    "internal/linuxmedia/extracted_layout_options.go",
    r'''//go:build linux

package linuxmedia

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"strings"
)

const (
	extractedPartitionMBR = "mbr"
	extractedPartitionGPT = "gpt"
)

func normalizeExtractedPartitionScheme(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return extractedPartitionMBR, nil
	}
	if value != extractedPartitionMBR && value != extractedPartitionGPT {
		return "", errors.New("ISO Image mode partition scheme must be MBR or GPT")
	}
	return value, nil
}

func normalizeExtractedClusterSize(requested, sectorSize uint64) (uint64, error) {
	if requested == 0 {
		requested = fat32ClusterBytes
	}
	switch requested {
	case 4096, 8192, 16384, 32768:
	default:
		return 0, errors.New("ISO Image mode FAT32 cluster size must be 4096, 8192, 16384, or 32768 bytes")
	}
	if sectorSize == 0 || requested%sectorSize != 0 {
		return 0, fmt.Errorf("FAT32 cluster size %d is not aligned to logical sector size %d", requested, sectorSize)
	}
	return requested, nil
}

// EstimateFAT32BytesForCluster conservatively accounts for file-tail slack,
// directory clusters, and long-filename records at the selected cluster size.
func EstimateFAT32BytesForCluster(manifest Manifest, clusterBytes uint64) (uint64, error) {
	if len(manifest.Entries) == 0 || manifest.TotalBytes == 0 {
		return 0, errors.New("linux media manifest is empty")
	}
	if clusterBytes == 0 {
		clusterBytes = fat32ClusterBytes
	}
	perEntry := clusterBytes + fat32EntryOverhead
	entryCount := uint64(len(manifest.Entries))
	if entryCount > ^uint64(0)/perEntry {
		return 0, errors.New("linux media entry count overflows FAT32 sizing")
	}
	overhead := entryCount * perEntry
	if manifest.TotalBytes > ^uint64(0)-overhead {
		return 0, errors.New("linux media size overflows FAT32 sizing")
	}
	return manifest.TotalBytes + overhead, nil
}

// PlanExtractedLayoutForScheme returns the exact one-partition layout selected
// for ISO Image mode. MBR preserves the original bounded implementation; GPT
// reserves complete primary and backup metadata before exposing usable space.
func PlanExtractedLayoutForScheme(targetSize, sectorSize, copiedBytes uint64, scheme string) (ExtractedLayout, error) {
	normalized, err := normalizeExtractedPartitionScheme(scheme)
	if err != nil {
		return ExtractedLayout{}, err
	}
	if normalized == extractedPartitionMBR {
		return PlanExtractedLayout(targetSize, sectorSize, copiedBytes)
	}
	if targetSize > uint64(math.MaxInt64) {
		return ExtractedLayout{}, errors.New("target exceeds the supported signed file-offset range")
	}
	if targetSize < minimumExtractedDiskSize {
		return ExtractedLayout{}, fmt.Errorf("target is too small for ISO Image mode: need at least %d bytes", minimumExtractedDiskSize)
	}
	if sectorSize < 512 || sectorSize > fat32ClusterBytes || sectorSize&(sectorSize-1) != 0 {
		return ExtractedLayout{}, fmt.Errorf("unsupported logical sector size %d", sectorSize)
	}
	if targetSize%sectorSize != 0 {
		return ExtractedLayout{}, fmt.Errorf("target size %d is not aligned to logical sector size %d", targetSize, sectorSize)
	}
	if copiedBytes == 0 {
		return ExtractedLayout{}, errors.New("linux media tree is empty")
	}
	totalLBAs := targetSize / sectorSize
	entryBytes := uint64(layoutGPTEntryCount * layoutGPTEntrySize)
	entryLBAs := (entryBytes + sectorSize - 1) / sectorSize
	if totalLBAs <= 2*entryLBAs+3 {
		return ExtractedLayout{}, errors.New("target has no usable space after GPT metadata")
	}
	firstUsableLBA := uint64(2) + entryLBAs
	backupHeaderLBA := totalLBAs - 1
	backupEntriesLBA := backupHeaderLBA - entryLBAs
	lastUsableLBA := backupEntriesLBA - 1
	startLBA := alignLayout(layoutAlignment, sectorSize) / sectorSize
	if startLBA < firstUsableLBA {
		startLBA = firstUsableLBA
	}
	if startLBA > lastUsableLBA {
		return ExtractedLayout{}, errors.New("target has no usable GPT partition space after alignment")
	}
	partitionBytes := (lastUsableLBA - startLBA + 1) * sectorSize
	margin := copiedBytes / 20
	if margin < 64*1024*1024 {
		margin = 64 * 1024 * 1024
	}
	if copiedBytes > ^uint64(0)-margin || copiedBytes+margin > partitionBytes {
		return ExtractedLayout{}, fmt.Errorf("target has %d usable bytes but the verified media tree needs at least %d", partitionBytes, copiedBytes+margin)
	}
	return ExtractedLayout{
		SectorSize: sectorSize,
		TargetSize: targetSize,
		Partition: PartitionLayout{
			Number:     1,
			StartBytes: startLBA * sectorSize,
			SizeBytes:  partitionBytes,
		},
	}, nil
}

func WriteExtractedPartitionTable(target layoutTarget, layout ExtractedLayout, scheme, label string) error {
	normalized, err := normalizeExtractedPartitionScheme(scheme)
	if err != nil {
		return err
	}
	if normalized == extractedPartitionMBR {
		return WriteExtractedMBR(target, layout)
	}
	return WriteExtractedGPT(target, layout, label)
}

// WriteExtractedGPT writes a single EFI System Partition with ordinary
// automount semantics and verifies protective MBR, primary/backup headers, and
// both entry tables before returning.
func WriteExtractedGPT(target layoutTarget, layout ExtractedLayout, label string) error {
	if target == nil {
		return errors.New("nil ISO Image mode target")
	}
	if err := validateExtractedGPTLayout(layout); err != nil {
		return err
	}
	sectorSize := layout.SectorSize
	totalLBAs := layout.TargetSize / sectorSize
	entryBytes := uint64(layoutGPTEntryCount * layoutGPTEntrySize)
	entryLBAs := (entryBytes + sectorSize - 1) / sectorSize
	primaryEntriesLBA := uint64(2)
	backupHeaderLBA := totalLBAs - 1
	backupEntriesLBA := backupHeaderLBA - entryLBAs
	firstUsableLBA := primaryEntriesLBA + entryLBAs
	lastUsableLBA := backupEntriesLBA - 1

	diskGUID, err := randomLayoutGUID(randReader{})
	if err != nil {
		return err
	}
	partitionGUID, err := randomLayoutGUID(randReader{})
	if err != nil {
		return err
	}
	entries := make([]byte, entryLBAs*sectorSize)
	writeExtractedGPTEntry(entries[:layoutGPTEntrySize], partitionGUID, layout.Partition, sectorSize, label)
	entriesCRC := crc32.ChecksumIEEE(entries[:entryBytes])
	primary := makeLayoutGPTHeader(sectorSize, 1, backupHeaderLBA, firstUsableLBA, lastUsableLBA, diskGUID, primaryEntriesLBA, entriesCRC)
	backup := makeLayoutGPTHeader(sectorSize, backupHeaderLBA, 1, firstUsableLBA, lastUsableLBA, diskGUID, backupEntriesLBA, entriesCRC)
	protective := makeLayoutProtectiveMBR(totalLBAs, sectorSize)

	for _, item := range []struct {
		offset uint64
		data   []byte
		name   string
	}{
		{backupEntriesLBA * sectorSize, entries, "backup ISO Image mode GPT entries"},
		{backupHeaderLBA * sectorSize, backup, "backup ISO Image mode GPT header"},
	} {
		if err := writeLayoutAt(target, item.data, item.offset); err != nil {
			return fmt.Errorf("write %s: %w", item.name, err)
		}
	}
	if err := target.Sync(); err != nil {
		return fmt.Errorf("sync backup ISO Image mode GPT: %w", err)
	}
	for _, item := range []struct {
		offset uint64
		data   []byte
		name   string
	}{
		{primaryEntriesLBA * sectorSize, entries, "primary ISO Image mode GPT entries"},
		{sectorSize, primary, "primary ISO Image mode GPT header"},
		{0, protective, "protective ISO Image mode MBR"},
	} {
		if err := writeLayoutAt(target, item.data, item.offset); err != nil {
			return fmt.Errorf("write %s: %w", item.name, err)
		}
	}
	if err := target.Sync(); err != nil {
		return fmt.Errorf("sync primary ISO Image mode GPT: %w", err)
	}
	return verifyExtractedGPT(target, layout, entriesCRC, diskGUID, partitionGUID, label)
}

// randReader keeps random GUID generation injectable through the existing
// io.Reader contract without exposing another package-level mutable variable.
type randReader struct{}

func (randReader) Read(buffer []byte) (int, error) {
	return io.ReadFull(systemRandomReader{}, buffer)
}

type systemRandomReader struct{}

func (systemRandomReader) Read(buffer []byte) (int, error) {
	return cryptoRandRead(buffer)
}

func validateExtractedGPTLayout(layout ExtractedLayout) error {
	if layout.TargetSize > uint64(math.MaxInt64) || layout.TargetSize < minimumExtractedDiskSize ||
		layout.SectorSize < 512 || layout.SectorSize > fat32ClusterBytes || layout.SectorSize&(layout.SectorSize-1) != 0 ||
		layout.TargetSize%layout.SectorSize != 0 {
		return errors.New("ISO Image mode GPT layout has invalid target geometry")
	}
	part := layout.Partition
	if part.Number != 1 || part.StartBytes%layout.SectorSize != 0 || part.SizeBytes == 0 || part.SizeBytes%layout.SectorSize != 0 ||
		part.StartBytes >= layout.TargetSize || part.SizeBytes > layout.TargetSize-part.StartBytes {
		return errors.New("ISO Image mode GPT layout has an invalid partition extent")
	}
	entryBytes := uint64(layoutGPTEntryCount * layoutGPTEntrySize)
	entryLBAs := (entryBytes + layout.SectorSize - 1) / layout.SectorSize
	firstUsable := (uint64(2) + entryLBAs) * layout.SectorSize
	backupEntriesStart := layout.TargetSize - (entryLBAs+1)*layout.SectorSize
	if part.StartBytes < firstUsable || part.StartBytes+part.SizeBytes > backupEntriesStart {
		return errors.New("ISO Image mode partition overlaps GPT metadata")
	}
	return nil
}

func writeExtractedGPTEntry(entry []byte, unique [16]byte, layout PartitionLayout, sectorSize uint64, label string) {
	copy(entry[0:16], layoutEFIType[:])
	copy(entry[16:32], unique[:])
	binary.LittleEndian.PutUint64(entry[32:40], layout.StartBytes/sectorSize)
	binary.LittleEndian.PutUint64(entry[40:48], (layout.StartBytes+layout.SizeBytes)/sectorSize-1)
	binary.LittleEndian.PutUint64(entry[48:56], 0)
	writeLayoutName(entry[56:128], label)
}

func verifyExtractedGPT(target io.ReaderAt, layout ExtractedLayout, entriesCRC uint32, diskGUID, partitionGUID [16]byte, label string) error {
	sectorSize := layout.SectorSize
	totalLBAs := layout.TargetSize / sectorSize
	entryBytes := uint64(layoutGPTEntryCount * layoutGPTEntrySize)
	entryLBAs := (entryBytes + sectorSize - 1) / sectorSize
	backupHeaderLBA := totalLBAs - 1
	backupEntriesLBA := backupHeaderLBA - entryLBAs
	protective := make([]byte, sectorSize)
	primaryHeader := make([]byte, sectorSize)
	backupHeader := make([]byte, sectorSize)
	primaryEntries := make([]byte, entryLBAs*sectorSize)
	backupEntries := make([]byte, entryLBAs*sectorSize)
	for _, item := range []struct {
		offset uint64
		data   []byte
		name   string
	}{
		{0, protective, "protective MBR"},
		{sectorSize, primaryHeader, "primary GPT header"},
		{backupHeaderLBA * sectorSize, backupHeader, "backup GPT header"},
		{2 * sectorSize, primaryEntries, "primary GPT entries"},
		{backupEntriesLBA * sectorSize, backupEntries, "backup GPT entries"},
	} {
		if _, err := target.ReadAt(item.data, int64(item.offset)); err != nil {
			return fmt.Errorf("read back %s: %w", item.name, err)
		}
	}
	if !bytes.Equal(protective, makeLayoutProtectiveMBR(totalLBAs, sectorSize)) {
		return errors.New("ISO Image mode protective MBR verification failed")
	}
	expectedEntries := make([]byte, entryLBAs*sectorSize)
	writeExtractedGPTEntry(expectedEntries[:layoutGPTEntrySize], partitionGUID, layout.Partition, sectorSize, label)
	if !bytes.Equal(primaryEntries, expectedEntries) || !bytes.Equal(backupEntries, expectedEntries) || crc32.ChecksumIEEE(primaryEntries[:entryBytes]) != entriesCRC {
		return errors.New("ISO Image mode GPT entry-table verification failed")
	}
	firstUsableLBA := uint64(2) + entryLBAs
	lastUsableLBA := backupEntriesLBA - 1
	expectedPrimary := makeLayoutGPTHeader(sectorSize, 1, backupHeaderLBA, firstUsableLBA, lastUsableLBA, diskGUID, 2, entriesCRC)
	expectedBackup := makeLayoutGPTHeader(sectorSize, backupHeaderLBA, 1, firstUsableLBA, lastUsableLBA, diskGUID, backupEntriesLBA, entriesCRC)
	if !bytes.Equal(primaryHeader, expectedPrimary) || !bytes.Equal(backupHeader, expectedBackup) {
		return errors.New("ISO Image mode GPT header verification failed")
	}
	entry := primaryEntries[:layoutGPTEntrySize]
	if !bytes.Equal(entry[:16], layoutEFIType[:]) || !bytes.Equal(entry[16:32], partitionGUID[:]) ||
		binary.LittleEndian.Uint64(entry[32:40]) != layout.Partition.StartBytes/sectorSize ||
		binary.LittleEndian.Uint64(entry[40:48]) != (layout.Partition.StartBytes+layout.Partition.SizeBytes)/sectorSize-1 ||
		binary.LittleEndian.Uint64(entry[48:56]) != 0 {
		return errors.New("ISO Image mode GPT partition entry verification failed")
	}
	return nil
}
''',
)

# Replace the synthetic random-reader indirection with crypto/rand directly.
replace(
    "internal/linuxmedia/extracted_layout_options.go",
    '"bytes"\n\t"encoding/binary"',
    '"bytes"\n\t"crypto/rand"\n\t"encoding/binary"',
)
replace(
    "internal/linuxmedia/extracted_layout_options.go",
    "\tdiskGUID, err := randomLayoutGUID(randReader{})\n",
    "\tdiskGUID, err := randomLayoutGUID(rand.Reader)\n",
)
replace(
    "internal/linuxmedia/extracted_layout_options.go",
    "\tpartitionGUID, err := randomLayoutGUID(randReader{})\n",
    "\tpartitionGUID, err := randomLayoutGUID(rand.Reader)\n",
)
replace(
    "internal/linuxmedia/extracted_layout_options.go",
    '''// randReader keeps random GUID generation injectable through the existing
// io.Reader contract without exposing another package-level mutable variable.
type randReader struct{}

func (randReader) Read(buffer []byte) (int, error) {
	return io.ReadFull(systemRandomReader{}, buffer)
}

type systemRandomReader struct{}

func (systemRandomReader) Read(buffer []byte) (int, error) {
	return cryptoRandRead(buffer)
}

''',
    "",
)

# Privileged helper flags and evidence.
replace(
    "cmd/rufus-persistence-helper/main.go",
    '"runtime"\n\t"strings"',
    '"runtime"\n\t"strconv"\n\t"strings"',
)
replace(
    "cmd/rufus-persistence-helper/main.go",
    '\tvolumeLabel := flags.String("volume-label", "RUFUS-LIVE", "FAT32 volume label")\n',
    '\tvolumeLabel := flags.String("volume-label", "RUFUS-LIVE", "FAT32 volume label")\n\tpartitionScheme := flags.String("partition-scheme", "", "ISO Image mode partition scheme: mbr or gpt")\n\tclusterSizeText := flags.String("cluster-size", "0", "ISO Image mode FAT32 cluster size in bytes")\n',
)
replace(
    "cmd/rufus-persistence-helper/main.go",
    '''\tpersistenceSize, err := persistence.ParseSize(*persistenceSizeText)
\tif err != nil {
\t\treturn fmt.Errorf("parse --persistence-size: %w", err)
\t}
\tif selectedOperation == "iso" {
''',
    '''\tpersistenceSize, err := persistence.ParseSize(*persistenceSizeText)
\tif err != nil {
\t\treturn fmt.Errorf("parse --persistence-size: %w", err)
\t}
\tselectedPartitionScheme := strings.ToLower(strings.TrimSpace(*partitionScheme))
\tclusterSize, err := strconv.ParseUint(strings.TrimSpace(*clusterSizeText), 10, 64)
\tif err != nil {
\t\treturn fmt.Errorf("parse --cluster-size: %w", err)
\t}
\tif selectedOperation == "iso" {
''',
)
replace(
    "cmd/rufus-persistence-helper/main.go",
    '''\t\tif *runtimeUEFIValidation {
\t\t\treturn errors.New("ISO Image mode does not install the persistence runtime validator")
\t\t}
\t}
''',
    '''\t\tif *runtimeUEFIValidation {
\t\t\treturn errors.New("ISO Image mode does not install the persistence runtime validator")
\t\t}
\t\tif selectedPartitionScheme == "" {
\t\t\tselectedPartitionScheme = "mbr"
\t\t}
\t\tif selectedPartitionScheme != "mbr" && selectedPartitionScheme != "gpt" {
\t\t\treturn errors.New("--partition-scheme must be mbr or gpt for ISO Image mode")
\t\t}
\t\tif clusterSize == 0 {
\t\t\tclusterSize = 4096
\t\t}
\t\tswitch clusterSize {
\t\tcase 4096, 8192, 16384, 32768:
\t\tdefault:
\t\t\treturn errors.New("--cluster-size must be 4096, 8192, 16384, or 32768 for ISO Image mode")
\t\t}
\t} else if selectedPartitionScheme != "" || clusterSize != 0 {
\t\treturn errors.New("--partition-scheme and --cluster-size are accepted only for ISO Image mode")
\t}
''',
)
replace(
    "cmd/rufus-persistence-helper/main.go",
    '''\tpreflightMessage := fmt.Sprintf("%s: %s; target: %s", operationLabel, filepath.Base(resolvedImage), resolvedTarget)
''',
    '''\tpreflightMessage := fmt.Sprintf("%s: %s; target: %s", operationLabel, filepath.Base(resolvedImage), resolvedTarget)
\tif selectedOperation == "iso" {
\t\tpreflightMessage = fmt.Sprintf("%s; layout: %s/UEFI/FAT32; cluster: %d bytes", preflightMessage, strings.ToUpper(selectedPartitionScheme), clusterSize)
\t}
''',
)
replace(
    "cmd/rufus-persistence-helper/main.go",
    '''\t\t\tArchitecture:      runtime.GOARCH,
\t\t\tVolumeLabel:       *volumeLabel,
\t\t\tBeforeDestructive: targetCheck,
''',
    '''\t\t\tArchitecture:      runtime.GOARCH,
\t\t\tVolumeLabel:       *volumeLabel,
\t\t\tPartitionScheme:   selectedPartitionScheme,
\t\t\tClusterSize:       clusterSize,
\t\t\tBeforeDestructive: targetCheck,
''',
)
replace(
    "cmd/rufus-persistence-helper/main.go",
    '''\t\t\tMessage: fmt.Sprintf("ISO Image mode source SHA-256 %s; verified UEFI fallback %s.", result.SourceSHA256, result.UEFIBootPath),
''',
    '''\t\t\tMessage: fmt.Sprintf("ISO Image mode source SHA-256 %s; verified UEFI fallback %s; layout %s/UEFI/FAT32; cluster %d bytes.", result.SourceSHA256, result.UEFIBootPath, strings.ToUpper(result.PartitionScheme), result.ClusterSize),
''',
)

# GTK integration: independent ISO settings, stale-label reset, exact command binding.
write(
    "gui/rufusarm64_iso_write_mode.py",
    r'''"""Rufus-style ISO Image mode versus DD Image mode selection for Linux ISOHybrid media."""

import os

from gi.repository import Gtk

import rufusarm64
from rufusarm64_logic import inspect_source_identity, normalize_volume_label


ISO_HELPER = "/usr/lib/rufusarm64/rufusarm64-persistence-helper"
DEFAULT_ISO_PARTITION_SCHEME = "mbr"
DEFAULT_ISO_CLUSTER_SIZE = "4096"
DEFAULT_ISO_VOLUME_LABEL = "RUFUS-LIVE"
_pending_iso_window = None


def hybrid_mode_available(info):
    """Return whether inspection exposes a bounded UEFI ISOHybrid choice."""
    if not isinstance(info, dict) or info.get("mode") != "raw":
        return False
    profile = info.get("compatibility_profile")
    if not isinstance(profile, dict):
        return False
    methods = profile.get("boot_methods") or []
    return (
        profile.get("write_path") == "hybrid-direct-write"
        and profile.get("hybrid") is True
        and isinstance(methods, list)
        and "UEFI" in methods
    )


def normalize_iso_partition_scheme(value):
    value = str(value or DEFAULT_ISO_PARTITION_SCHEME).strip().lower()
    if value not in {"mbr", "gpt"}:
        raise ValueError("ISO Image mode partition scheme must be MBR or GPT.")
    return value


def normalize_iso_cluster_size(value):
    value = str(value or DEFAULT_ISO_CLUSTER_SIZE).strip().lower()
    if value in {"", "auto", "0"}:
        return DEFAULT_ISO_CLUSTER_SIZE
    if value not in {"4096", "8192", "16384", "32768"}:
        raise ValueError("ISO Image mode cluster size must be 4 KiB, 8 KiB, 16 KiB, or 32 KiB.")
    return value


def iso_source_state(previous_source, selected_source, current_label):
    selected = os.path.realpath(str(selected_source or "").strip()) if selected_source else ""
    label = str(current_label or DEFAULT_ISO_VOLUME_LABEL)
    if selected and selected != str(previous_source or ""):
        label = DEFAULT_ISO_VOLUME_LABEL
    return selected or str(previous_source or ""), label


def iso_layout_summary(partition_scheme, cluster_size, volume_label):
    scheme = normalize_iso_partition_scheme(partition_scheme).upper()
    cluster = int(normalize_iso_cluster_size(cluster_size)) // 1024
    label = normalize_volume_label(volume_label or DEFAULT_ISO_VOLUME_LABEL, "fat32")
    return f"{scheme} / UEFI / FAT32 / {cluster} KiB clusters / label {label}"


def build_iso_write_command(
    pkexec,
    helper,
    image,
    path,
    identity,
    cancel_path,
    volume_label=DEFAULT_ISO_VOLUME_LABEL,
    partition_scheme=DEFAULT_ISO_PARTITION_SCHEME,
    cluster_size=DEFAULT_ISO_CLUSTER_SIZE,
):
    """Build the narrow identity-bound privileged ISO Image mode command."""
    values = [str(value or "").strip() for value in (pkexec, helper, image, path, identity, cancel_path)]
    if not all(values):
        raise ValueError("ISO Image mode requires authentication, an image, a USB identity, and a cancellation channel.")
    resolved_image, source_identity = inspect_source_identity(values[2])
    scheme = normalize_iso_partition_scheme(partition_scheme)
    cluster = normalize_iso_cluster_size(cluster_size)
    return [
        values[0],
        values[1],
        "--operation",
        "iso",
        "--image",
        resolved_image,
        "--expected-source-identity",
        source_identity,
        "--device",
        values[3],
        "--expected-identity",
        values[4],
        "--volume-label",
        normalize_volume_label(volume_label, "fat32"),
        "--partition-scheme",
        scheme,
        "--cluster-size",
        cluster,
        "--cancel-file",
        values[5],
        "--json-progress",
        "--yes",
    ]


class ISOHybridWriteModeDialog(Gtk.Dialog):
    """Explicit choice matching Rufus's ISOHybrid write-mode boundary."""

    def __init__(self, parent):
        super().__init__(title="ISOHybrid image detected", transient_for=parent, modal=True)
        self.add_button("Cancel", Gtk.ResponseType.CANCEL)
        self.add_button("Continue", Gtk.ResponseType.OK)
        self.set_default_response(Gtk.ResponseType.OK)
        self.set_default_size(620, 360)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        box.set_border_width(18)
        self.get_content_area().pack_start(box, True, True, 0)

        title = Gtk.Label()
        title.set_markup("<span size='large' weight='bold'>Choose how to write this image</span>")
        title.set_xalign(0)
        box.pack_start(title, False, False, 0)

        intro = Gtk.Label(
            label=(
                "This image can be used as an optical ISO or as a complete disk image. "
                "ISO Image mode is selected by default, as in Rufus on Windows."
            )
        )
        intro.set_xalign(0)
        intro.set_line_wrap(True)
        box.pack_start(intro, False, False, 0)

        self.iso_mode = Gtk.RadioButton.new_with_label_from_widget(
            None, "Write in ISO Image mode (Recommended)"
        )
        self.iso_mode.set_active(True)
        self.iso_mode.set_tooltip_text(
            "Create a conventional writable FAT32 USB using the reviewed MBR/GPT and cluster settings."
        )
        box.pack_start(self.iso_mode, False, False, 0)

        iso_detail = Gtk.Label(
            label=(
                "Creates one conventional writable FAT32 partition, extracts the ISO files, and verifies every copied file by SHA-256. "
                "Partition scheme, cluster size, and label come from the visible ISO-mode controls. UEFI and FAT32 remain capability-bound. "
                "All checks finish before the USB is erased."
            )
        )
        iso_detail.set_xalign(0)
        iso_detail.set_line_wrap(True)
        iso_detail.set_margin_start(28)
        iso_detail.get_style_context().add_class("dim-label")
        box.pack_start(iso_detail, False, False, 0)

        self.dd_mode = Gtk.RadioButton.new_with_label_from_widget(
            self.iso_mode, "Write in DD Image mode"
        )
        self.dd_mode.set_tooltip_text(
            "Copy the image byte-for-byte, preserving its embedded partitions and boot structures."
        )
        box.pack_start(self.dd_mode, False, False, 0)

        dd_detail = Gtk.Label(
            label=(
                "Copies the whole image exactly, preserving its embedded partition table, filesystems, boot records, and fixed image capacity. "
                "The visible ISO extraction layout controls are ignored in DD mode."
            )
        )
        dd_detail.set_xalign(0)
        dd_detail.set_line_wrap(True)
        dd_detail.set_margin_start(28)
        dd_detail.get_style_context().add_class("dim-label")
        box.pack_start(dd_detail, False, False, 0)

        self.show_all()

    def selected_mode(self):
        return "iso" if self.iso_mode.get_active() else "dd"


def install_iso_write_mode():
    """Install the choice and reviewed ISO layout controls without changing DD semantics."""
    window_class = rufusarm64.RufusWindow
    if getattr(window_class, "_iso_write_mode_installed", False):
        return

    original_init = window_class.__init__
    original_update_layout = window_class.update_layout
    original_start = window_class.start
    original_save_settings = window_class.save_settings
    original_partition_changed = window_class.partition_changed
    original_build_writer_command = rufusarm64.build_writer_command

    def update_iso_note(window):
        try:
            summary = iso_layout_summary(
                window.partition_combo.get_active_id(),
                window.cluster_combo.get_active_id(),
                window.volume_label.get_text(),
            )
        except ValueError as exc:
            window.layout_note.set_text(str(exc))
            return
        window.layout_note.set_text(
            "ISO Image mode: " + summary + ". MBR is broadly compatible with removable-media UEFI; GPT is the modern alternative. "
            "DD Image mode ignores these controls and preserves the source image exactly."
        )

    def label_changed(widget, window):
        if getattr(window, "_iso_settings_suspended", False):
            return
        if hybrid_mode_available(window.inspection) or _pending_iso_window is window:
            window.iso_volume_label = widget.get_text()
            update_iso_note(window)
        elif window.inspection.get("mode") == "windows":
            window._windows_volume_label = widget.get_text()

    def cluster_changed(_widget, window):
        if hybrid_mode_available(window.inspection) or _pending_iso_window is window:
            try:
                window.iso_cluster_size = normalize_iso_cluster_size(window.cluster_combo.get_active_id())
            except ValueError:
                return
            update_iso_note(window)

    def integrated_init(window, *args, **kwargs):
        original_init(window, *args, **kwargs)
        window.iso_partition_scheme = normalize_iso_partition_scheme(
            window.settings.get("iso_partition_scheme", DEFAULT_ISO_PARTITION_SCHEME)
        )
        window.iso_cluster_size = normalize_iso_cluster_size(
            window.settings.get("iso_cluster_size", DEFAULT_ISO_CLUSTER_SIZE)
        )
        try:
            window.iso_volume_label = normalize_volume_label(
                window.settings.get("iso_volume_label", DEFAULT_ISO_VOLUME_LABEL), "fat32"
            )
        except ValueError:
            window.iso_volume_label = DEFAULT_ISO_VOLUME_LABEL
        window._windows_volume_label = str(window.settings.get("volume_label", "RUFUSARM64"))
        window._iso_source_path = ""
        window._iso_settings_suspended = False
        window.volume_label.connect("changed", label_changed, window)
        window.cluster_combo.connect("changed", cluster_changed, window)

    def apply_iso_controls(window):
        source, label = iso_source_state(
            window._iso_source_path,
            window.image_chooser.get_filename() or "",
            window.iso_volume_label,
        )
        window._iso_source_path = source
        window.iso_volume_label = label
        window._iso_settings_suspended = True
        try:
            window.partition_combo.set_active_id(window.iso_partition_scheme)
            window.target_system_combo.set_active_id("uefi")
            window.filesystem_combo.set_active_id("fat32")
            window.cluster_combo.set_active_id(window.iso_cluster_size)
            window.volume_label.set_max_length(11)
            window.volume_label.set_text(window.iso_volume_label)
        finally:
            window._iso_settings_suspended = False
        editable = not window.busy
        window.partition_combo.set_sensitive(editable)
        window.target_system_combo.set_sensitive(False)
        window.filesystem_combo.set_sensitive(False)
        window.cluster_combo.set_sensitive(editable)
        window.volume_label.set_sensitive(editable)
        for widget in (
            window.driver_chooser,
            window.dbx_chooser,
            window.dbx_update_button,
            window.quick_format,
            window.bad_block_check,
        ):
            widget.set_sensitive(False)
        update_iso_note(window)

    def integrated_update_layout(window, info):
        result = original_update_layout(window, info)
        if info.get("mode") == "windows":
            window._iso_settings_suspended = True
            try:
                window.volume_label.set_text(window._windows_volume_label)
            finally:
                window._iso_settings_suspended = False
        elif hybrid_mode_available(info):
            window.mode_value.set_text(
                "ISOHybrid image: ISO Image mode (recommended/default) and DD Image mode are available. "
                "ISO mode supports reviewed MBR/GPT and FAT32 cluster choices."
            )
            apply_iso_controls(window)
        return result

    def integrated_partition_changed(window, *args):
        result = original_partition_changed(window, *args)
        if hybrid_mode_available(window.inspection) or _pending_iso_window is window:
            try:
                window.iso_partition_scheme = normalize_iso_partition_scheme(
                    window.partition_combo.get_active_id()
                )
            except ValueError:
                return result
            update_iso_note(window)
        return result

    def integrated_save_settings(window):
        iso_active = hybrid_mode_available(window.inspection) or _pending_iso_window is window
        if not iso_active:
            if window.inspection.get("mode") == "windows":
                window._windows_volume_label = window.volume_label.get_text()
            return original_save_settings(window)

        window.iso_partition_scheme = normalize_iso_partition_scheme(window.partition_combo.get_active_id())
        window.iso_cluster_size = normalize_iso_cluster_size(window.cluster_combo.get_active_id())
        window.iso_volume_label = normalize_volume_label(window.volume_label.get_text(), "fat32")
        window.settings["iso_partition_scheme"] = window.iso_partition_scheme
        window.settings["iso_cluster_size"] = window.iso_cluster_size
        window.settings["iso_volume_label"] = window.iso_volume_label

        state = (
            window.partition_combo.get_active_id(),
            window.target_system_combo.get_active_id(),
            window.filesystem_combo.get_active_id(),
            window.cluster_combo.get_active_id(),
            window.volume_label.get_text(),
        )
        window._iso_settings_suspended = True
        try:
            window.partition_combo.set_active_id(window.windows_partition_scheme)
            window.target_system_combo.set_active_id(window.windows_target_system)
            window.filesystem_combo.set_active_id(window.windows_filesystem)
            window.cluster_combo.set_active_id(window.windows_cluster_size)
            window.volume_label.set_text(window._windows_volume_label)
            original_save_settings(window)
        finally:
            window.partition_combo.set_active_id(state[0])
            window.target_system_combo.set_active_id(state[1])
            window.filesystem_combo.set_active_id(state[2])
            window.cluster_combo.set_active_id(state[3])
            window.volume_label.set_text(state[4])
            window._iso_settings_suspended = False

    def integrated_build_writer_command(*args, **kwargs):
        global _pending_iso_window
        window = _pending_iso_window
        if window is None:
            return original_build_writer_command(*args, **kwargs)
        if not os.path.isfile(ISO_HELPER) or not os.access(ISO_HELPER, os.X_OK):
            raise ValueError("The package-owned ISO Image mode helper is not installed or executable.")
        if len(args) < 8:
            raise ValueError("ISO Image mode received an incomplete writer request.")
        return build_iso_write_command(
            args[0],
            ISO_HELPER,
            args[2],
            args[3],
            args[4],
            args[6],
            window.volume_label.get_text(),
            window.partition_combo.get_active_id(),
            window.cluster_combo.get_active_id(),
        )

    def integrated_start(window, *args):
        global _pending_iso_window
        if window.persistence_enabled.get_active() or not hybrid_mode_available(window.inspection):
            return original_start(window, *args)

        dialog = ISOHybridWriteModeDialog(window)
        response = dialog.run()
        choice = dialog.selected_mode()
        dialog.destroy()
        if response != Gtk.ResponseType.OK:
            return None

        original_inspection = window.inspection
        original_verify = window.verify.get_active()
        original_append_log = window.append_log
        temporary = dict(original_inspection)
        layout_summary = ""
        if choice == "iso":
            try:
                window.iso_partition_scheme = normalize_iso_partition_scheme(window.partition_combo.get_active_id())
                window.iso_cluster_size = normalize_iso_cluster_size(window.cluster_combo.get_active_id())
                window.iso_volume_label = normalize_volume_label(window.volume_label.get_text(), "fat32")
                layout_summary = iso_layout_summary(
                    window.iso_partition_scheme,
                    window.iso_cluster_size,
                    window.iso_volume_label,
                )
            except ValueError as exc:
                window.message(str(exc), Gtk.MessageType.ERROR)
                return None
            temporary.update(
                {
                    "mode": "linux-iso",
                    "description": (
                        "ISO Image mode (recommended): " + layout_summary + "; extract the ISO files and SHA-256 verify every copied file"
                    ),
                    "windows_options": False,
                }
            )
            window.verify.set_active(True)
            _pending_iso_window = window

            def append_iso_log(text):
                if str(text) == "Layout: From image / From image / From image":
                    text = "Layout: " + layout_summary
                return original_append_log(text)

            window.append_log = append_iso_log
        else:
            temporary.update(
                {
                    "mode": "raw",
                    "description": (
                        "DD Image mode: preserve the ISOHybrid partition and boot layout byte-for-byte; visible ISO layout choices are ignored"
                    ),
                    "windows_options": False,
                }
            )

        window.inspection = temporary
        try:
            result = original_start(window, *args)
            if choice == "iso" and window.active_job == "writer":
                window.active_mode = "linux-iso"
                window.active_filesystem = "fat32"
                window.active_verify_requested = True
            return result
        finally:
            _pending_iso_window = None
            window.append_log = original_append_log
            window.inspection = original_inspection
            window.verify.set_active(original_verify)
            window.update_layout(window.inspection)

    rufusarm64.build_writer_command = integrated_build_writer_command
    window_class.__init__ = integrated_init
    window_class.update_layout = integrated_update_layout
    window_class.partition_changed = integrated_partition_changed
    window_class.save_settings = integrated_save_settings
    window_class.start = integrated_start
    window_class._iso_write_mode_installed = True
''',
)

# Focused tests.
write(
    "internal/linuxmedia/extracted_layout_options_test.go",
    r'''//go:build linux

package linuxmedia

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestPlanExtractedLayoutForSchemeSupportsMBRAndGPT(t *testing.T) {
	const targetSize = uint64(768 * 1024 * 1024)
	mbr, err := PlanExtractedLayoutForScheme(targetSize, 512, 32*1024*1024, "mbr")
	if err != nil {
		t.Fatal(err)
	}
	gpt, err := PlanExtractedLayoutForScheme(targetSize, 512, 32*1024*1024, "gpt")
	if err != nil {
		t.Fatal(err)
	}
	if mbr.Partition.StartBytes != 1024*1024 || gpt.Partition.StartBytes != 1024*1024 {
		t.Fatalf("unexpected aligned starts: mbr=%+v gpt=%+v", mbr, gpt)
	}
	if gpt.Partition.SizeBytes >= mbr.Partition.SizeBytes {
		t.Fatalf("GPT did not reserve backup metadata: mbr=%d gpt=%d", mbr.Partition.SizeBytes, gpt.Partition.SizeBytes)
	}
	if err := validateExtractedGPTLayout(gpt); err != nil {
		t.Fatal(err)
	}
}

func TestWriteExtractedGPTWritesVerifiedEFIEntry(t *testing.T) {
	const targetSize = uint64(768 * 1024 * 1024)
	layout, err := PlanExtractedLayoutForScheme(targetSize, 512, 8*1024*1024, "gpt")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "target.img")
	truncateLinuxTestFile(t, path, targetSize)
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := WriteExtractedGPT(file, layout, "RUFUS-LIVE"); err != nil {
		t.Fatal(err)
	}
	sector := make([]byte, 512)
	if _, err := file.ReadAt(sector, 0); err != nil {
		t.Fatal(err)
	}
	if sector[446+4] != 0xee || sector[510] != 0x55 || sector[511] != 0xaa {
		t.Fatalf("unexpected protective MBR: %x", sector[446:462])
	}
	header := make([]byte, 512)
	if _, err := file.ReadAt(header, 512); err != nil {
		t.Fatal(err)
	}
	if string(header[:8]) != "EFI PART" {
		t.Fatalf("missing GPT signature: %q", header[:8])
	}
	entry := make([]byte, layoutGPTEntrySize)
	if _, err := file.ReadAt(entry, 2*512); err != nil {
		t.Fatal(err)
	}
	if string(entry[:16]) != string(layoutEFIType[:]) {
		t.Fatalf("unexpected partition type: %x", entry[:16])
	}
	if got := binary.LittleEndian.Uint64(entry[48:56]); got != 0 {
		t.Fatalf("ordinary ISO Image mode GPT partition unexpectedly has attributes %#x", got)
	}
}

func TestNormalizeExtractedClusterSize(t *testing.T) {
	for _, value := range []uint64{0, 4096, 8192, 16384, 32768} {
		if _, err := normalizeExtractedClusterSize(value, 512); err != nil {
			t.Fatalf("cluster %d rejected: %v", value, err)
		}
	}
	if _, err := normalizeExtractedClusterSize(65536, 512); err == nil {
		t.Fatal("accepted unsupported FAT32 cluster size")
	}
}
''',
)

write(
    "internal/linuxmedia/extracted_gpt_loop_test.go",
    r'''//go:build linux

package linuxmedia

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/geocausa/RufusArm64/internal/safety"
	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

func TestCreateExtractedOnRealLoopDeviceGPT(t *testing.T) {
	if os.Getenv("RUFUS_REAL_EXTRACTED_TEST") != "1" {
		t.Skip("set RUFUS_REAL_EXTRACTED_TEST=1 to exercise a real loop device")
	}
	if os.Geteuid() != 0 {
		t.Skip("real ISO Image mode loop test requires root")
	}
	sourceRoot := t.TempDir()
	writeLinuxTestBytes(t, filepath.Join(sourceRoot, "EFI", "BOOT", "BOOTAA64.EFI"), linuxTestARM64EFI(0x71))
	writeLinuxTestFile(t, filepath.Join(sourceRoot, "boot", "grub", "grub.cfg"), "linux /casper/vmlinuz boot=casper --- quiet\n")
	writeLinuxTestFile(t, filepath.Join(sourceRoot, "casper", "vmlinuz"), "gpt-loop-kernel")
	writeLinuxTestFile(t, filepath.Join(sourceRoot, "casper", "initrd"), "gpt-loop-initrd")
	writeLinuxTestFile(t, filepath.Join(sourceRoot, "README.txt"), "RufusArm64 GPT ISO Image mode qualification\n")

	isoPath := filepath.Join(t.TempDir(), "linux-arm64-gpt.iso")
	output, err := exec.Command("genisoimage", "-quiet", "-J", "-R", "-V", "RUFUSGPT", "-o", isoPath, sourceRoot).CombinedOutput()
	if err != nil {
		t.Fatalf("create source ISO: %v: %s", err, strings.TrimSpace(string(output)))
	}
	resolvedISO, sourceIdentity, err := sourcefile.Inspect(isoPath)
	if err != nil {
		t.Fatal(err)
	}

	const capacity = int64(768 * 1024 * 1024)
	backing := filepath.Join(t.TempDir(), "target-gpt.img")
	backingFile, err := os.OpenFile(backing, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := backingFile.Truncate(capacity); err != nil {
		_ = backingFile.Close()
		t.Fatal(err)
	}
	if err := backingFile.Close(); err != nil {
		t.Fatal(err)
	}

	loopPath := attachExtractedLoop(t, backing)
	mountRoot := filepath.Join(t.TempDir(), "mounted-gpt")
	if err := os.Mkdir(mountRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	mounted := false
	t.Cleanup(func() {
		if mounted {
			_, _ = exec.Command("umount", "--", mountRoot).CombinedOutput()
		}
		if loopPath != "" {
			_, _ = exec.Command("losetup", "--detach", loopPath).CombinedOutput()
		}
	})
	waitForExtractedLoopFlock(t, loopPath)
	deviceID, err := safety.KernelDeviceID(loopPath)
	if err != nil {
		t.Fatal(err)
	}
	sizeOutput, err := exec.Command("blockdev", "--getsize64", loopPath).CombinedOutput()
	if err != nil {
		t.Fatalf("read loop capacity: %v: %s", err, strings.TrimSpace(string(sizeOutput)))
	}
	targetSize, err := strconv.ParseUint(strings.TrimSpace(string(sizeOutput)), 10, 64)
	if err != nil || targetSize != uint64(capacity) {
		t.Fatalf("unexpected loop capacity %q: %v", strings.TrimSpace(string(sizeOutput)), err)
	}

	result, err := CreateExtracted(context.Background(), resolvedISO, loopPath, ExtractedCreateOptions{
		TargetSize:       targetSize,
		ExpectedDeviceID: deviceID,
		ExpectedSource:   sourceIdentity,
		Architecture:     "arm64",
		VolumeLabel:      "RUFUS-GPT",
		PartitionScheme:  "gpt",
		ClusterSize:      8192,
		BeforeDestructive: func(_ *os.File) error {
			open, err := safety.OpenReopenableDevice(loopPath)
			if err != nil {
				return err
			}
			defer open.Close()
			return safety.VerifyOpenDevice(open, deviceID, targetSize)
		},
	}, nil)
	if err != nil {
		t.Fatalf("create GPT ISO Image mode loop media: %v; result=%+v", err, result)
	}
	if result.PartitionScheme != "gpt" || result.ClusterSize != 8192 {
		t.Fatalf("unexpected selected layout evidence: %+v", result)
	}

	if output, err := exec.Command("losetup", "--detach", loopPath).CombinedOutput(); err != nil {
		t.Fatalf("detach completed target: %v: %s", err, strings.TrimSpace(string(output)))
	}
	loopPath = ""
	loopPath = attachExtractedLoop(t, backing)
	waitForExtractedLoopFlock(t, loopPath)
	partitionPath, err := waitExtractedLoopPartition(loopPath, result.Layout.Partition, 20*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	blkidOutput, err := exec.Command("blkid", "-p", "-o", "export", partitionPath).CombinedOutput()
	if err != nil {
		t.Fatalf("inspect completed FAT32 partition: %v: %s", err, strings.TrimSpace(string(blkidOutput)))
	}
	metadata := string(blkidOutput)
	if !strings.Contains(metadata, "TYPE=vfat") || !strings.Contains(metadata, "LABEL=RUFUS-GPT") {
		t.Fatalf("unexpected completed filesystem metadata:\n%s", metadata)
	}
	output, err = exec.Command("mount", "-t", "vfat", "-o", "ro,nosuid,nodev,noexec", "--", partitionPath, mountRoot).CombinedOutput()
	if err != nil {
		t.Fatalf("mount completed GPT media: %v: %s", err, strings.TrimSpace(string(output)))
	}
	mounted = true
	data, err := os.ReadFile(filepath.Join(mountRoot, "README.txt"))
	if err != nil || string(data) != "RufusArm64 GPT ISO Image mode qualification\n" {
		t.Fatalf("copied GPT media mismatch: %q %v", data, err)
	}
	if output, err := exec.Command("umount", "--", mountRoot).CombinedOutput(); err != nil {
		t.Fatalf("unmount completed GPT media: %v: %s", err, strings.TrimSpace(string(output)))
	}
	mounted = false
}
''',
)

write(
    "gui/test_iso_layout_options.py",
    r'''import os
from pathlib import Path
import sys
import tempfile
import types
import unittest

fake_gi = types.ModuleType("gi")
fake_repository = types.ModuleType("gi.repository")

class FakeDialog:
    pass

fake_repository.Gtk = types.SimpleNamespace(Dialog=FakeDialog)
fake_gi.repository = fake_repository
fake_rufusarm64 = types.ModuleType("rufusarm64")
fake_rufusarm64.RufusWindow = object
fake_rufusarm64.build_writer_command = lambda *args, **kwargs: []

_saved = {name: sys.modules.get(name) for name in ("gi", "gi.repository", "rufusarm64", "rufusarm64_iso_write_mode")}
try:
    sys.modules["gi"] = fake_gi
    sys.modules["gi.repository"] = fake_repository
    sys.modules["rufusarm64"] = fake_rufusarm64
    sys.modules.pop("rufusarm64_iso_write_mode", None)
    from rufusarm64_iso_write_mode import (
        build_iso_write_command,
        iso_layout_summary,
        iso_source_state,
        normalize_iso_cluster_size,
        normalize_iso_partition_scheme,
    )
finally:
    for name, module in _saved.items():
        if module is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = module


class ISOLayoutOptionTests(unittest.TestCase):
    def test_layout_normalization_is_bounded(self):
        self.assertEqual(normalize_iso_partition_scheme("GPT"), "gpt")
        self.assertEqual(normalize_iso_cluster_size("auto"), "4096")
        self.assertEqual(normalize_iso_cluster_size("32768"), "32768")
        with self.assertRaises(ValueError):
            normalize_iso_partition_scheme("apm")
        with self.assertRaises(ValueError):
            normalize_iso_cluster_size("65536")

    def test_source_change_resets_stale_windows_label(self):
        source, label = iso_source_state("/tmp/windows.iso", "/tmp/ubuntu.iso", "WIN11ARM64")
        self.assertEqual(source, os.path.realpath("/tmp/ubuntu.iso"))
        self.assertEqual(label, "RUFUS-LIVE")
        source2, label2 = iso_source_state(source, "/tmp/ubuntu.iso", "CUSTOM")
        self.assertEqual(source2, source)
        self.assertEqual(label2, "CUSTOM")

    def test_command_binds_gpt_cluster_and_label(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "ubuntu.iso"
            image.write_bytes(b"identity-bound-layout-test")
            cancel = Path(directory) / "cancel"
            command = build_iso_write_command(
                "/usr/bin/pkexec",
                "/usr/lib/rufusarm64/rufusarm64-persistence-helper",
                str(image),
                "/dev/sdz",
                "target-token",
                str(cancel),
                "ubuntu",
                "gpt",
                "8192",
            )
        self.assertEqual(command[command.index("--partition-scheme") + 1], "gpt")
        self.assertEqual(command[command.index("--cluster-size") + 1], "8192")
        self.assertEqual(command[command.index("--volume-label") + 1], "UBUNTU")
        self.assertIn("GPT / UEFI / FAT32 / 8 KiB clusters", iso_layout_summary("gpt", "8192", "ubuntu"))


if __name__ == "__main__":
    unittest.main()
''',
)

# Documentation and parity truthfulness.
replace(
    "docs/iso-image-mode.md",
    "ISO Image mode creates one conventional, writable FAT32 partition and extracts the supported ISO media tree onto it. The first implementation tranche is deliberately bounded to media that can be represented safely as ARM64 UEFI/FAT32 removable media.",
    "ISO Image mode creates one conventional, writable FAT32 partition and extracts the supported ISO media tree onto it. Compatible ARM64 UEFI media can use a reviewed MBR or GPT layout, a safe FAT32 cluster size, and an editable FAT32 label. UEFI and FAT32 remain capability-bound rather than cosmetic choices.",
)
replace(
    "docs/iso-image-mode.md",
    "Only after those checks pass does it create an active MBR FAT32-LBA partition, format it through a held partition descriptor, copy each file transactionally, hash every copied file back from the USB, run a read-only FAT32 consistency check, and flush the device.",
    "Only after those checks pass does it create the selected MBR FAT32-LBA or GPT EFI System Partition layout, format it through a held partition descriptor with the reviewed cluster size and label, copy each file transactionally, hash every copied file back from the USB, run a read-only FAT32 consistency check, and flush the device. Primary and backup GPT metadata are both written and read back when GPT is selected.",
)
replace(
    "docs/iso-image-mode.md",
    "Ordinary ISO Image mode does **not** modify boot configuration or enable persistence. Persistent live media remains a separate explicit workflow.\n",
    "Ordinary ISO Image mode does **not** modify boot configuration or enable persistence. Persistent live media remains a separate explicit workflow.\n\n## Visible layout choices\n\nFor compatible Linux ISOHybrid media, the main window exposes MBR or GPT and 4, 8, 16, or 32 KiB FAT32 clusters. The FAT32 label is editable and resets to `RUFUS-LIVE` when a different image is selected, preventing a stale Windows label from leaking into Linux media. Target system remains UEFI and filesystem remains FAT32 until separately reviewed boot paths justify broader choices. DD Image mode ignores all extraction-layout controls.\n",
)

parity_path = ROOT / "docs/upstream-rufus-parity.json"
parity = json.loads(parity_path.read_text(encoding="utf-8"))
for feature in parity.get("features", []):
    if feature.get("id") == "linux-iso-image-mode":
        feature["status"] = "partial"
        feature["notes"] = (
            "Suitable Linux ISOHybrid media receive an explicit Rufus-style choice with ISO Image mode recommended by default and DD retained as the exact-clone alternative. "
            "ISO mode now binds reviewed MBR/GPT, FAT32 cluster, and volume-label choices through confirmation, the privileged helper, diagnostics, metadata readback, copied-file verification, filesystem checking, flushing, and real reopened-loop qualification. "
            "UEFI and FAT32 remain capability-bound; Linux NTFS/UEFI:NTFS extraction and broader target-system/filesystem parity remain planned, and physical firmware boot remains release-qualification evidence."
        )
        break
else:
    raise SystemExit("linux-iso-image-mode parity row not found")
parity_path.write_text(json.dumps(parity, indent=2) + "\n", encoding="utf-8")

replace(
    "CHANGELOG.md",
    "# Changelog\n\n## 0.15.0 — 2026-07-28\n",
    "# Changelog\n\n## Unreleased\n\n- Expanded Linux ISO Image mode with exact MBR/GPT selection, reviewed FAT32 cluster sizes, an editable per-ISO label that resets when the image changes, and option-bound confirmation, diagnostics, GPT metadata readback, and real reopened-loop qualification.\n- Kept UEFI and FAT32 capability-bound and kept DD Image mode immutable; Linux NTFS/UEFI:NTFS extraction and broader filesystem/target-system parity remain planned.\n\n## 0.15.0 — 2026-07-28\n",
)

write(
    "docs/iso-layout-options-plan.md",
    """# ISO Image mode layout parity\n\nThis tranche expands the bounded Linux ISO Image mode while preserving DD semantics.\n\nDelivered scope:\n\n- MBR or GPT for compatible ARM64 UEFI ISO Image mode;\n- UEFI target and FAT32 filesystem remain capability-bound;\n- 4, 8, 16, or 32 KiB FAT32 clusters;\n- editable FAT32 label with per-image state and reset from stale Windows labels;\n- exact binding through confirmation, package-owned privileged helper, diagnostics, result evidence, and settings;\n- primary/backup GPT write and readback verification;\n- unit tests and real detached/reopened loop-device qualification for MBR and GPT;\n- DD mode continues to preserve the source image byte-for-byte and ignores extraction layout controls.\n\nRemaining parity includes separately reviewed Linux NTFS/UEFI:NTFS extraction and any broader target-system/filesystem choices. Physical firmware boot remains tracked in #399.\n\nRefs #289.\n""",
)

print("ISO layout-options tranche applied")
