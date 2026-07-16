package persistence

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"unicode/utf16"
)

// ReadWriteAt is the minimum interface needed to materialize a previously
// validated persistence partition proposal. *os.File satisfies it for regular
// files and block devices.
type ReadWriteAt interface {
	io.ReaderAt
	io.WriterAt
}

// MaterializeOptions supplies entropy for the GPT unique partition GUID. The
// default is crypto/rand.Reader. Tests may provide deterministic entropy.
type MaterializeOptions struct {
	Random io.Reader
}

var linuxFilesystemDataGUID = [16]byte{
	0xaf, 0x3d, 0xc6, 0x0f, 0x83, 0x84, 0x72, 0x47,
	0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4,
}

// ApplyPartitionPlan writes only partition-table metadata. It deliberately
// does not format the new partition or edit boot files. Before changing bytes,
// it rebuilds the plan from the currently open target and requires an exact
// match, preventing a stale proposal from being applied to different media.
func ApplyPartitionPlan(target ReadWriteAt, imageSize, targetSize uint64, plan Plan, opts MaterializeOptions) error {
	if target == nil {
		return errors.New("target is nil")
	}
	detection := Detection{
		Family:              plan.Family,
		BootParameter:       plan.BootParameter,
		Filesystem:          plan.Filesystem,
		FilesystemLabel:     plan.FilesystemLabel,
		PersistenceConfig:   plan.PersistenceConfig,
		PatchPaths:          append([]string(nil), plan.PatchPaths...),
		AlreadyEnabledPaths: append([]string(nil), plan.AlreadyEnabledPaths...),
	}
	fresh, err := BuildPlan(target, imageSize, targetSize, plan.SizeBytes, detection)
	if err != nil {
		return fmt.Errorf("revalidate persistence plan against target: %w", err)
	}
	if !plansEqual(fresh, plan) {
		return errors.New("persistence plan no longer matches the open target")
	}
	switch plan.PartitionTable {
	case TableMBR:
		return applyMBRPlan(target, plan)
	case TableGPT:
		return applyGPTPlan(target, imageSize, targetSize, plan, opts)
	default:
		return fmt.Errorf("unsupported partition table %q", plan.PartitionTable)
	}
}

func plansEqual(left, right Plan) bool {
	if left.Family != right.Family || left.PartitionTable != right.PartitionTable || left.PartitionNumber != right.PartitionNumber ||
		left.StartBytes != right.StartBytes || left.SizeBytes != right.SizeBytes || left.Filesystem != right.Filesystem ||
		left.FilesystemLabel != right.FilesystemLabel || left.BootParameter != right.BootParameter ||
		left.PersistenceConfig != right.PersistenceConfig || left.RequiresGPTRelocation != right.RequiresGPTRelocation {
		return false
	}
	return stringSlicesEqual(left.PatchPaths, right.PatchPaths) && stringSlicesEqual(left.AlreadyEnabledPaths, right.AlreadyEnabledPaths)
}

func stringSlicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func applyMBRPlan(target ReadWriteAt, plan Plan) error {
	if plan.PartitionNumber < 1 || plan.PartitionNumber > 4 || plan.StartBytes%sectorSize != 0 || plan.SizeBytes%sectorSize != 0 {
		return errors.New("invalid MBR persistence geometry")
	}
	sector, err := readAtExact(target, 0, sectorSize, "target MBR")
	if err != nil {
		return err
	}
	offset := 446 + (plan.PartitionNumber-1)*16
	entry := sector[offset : offset+16]
	if !allZero(entry) {
		return errors.New("planned MBR partition entry is no longer empty")
	}
	start := plan.StartBytes / sectorSize
	count := plan.SizeBytes / sectorSize
	if start > math.MaxUint32 || count == 0 || count > math.MaxUint32 || start+count > uint64(math.MaxUint32)+1 {
		return errors.New("MBR persistence geometry exceeds 32-bit LBA limits")
	}
	entry[0] = 0
	entry[1], entry[2], entry[3] = 0xfe, 0xff, 0xff
	entry[4] = 0x83 // Linux filesystem
	entry[5], entry[6], entry[7] = 0xfe, 0xff, 0xff
	binary.LittleEndian.PutUint32(entry[8:12], uint32(start))
	binary.LittleEndian.PutUint32(entry[12:16], uint32(count))
	if err := writeAtFull(target, sector, 0); err != nil {
		return fmt.Errorf("write target MBR: %w", err)
	}
	check, err := readAtExact(target, 0, sectorSize, "written target MBR")
	if err != nil {
		return err
	}
	if !bytes.Equal(check[offset:offset+16], entry) || check[510] != 0x55 || check[511] != 0xaa {
		return errors.New("written MBR persistence entry did not verify")
	}
	return syncIfSupported(target)
}

func applyGPTPlan(target ReadWriteAt, imageSize, targetSize uint64, plan Plan, opts MaterializeOptions) error {
	if !plan.RequiresGPTRelocation || plan.PartitionNumber < 1 || plan.StartBytes%sectorSize != 0 || plan.SizeBytes%sectorSize != 0 {
		return errors.New("invalid GPT persistence geometry")
	}
	if imageSize%sectorSize != 0 || targetSize%sectorSize != 0 || targetSize <= imageSize {
		return errors.New("invalid GPT source or target size")
	}
	primarySector, err := readAtExact(target, sectorSize, sectorSize, "primary GPT header")
	if err != nil {
		return err
	}
	primary, err := parseGPTHeader(primarySector, "primary")
	if err != nil {
		return err
	}
	entriesBytes := uint64(primary.NumEntries) * uint64(primary.EntrySize)
	entrySectors := (entriesBytes + sectorSize - 1) / sectorSize
	entries, err := readAtExact(target, primary.EntriesLBA*sectorSize, entriesBytes, "primary GPT entry table")
	if err != nil {
		return err
	}
	entryIndex := plan.PartitionNumber - 1
	if entryIndex < 0 || entryIndex >= int(primary.NumEntries) {
		return errors.New("planned GPT partition entry is outside the table")
	}
	entryOffset := uint64(entryIndex) * uint64(primary.EntrySize)
	entry := entries[entryOffset : entryOffset+uint64(primary.EntrySize)]
	if !allZero(entry) {
		return errors.New("planned GPT partition entry is no longer empty")
	}

	targetSectors := targetSize / sectorSize
	backupHeaderLBA := targetSectors - 1
	if backupHeaderLBA <= entrySectors+1 {
		return errors.New("target is too small for relocated GPT metadata")
	}
	backupEntriesLBA := backupHeaderLBA - entrySectors
	lastUsable := backupEntriesLBA - 1
	first := plan.StartBytes / sectorSize
	count := plan.SizeBytes / sectorSize
	if count == 0 || first+count < first || first < primary.FirstUsable || first+count-1 > lastUsable {
		return errors.New("planned GPT persistence partition overlaps reserved metadata")
	}

	random := opts.Random
	if random == nil {
		random = rand.Reader
	}
	unique, err := newUniqueGUID(random, entries, primary)
	if err != nil {
		return err
	}
	copy(entry[:16], linuxFilesystemDataGUID[:])
	copy(entry[16:32], unique[:])
	binary.LittleEndian.PutUint64(entry[32:40], first)
	binary.LittleEndian.PutUint64(entry[40:48], first+count-1)
	binary.LittleEndian.PutUint64(entry[48:56], 0)
	writeGPTName(entry[56:], "Rufus persistence")
	entriesCRC := crc32.ChecksumIEEE(entries)

	oldBackupHeaderLBA := primary.BackupLBA
	oldEntrySectors := entrySectors
	oldBackupEntriesLBA := oldBackupHeaderLBA - oldEntrySectors
	backupSector, err := readAtExact(target, oldBackupHeaderLBA*sectorSize, sectorSize, "existing backup GPT header")
	if err != nil {
		return err
	}

	newPrimary := append([]byte(nil), primarySector...)
	newBackup := append([]byte(nil), backupSector...)
	updateGPTHeader(newPrimary, 1, backupHeaderLBA, primary.FirstUsable, lastUsable, primary.EntriesLBA, entriesCRC)
	updateGPTHeader(newBackup, backupHeaderLBA, 1, primary.FirstUsable, lastUsable, backupEntriesLBA, entriesCRC)
	paddedEntries := make([]byte, entrySectors*sectorSize)
	copy(paddedEntries, entries)

	// Write the new backup first. If interrupted before the primary is updated,
	// the original primary and backup remain the authoritative pair.
	if err := writeAtFull(target, paddedEntries, backupEntriesLBA*sectorSize); err != nil {
		return fmt.Errorf("write relocated backup GPT entries: %w", err)
	}
	if err := writeAtFull(target, newBackup, backupHeaderLBA*sectorSize); err != nil {
		return fmt.Errorf("write relocated backup GPT header: %w", err)
	}
	if err := syncIfSupported(target); err != nil {
		return err
	}

	if err := writeAtFull(target, paddedEntries, primary.EntriesLBA*sectorSize); err != nil {
		return fmt.Errorf("write primary GPT entries: %w", err)
	}
	if err := writeAtFull(target, newPrimary, sectorSize); err != nil {
		return fmt.Errorf("write primary GPT header: %w", err)
	}
	mbr, err := readAtExact(target, 0, sectorSize, "protective MBR")
	if err != nil {
		return err
	}
	protectiveCount := targetSectors - 1
	if protectiveCount > math.MaxUint32 {
		protectiveCount = math.MaxUint32
	}
	binary.LittleEndian.PutUint32(mbr[446+12:446+16], uint32(protectiveCount))
	if err := writeAtFull(target, mbr, 0); err != nil {
		return fmt.Errorf("update protective MBR: %w", err)
	}
	if err := syncIfSupported(target); err != nil {
		return err
	}

	// Remove the obsolete backup metadata only after the new pair is durable.
	if oldBackupHeaderLBA != backupHeaderLBA {
		zero := make([]byte, (oldEntrySectors+1)*sectorSize)
		if err := writeAtFull(target, zero, oldBackupEntriesLBA*sectorSize); err != nil {
			return fmt.Errorf("clear obsolete backup GPT metadata: %w", err)
		}
		if err := syncIfSupported(target); err != nil {
			return err
		}
	}
	return verifyMaterializedGPT(target, targetSize, plan, unique)
}

func newUniqueGUID(random io.Reader, entries []byte, header gptHeader) ([16]byte, error) {
	for attempt := 0; attempt < 16; attempt++ {
		var guid [16]byte
		if _, err := io.ReadFull(random, guid[:]); err != nil {
			return guid, fmt.Errorf("generate GPT partition GUID: %w", err)
		}
		guid[6] = (guid[6] & 0x0f) | 0x40
		guid[8] = (guid[8] & 0x3f) | 0x80
		if allZero(guid[:]) {
			continue
		}
		duplicate := false
		for index := uint32(0); index < header.NumEntries; index++ {
			offset := uint64(index) * uint64(header.EntrySize)
			if bytes.Equal(entries[offset+16:offset+32], guid[:]) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			return guid, nil
		}
	}
	return [16]byte{}, errors.New("could not generate a unique GPT partition GUID")
}

func writeGPTName(destination []byte, name string) {
	for index := range destination {
		destination[index] = 0
	}
	encoded := utf16.Encode([]rune(name))
	limit := len(destination) / 2
	if len(encoded) > limit {
		encoded = encoded[:limit]
	}
	for index, value := range encoded {
		binary.LittleEndian.PutUint16(destination[index*2:index*2+2], value)
	}
}

func updateGPTHeader(header []byte, current, backup, firstUsable, lastUsable, entriesLBA uint64, entriesCRC uint32) {
	headerSize := binary.LittleEndian.Uint32(header[12:16])
	binary.LittleEndian.PutUint64(header[24:32], current)
	binary.LittleEndian.PutUint64(header[32:40], backup)
	binary.LittleEndian.PutUint64(header[40:48], firstUsable)
	binary.LittleEndian.PutUint64(header[48:56], lastUsable)
	binary.LittleEndian.PutUint64(header[72:80], entriesLBA)
	binary.LittleEndian.PutUint32(header[88:92], entriesCRC)
	binary.LittleEndian.PutUint32(header[16:20], 0)
	binary.LittleEndian.PutUint32(header[16:20], crc32.ChecksumIEEE(header[:headerSize]))
}

func verifyMaterializedGPT(target ReadWriteAt, targetSize uint64, plan Plan, unique [16]byte) error {
	primaryBytes, err := readAtExact(target, sectorSize, sectorSize, "written primary GPT header")
	if err != nil {
		return err
	}
	primary, err := parseGPTHeader(primaryBytes, "written primary")
	if err != nil {
		return err
	}
	if primary.BackupLBA != targetSize/sectorSize-1 {
		return errors.New("written primary GPT points to the wrong backup header")
	}
	entriesBytes := uint64(primary.NumEntries) * uint64(primary.EntrySize)
	entries, err := readAtExact(target, primary.EntriesLBA*sectorSize, entriesBytes, "written primary GPT entries")
	if err != nil {
		return err
	}
	if crc32.ChecksumIEEE(entries) != primary.EntriesCRC {
		return errors.New("written primary GPT entry-table CRC is invalid")
	}
	offset := uint64(plan.PartitionNumber-1) * uint64(primary.EntrySize)
	entry := entries[offset : offset+uint64(primary.EntrySize)]
	if !bytes.Equal(entry[:16], linuxFilesystemDataGUID[:]) || !bytes.Equal(entry[16:32], unique[:]) ||
		binary.LittleEndian.Uint64(entry[32:40])*sectorSize != plan.StartBytes ||
		(binary.LittleEndian.Uint64(entry[40:48])-binary.LittleEndian.Uint64(entry[32:40])+1)*sectorSize != plan.SizeBytes {
		return errors.New("written GPT persistence entry did not verify")
	}
	backupBytes, err := readAtExact(target, primary.BackupLBA*sectorSize, sectorSize, "written backup GPT header")
	if err != nil {
		return err
	}
	backup, err := parseGPTHeader(backupBytes, "written backup")
	if err != nil {
		return err
	}
	if backup.BackupLBA != 1 || backup.EntriesCRC != primary.EntriesCRC || backup.LastUsable != primary.LastUsable {
		return errors.New("written GPT headers are inconsistent")
	}
	backupEntries, err := readAtExact(target, backup.EntriesLBA*sectorSize, entriesBytes, "written backup GPT entries")
	if err != nil {
		return err
	}
	if !bytes.Equal(entries, backupEntries) || crc32.ChecksumIEEE(backupEntries) != backup.EntriesCRC {
		return errors.New("written GPT entry tables are inconsistent")
	}
	return nil
}

func writeAtFull(writer io.WriterAt, data []byte, offset uint64) error {
	if offset > math.MaxInt64 {
		return errors.New("write offset is too large")
	}
	written := 0
	for written < len(data) {
		n, err := writer.WriteAt(data[written:], int64(offset)+int64(written))
		written += n
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func syncIfSupported(target any) error {
	if syncer, ok := target.(interface{ Sync() error }); ok {
		if err := syncer.Sync(); err != nil {
			return fmt.Errorf("sync persistence partition metadata: %w", err)
		}
	}
	return nil
}
