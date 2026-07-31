//go:build linux

package windowstogo

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
)

type gptDevice interface {
	io.ReaderAt
	io.WriterAt
	Sync() error
}

type gptRegion struct {
	name   string
	offset uint64
	data   []byte
}

// WriteGPT writes backup metadata before primary metadata, makes each phase
// durable, and independently rereads every byte. The ordering leaves the target
// with recoverable backup metadata if power is lost during the second phase.
func WriteGPT(target gptDevice, layout GPTLayout, plan Plan) error {
	if target == nil {
		return errors.New("windows To Go GPT target is nil")
	}
	if err := ValidateGPT(layout, plan); err != nil {
		return err
	}
	sector := layout.SectorSize
	backup := []gptRegion{
		{name: "backup GPT entries", offset: layout.BackupEntriesLBA * sector, data: layout.BackupEntries},
		{name: "backup GPT header", offset: layout.BackupHeaderLBA * sector, data: layout.BackupHeader},
	}
	primary := []gptRegion{
		{name: "primary GPT entries", offset: layout.PrimaryEntriesLBA * sector, data: layout.PrimaryEntries},
		{name: "primary GPT header", offset: layout.PrimaryHeaderLBA * sector, data: layout.PrimaryHeader},
		{name: "protective MBR", offset: 0, data: layout.ProtectiveMBR},
	}
	for _, region := range backup {
		if err := writeGPTRegion(target, region); err != nil {
			return err
		}
	}
	if err := target.Sync(); err != nil {
		return fmt.Errorf("make backup GPT durable: %w", err)
	}
	for _, region := range primary {
		if err := writeGPTRegion(target, region); err != nil {
			return err
		}
	}
	if err := target.Sync(); err != nil {
		return fmt.Errorf("make primary GPT durable: %w", err)
	}
	for _, region := range append(append([]gptRegion(nil), backup...), primary...) {
		if err := verifyGPTRegion(target, region); err != nil {
			return err
		}
	}
	return nil
}

func writeGPTRegion(target io.WriterAt, region gptRegion) error {
	if region.offset > math.MaxInt64 || uint64(len(region.data)) > math.MaxInt64-region.offset {
		return fmt.Errorf("%s exceeds the supported signed device offset", region.name)
	}
	written, err := target.WriteAt(region.data, int64(region.offset))
	if err != nil {
		return fmt.Errorf("write %s: %w", region.name, err)
	}
	if written != len(region.data) {
		return fmt.Errorf("write %s: %w", region.name, io.ErrShortWrite)
	}
	return nil
}

func verifyGPTRegion(target io.ReaderAt, region gptRegion) error {
	if region.offset > math.MaxInt64 || uint64(len(region.data)) > math.MaxInt64-region.offset {
		return fmt.Errorf("%s readback exceeds the supported signed device offset", region.name)
	}
	actual := make([]byte, len(region.data))
	read, err := target.ReadAt(actual, int64(region.offset))
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read back %s: %w", region.name, err)
	}
	if read != len(actual) {
		return fmt.Errorf("read back %s: %w", region.name, io.ErrUnexpectedEOF)
	}
	if !bytes.Equal(actual, region.data) {
		return fmt.Errorf("read back %s: content mismatch", region.name)
	}
	return nil
}

// VerifyGPTOnDevice rereads the already-written GPT without modifying it.
func VerifyGPTOnDevice(target io.ReaderAt, layout GPTLayout, plan Plan) error {
	if target == nil {
		return errors.New("windows To Go GPT verification target is nil")
	}
	if err := ValidateGPT(layout, plan); err != nil {
		return err
	}
	sector := layout.SectorSize
	regions := []gptRegion{
		{name: "backup GPT entries", offset: layout.BackupEntriesLBA * sector, data: layout.BackupEntries},
		{name: "backup GPT header", offset: layout.BackupHeaderLBA * sector, data: layout.BackupHeader},
		{name: "primary GPT entries", offset: layout.PrimaryEntriesLBA * sector, data: layout.PrimaryEntries},
		{name: "primary GPT header", offset: layout.PrimaryHeaderLBA * sector, data: layout.PrimaryHeader},
		{name: "protective MBR", offset: 0, data: layout.ProtectiveMBR},
	}
	for _, region := range regions {
		if err := verifyGPTRegion(target, region); err != nil {
			return err
		}
	}
	return nil
}
