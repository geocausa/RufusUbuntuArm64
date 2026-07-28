package persistence

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestApplyGPTPartitionPlanEntropyFailureLeavesMetadataUnchanged(t *testing.T) {
	file, imageSize, targetSize, plan := newGPTFailureTarget(t)
	defer file.Close()
	target := &failureTarget{file: file}
	beforePrimary := readFailureRange(t, file, 0, 34*sectorSize)
	beforeOldBackup := readFailureRange(t, file, imageSize-34*sectorSize, 34*sectorSize)
	injected := errors.New("injected GPT entropy failure")

	err := ApplyPartitionPlan(target, imageSize, targetSize, plan, MaterializeOptions{Random: failingEntropy{err: injected}})
	if !errors.Is(err, injected) {
		t.Fatalf("entropy failure = %v", err)
	}
	if target.writeCalls != 0 || target.syncCalls != 0 {
		t.Fatalf("entropy failure wrote target: writes=%d syncs=%d", target.writeCalls, target.syncCalls)
	}
	if !bytes.Equal(beforePrimary, readFailureRange(t, file, 0, 34*sectorSize)) {
		t.Fatal("primary GPT metadata changed before the first write")
	}
	if !bytes.Equal(beforeOldBackup, readFailureRange(t, file, imageSize-34*sectorSize, 34*sectorSize)) {
		t.Fatal("original backup GPT metadata changed before the first write")
	}
}

func TestApplyGPTPartitionPlanInterruptedWriteOrdering(t *testing.T) {
	for _, test := range []struct {
		name             string
		failWriteCall    int
		partialWriteSize int
		failSyncCall     int
		wantNewBackup    bool
		wantPrimaryMoved bool
	}{
		{name: "relocated backup entries", failWriteCall: 1, partialWriteSize: 1024},
		{name: "first durable backup sync", failSyncCall: 1, wantNewBackup: true},
		{name: "primary entry publication", failWriteCall: 3, partialWriteSize: 1024, wantNewBackup: true},
		{name: "obsolete backup cleanup", failWriteCall: 6, partialWriteSize: 512, wantNewBackup: true, wantPrimaryMoved: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			file, imageSize, targetSize, plan := newGPTFailureTarget(t)
			defer file.Close()
			beforePrimary := readFailureRange(t, file, sectorSize, sectorSize)
			beforeOldBackup := readFailureRange(t, file, imageSize-sectorSize, sectorSize)
			injected := errors.New("injected GPT materialization interruption")
			target := &failureTarget{
				file: file, failWriteCall: test.failWriteCall,
				partialWriteSize: test.partialWriteSize,
				failSyncCall: test.failSyncCall,
				writeErr: injected, syncErr: injected,
			}

			err := ApplyPartitionPlan(target, imageSize, targetSize, plan, MaterializeOptions{Random: bytes.NewReader(bytes.Repeat([]byte{0x44}, 64))})
			if !errors.Is(err, injected) {
				t.Fatalf("GPT interruption error = %v", err)
			}

			primaryBytes := readFailureRange(t, file, sectorSize, sectorSize)
			primary, primaryErr := parseGPTHeader(primaryBytes, "interrupted primary")
			primaryMoved := primaryErr == nil && primary.BackupLBA == targetSize/sectorSize-1
			if primaryMoved != test.wantPrimaryMoved {
				t.Fatalf("primary moved = %v, want %v (parse error %v)", primaryMoved, test.wantPrimaryMoved, primaryErr)
			}
			if !test.wantPrimaryMoved && !bytes.Equal(primaryBytes, beforePrimary) {
				t.Fatal("primary GPT header changed before its admitted publication point")
			}

			newBackupBytes := readFailureRange(t, file, targetSize-sectorSize, sectorSize)
			newBackup, newBackupErr := parseGPTHeader(newBackupBytes, "interrupted relocated backup")
			newBackupPresent := newBackupErr == nil && newBackup.CurrentLBA == targetSize/sectorSize-1 && newBackup.BackupLBA == 1
			if newBackupPresent != test.wantNewBackup {
				t.Fatalf("relocated backup present = %v, want %v (parse error %v)", newBackupPresent, test.wantNewBackup, newBackupErr)
			}

			oldBackupBytes := readFailureRange(t, file, imageSize-sectorSize, sectorSize)
			if allZero(oldBackupBytes) {
				t.Fatal("old backup GPT evidence disappeared during an interrupted operation")
			}
			if test.name != "obsolete backup cleanup" && !bytes.Equal(oldBackupBytes, beforeOldBackup) {
				t.Fatal("original backup GPT changed before cleanup")
			}
		})
	}
}

func newGPTFailureTarget(t *testing.T) (*os.File, uint64, uint64, Plan) {
	t.Helper()
	image, imageSize := testGPTImage(t, 128, false)
	targetSize := uint64(8 * 1024 * testMiB)
	file, err := os.OpenFile(filepath.Join(t.TempDir(), "target.img"), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(int64(targetSize)); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if _, err := file.WriteAt(image, 0); err != nil {
		file.Close()
		t.Fatal(err)
	}
	plan, err := BuildPlan(file, imageSize, targetSize, 2*1024*testMiB, readyDetection())
	if err != nil {
		file.Close()
		t.Fatal(err)
	}
	return file, imageSize, targetSize, plan
}

type failingEntropy struct {
	err error
}

func (reader failingEntropy) Read([]byte) (int, error) {
	return 0, reader.err
}

var _ io.Reader = failingEntropy{}
