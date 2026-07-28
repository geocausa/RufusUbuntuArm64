package persistence

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestApplyMBRPartitionPlanFailureStates(t *testing.T) {
	for _, test := range []struct {
		name             string
		failWriteCall    int
		partialWriteSize int
		failSyncCall     int
	}{
		{name: "partial write", failWriteCall: 1, partialWriteSize: 480},
		{name: "post-write sync", failSyncCall: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			file, imageSize, targetSize, plan := newMBRFailureTarget(t)
			defer file.Close()
			before := readFailureRange(t, file, 0, sectorSize)
			injected := errors.New("injected MBR materialization failure")
			target := &failureTarget{
				file: file, failWriteCall: test.failWriteCall,
				partialWriteSize: test.partialWriteSize,
				failSyncCall:     test.failSyncCall,
				writeErr:         injected, syncErr: injected,
			}

			err := ApplyPartitionPlan(target, imageSize, targetSize, plan, MaterializeOptions{})
			if !errors.Is(err, injected) {
				t.Fatalf("materialization error = %v", err)
			}
			after := readFailureRange(t, file, 0, sectorSize)
			if bytes.Equal(before, after) {
				t.Fatal("post-mutation failure left no inspectable MBR evidence")
			}
			if after[510] != 0x55 || after[511] != 0xaa {
				t.Fatalf("MBR signature changed after failure: %x", after[510:512])
			}
		})
	}
}

func newMBRFailureTarget(t *testing.T) (*os.File, uint64, uint64, Plan) {
	t.Helper()
	imageSize := uint64(64 * testMiB)
	targetSize := uint64(4 * 1024 * testMiB)
	file, err := os.OpenFile(filepath.Join(t.TempDir(), "target.img"), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(int64(targetSize)); err != nil {
		file.Close()
		t.Fatal(err)
	}
	mbr := make([]byte, sectorSize)
	mbr[510], mbr[511] = 0x55, 0xaa
	entry := mbr[446:462]
	entry[4] = 0x17
	binary.LittleEndian.PutUint32(entry[8:12], 64)
	binary.LittleEndian.PutUint32(entry[12:16], uint32(imageSize/sectorSize-64))
	if _, err := file.WriteAt(mbr, 0); err != nil {
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

func readFailureRange(t *testing.T, file *os.File, offset, size uint64) []byte {
	t.Helper()
	buffer := make([]byte, size)
	if _, err := file.ReadAt(buffer, int64(offset)); err != nil {
		t.Fatal(err)
	}
	return buffer
}

type failureTarget struct {
	file             *os.File
	failWriteCall    int
	partialWriteSize int
	failSyncCall     int
	writeCalls       int
	syncCalls        int
	writeErr         error
	syncErr          error
}

func (target *failureTarget) ReadAt(buffer []byte, offset int64) (int, error) {
	return target.file.ReadAt(buffer, offset)
}

func (target *failureTarget) WriteAt(buffer []byte, offset int64) (int, error) {
	target.writeCalls++
	if target.writeCalls == target.failWriteCall {
		count := target.partialWriteSize
		if count > len(buffer) {
			count = len(buffer)
		}
		if count > 0 {
			written, err := target.file.WriteAt(buffer[:count], offset)
			if err != nil {
				return written, err
			}
			return written, target.writeErr
		}
		return 0, target.writeErr
	}
	return target.file.WriteAt(buffer, offset)
}

func (target *failureTarget) Sync() error {
	target.syncCalls++
	if target.syncCalls == target.failSyncCall {
		return target.syncErr
	}
	return target.file.Sync()
}
