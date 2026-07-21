package qualification

import (
	"math"
	"strings"
	"testing"
)

func TestNormalizeRecordAcceptsCheckedNearLimitExtents(t *testing.T) {
	record := validRecord()
	record.TargetSize = math.MaxUint64
	record.Boot.StartBytes = math.MaxUint64 - 3000
	record.Boot.SizeBytes = 1000
	record.Persistence.StartBytes = math.MaxUint64 - 1500
	record.Persistence.SizeBytes = 1000

	if _, err := NormalizeRecord(record); err != nil {
		t.Fatalf("valid near-limit extents were rejected: %v", err)
	}
}

func TestNormalizeRecordRejectsOverflowingBootExtent(t *testing.T) {
	record := validRecord()
	record.TargetSize = math.MaxUint64
	record.Boot.StartBytes = math.MaxUint64 - 100
	record.Boot.SizeBytes = 200

	if _, err := NormalizeRecord(record); err == nil || !strings.Contains(err.Error(), "boot partition extent") {
		t.Fatalf("overflowing boot extent error = %v", err)
	}
}

func TestNormalizeRecordRejectsOverflowingPersistenceExtent(t *testing.T) {
	record := validRecord()
	record.TargetSize = math.MaxUint64
	record.Persistence.StartBytes = math.MaxUint64 - 100
	record.Persistence.SizeBytes = 200

	if _, err := NormalizeRecord(record); err == nil || !strings.Contains(err.Error(), "persistence partition extent") {
		t.Fatalf("overflowing persistence extent error = %v", err)
	}
}
