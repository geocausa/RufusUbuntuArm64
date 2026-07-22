//go:build linux

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/geocausa/RufusArm64/internal/freedos"
)

func TestFreeDOSProgressEmitterAccountsForWriteAndReadback(t *testing.T) {
	var output bytes.Buffer
	emitter := newFreeDOSProgressEmitter(&output, 100)
	for _, progress := range []freedos.ExecutionProgress{
		{Phase: freedos.ExecutionPhasePrepare},
		{Phase: freedos.ExecutionPhaseWrite, Processed: 50, Total: 100},
		{Phase: freedos.ExecutionPhaseFlush},
		{Phase: freedos.ExecutionPhaseReadback, Processed: 50, Total: 100},
		{Phase: freedos.ExecutionPhaseFinish},
	} {
		if err := emitter.Emit(progress); err != nil {
			t.Fatal(err)
		}
	}
	var records []freeDOSProgressRecord
	scanner := bufio.NewScanner(&output)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, freeDOSProgressPrefix) {
			t.Fatalf("progress line lacks prefix: %q", line)
		}
		var record freeDOSProgressRecord
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, freeDOSProgressPrefix)), &record); err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(records) != 5 {
		t.Fatalf("records=%d, want 5: %+v", len(records), records)
	}
	if records[1].OverallDone != 50 || records[3].OverallDone != 150 || records[4].OverallDone != 200 {
		t.Fatalf("unexpected full-device accounting: %+v", records)
	}
	for _, record := range records {
		if record.Schema != 1 || record.Type != "progress" || record.OverallTotal != 200 {
			t.Fatalf("invalid progress record: %+v", record)
		}
	}
}
