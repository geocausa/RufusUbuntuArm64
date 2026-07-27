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

func TestFreeDOSProgressEmitterAccountsForRequiredWriteAndReadback(t *testing.T) {
	var output bytes.Buffer
	emitter := newFreeDOSProgressEmitter(&output, 60, 40)
	for _, progress := range []freedos.ExecutionProgress{
		{Phase: freedos.ExecutionPhasePrepare},
		{Phase: freedos.ExecutionPhaseWrite, Processed: 30, Total: 60},
		{Phase: freedos.ExecutionPhaseFlush},
		{Phase: freedos.ExecutionPhaseReadback, Processed: 20, Total: 40},
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
	if records[1].OverallDone != 30 || records[3].OverallDone != 80 || records[4].OverallDone != 100 {
		t.Fatalf("unexpected required-extent accounting: %+v", records)
	}
	for _, record := range records {
		if record.Schema != 1 || record.Type != "progress" || record.OverallTotal != 100 {
			t.Fatalf("invalid progress record: %+v", record)
		}
	}
}

func TestFreeDOSProgressEmitterRejectsAlteredPhaseTotals(t *testing.T) {
	var output bytes.Buffer
	emitter := newFreeDOSProgressEmitter(&output, 60, 40)
	if err := emitter.Emit(freedos.ExecutionProgress{Phase: freedos.ExecutionPhaseWrite, Processed: 1, Total: 61}); err == nil {
		t.Fatal("write progress accepted an altered total")
	}
	if err := emitter.Emit(freedos.ExecutionProgress{Phase: freedos.ExecutionPhaseReadback, Processed: 1, Total: 41}); err == nil {
		t.Fatal("readback progress accepted an altered total")
	}
}
