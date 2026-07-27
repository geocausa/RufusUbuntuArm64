package drivebackup

import "testing"

func TestQEMUProgressWriterIsMonotonicAndReservesCompletion(t *testing.T) {
	diagnostics := newBoundedCommandBuffer(maxQEMUDiagnosticBytes)
	var events []Progress
	writer := newQEMUProgressWriter(diagnostics, 1000, func(progress Progress) {
		events = append(events, progress)
	})
	for _, chunk := range []string{
		"    (0.00/",
		"100%)\r    (12.50/100%)\r",
		"    (12.50/100%)\r    (99.99/100%)\r",
		"    (100.00/100%)\r",
	} {
		if n, err := writer.Write([]byte(chunk)); err != nil || n != len(chunk) {
			t.Fatalf("write=%d,%v", n, err)
		}
	}
	if len(events) == 0 {
		t.Fatal("no progress events were emitted")
	}
	var previous uint64
	for index, event := range events {
		if event.Total != 1000 || event.Done <= previous || event.Done >= event.Total {
			t.Fatalf("event %d is not bounded and monotonic: previous=%d event=%+v", index, previous, event)
		}
		previous = event.Done
	}
	if diagnostics.buffer.Len() == 0 || diagnostics.exceeded {
		t.Fatalf("diagnostics length=%d exceeded=%t", diagnostics.buffer.Len(), diagnostics.exceeded)
	}
}

func TestQEMUProgressWriterIgnoresMalformedPercentages(t *testing.T) {
	diagnostics := newBoundedCommandBuffer(maxQEMUDiagnosticBytes)
	var events []Progress
	writer := newQEMUProgressWriter(diagnostics, 100, func(progress Progress) {
		events = append(events, progress)
	})
	_, _ = writer.Write([]byte("(NaN/100%) (-1.00/100%) (101.00/100%) diagnostic"))
	if len(events) != 0 {
		t.Fatalf("malformed progress produced events: %+v", events)
	}
	if string(diagnostics.Bytes()) == "" {
		t.Fatal("diagnostics were not retained")
	}
}
