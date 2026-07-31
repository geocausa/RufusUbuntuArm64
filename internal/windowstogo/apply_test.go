//go:build linux

package windowstogo

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSplitCommandRecordsHandlesCarriageReturnProgress(t *testing.T) {
	input := "first\rsecond\r\nthird\nfourth"
	scanner := bufio.NewScanner(strings.NewReader(input))
	scanner.Split(splitCommandRecords)
	var records []string
	for scanner.Scan() {
		records = append(records, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	want := []string{"first", "second", "third", "fourth"}
	if !reflect.DeepEqual(records, want) {
		t.Fatalf("records=%q want=%q", records, want)
	}
}

func TestParseWIMApplyPercent(t *testing.T) {
	for line, want := range map[string]int{
		"Extracting file data: 0 MiB of 96 MiB (0%) done":    0,
		"Extracting file data: 48 MiB of 96 MiB (50%) done":  50,
		"Extracting file data: 96 MiB of 96 MiB (100%) done": 100,
	} {
		got, ok := parseWIMApplyPercent(line)
		if !ok || got != want {
			t.Fatalf("parse %q = %d,%v want %d,true", line, got, ok, want)
		}
	}
	for _, line := range []string{
		"Applying image 1",
		"Extracting file data: 97 MiB of 96 MiB (101%) done",
		"Extracting file data: 48 MiB of 96 MiB (50%)",
		"warning: 50% of something unrelated",
	} {
		if percent, ok := parseWIMApplyPercent(line); ok {
			t.Fatalf("unexpected progress parse %q = %d", line, percent)
		}
	}
}

func TestReadIOErrorCounterAndHealthEvaluation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ioerr_cnt")
	if err := os.WriteFile(path, []byte("0x1f\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	count, err := readIOErrorCounter(path)
	if err != nil || count != 31 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	if err := evaluateTargetHealth(31, 31, "running"); err != nil {
		t.Fatalf("healthy target rejected: %v", err)
	}
	for _, test := range []struct {
		current uint64
		state   string
	}{
		{current: 32, state: "running"},
		{current: 31, state: "offline"},
		{current: 30, state: "running"},
	} {
		if err := evaluateTargetHealth(31, test.current, test.state); !errors.Is(err, errTargetIO) {
			t.Fatalf("current=%d state=%q err=%v", test.current, test.state, err)
		}
	}
}

type eventRecorder struct {
	mutex  sync.Mutex
	events []Event
}

func (recorder *eventRecorder) emit(event Event) {
	recorder.mutex.Lock()
	defer recorder.mutex.Unlock()
	recorder.events = append(recorder.events, event)
}

func (recorder *eventRecorder) snapshot() []Event {
	recorder.mutex.Lock()
	defer recorder.mutex.Unlock()
	return append([]Event(nil), recorder.events...)
}

func executableScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nset -eu\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunWIMApplyStreamsMonotonicProgress(t *testing.T) {
	executable := executableScript(t, `
printf 'Applying image 1 ("Test") from "/tmp/test.wim" to NTFS volume "/dev/test"\n'
printf 'Extracting file data: 0 MiB of 96 MiB (0%%) done\r'
sleep 0.02
printf 'Extracting file data: 24 MiB of 96 MiB (25%%) done\r'
sleep 0.02
printf 'Extracting file data: 48 MiB of 96 MiB (50%%) done\r'
sleep 0.02
printf 'Extracting file data: 96 MiB of 96 MiB (100%%) done\n'
printf 'Done applying WIM image.\n'
`)
	recorder := &eventRecorder{}
	const total = uint64(24 * 1024 * 1024 * 1024)
	if err := runWIMApply(
		context.Background(), executable, []string{"apply", "/tmp/test.wim", "1", "/dev/test"},
		"Applying Windows image…", total, nil, 10*time.Millisecond, 50*time.Millisecond, recorder.emit,
	); err != nil {
		t.Fatal(err)
	}
	var percentages []uint64
	var sawRate bool
	for _, event := range recorder.snapshot() {
		if event.Stage != "apply" || event.Total != total {
			continue
		}
		percentages = append(percentages, event.Done*100/event.Total)
		if event.Rate > 0 {
			sawRate = true
		}
	}
	if want := []uint64{0, 25, 50, 100}; !reflect.DeepEqual(percentages, want) {
		t.Fatalf("percentages=%v want=%v events=%#v", percentages, want, recorder.snapshot())
	}
	if !sawRate {
		t.Fatal("streamed progress never reported a transfer rate")
	}
}

type failingHealthMonitor struct {
	mutex  sync.Mutex
	checks int
}

func (monitor *failingHealthMonitor) Check() error {
	monitor.mutex.Lock()
	defer monitor.mutex.Unlock()
	monitor.checks++
	if monitor.checks >= 2 {
		return fmt.Errorf("%w: injected counter increment", errTargetIO)
	}
	return nil
}

func TestRunWIMApplyCancelsOnTargetIOFailure(t *testing.T) {
	executable := executableScript(t, `
printf 'Extracting file data: 1 MiB of 100 MiB (1%%) done\r'
exec /bin/sleep 30
`)
	recorder := &eventRecorder{}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	started := time.Now()
	err := runWIMApply(
		ctx, executable, []string{"apply", "/tmp/test.wim", "1", "/dev/test"},
		"Applying Windows image…", 1000, &failingHealthMonitor{}, 10*time.Millisecond, 50*time.Millisecond, recorder.emit,
	)
	if !errors.Is(err, errTargetIO) {
		t.Fatalf("err=%v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("I/O failure cancellation took %s", elapsed)
	}
	var sawFailure bool
	for _, event := range recorder.snapshot() {
		if event.Stage == "target_io_error" && strings.Contains(event.Message, "hardware I/O failure") {
			sawFailure = true
		}
	}
	if !sawFailure {
		t.Fatalf("target failure event missing: %#v", recorder.snapshot())
	}
	time.Sleep(70 * time.Millisecond)
	for _, event := range recorder.snapshot() {
		if event.Stage == "target_io_blocked" {
			t.Fatalf("promptly cancelled command emitted a blocked-target escalation: %#v", recorder.snapshot())
		}
	}
}

func TestRunWIMApplyReportsCommandErrorDetail(t *testing.T) {
	executable := executableScript(t, `
printf 'controller write failed\n' >&2
exit 7
`)
	err := runWIMApply(
		context.Background(), executable, []string{"apply", "/tmp/test.wim", "1", "/dev/test"},
		"Applying Windows image…", 1000, nil, 10*time.Millisecond, 50*time.Millisecond, nil,
	)
	if err == nil || !strings.Contains(err.Error(), "controller write failed") {
		t.Fatalf("err=%v", err)
	}
}

func TestEmitBlockedTargetEscalation(t *testing.T) {
	done := make(chan struct{})
	var events []Event
	emitBlockedTargetEscalation(done, 5*time.Millisecond, func(event Event) {
		events = append(events, event)
	})
	if len(events) != 1 || events[0].Stage != "target_io_blocked" ||
		!strings.Contains(events[0].Message, "Disconnect only the selected failed target") {
		t.Fatalf("unexpected escalation events: %#v", events)
	}

	finished := make(chan struct{})
	close(finished)
	called := false
	emitBlockedTargetEscalation(finished, time.Second, func(Event) { called = true })
	if called {
		t.Fatal("completed apply emitted a blocked-target escalation")
	}
}
