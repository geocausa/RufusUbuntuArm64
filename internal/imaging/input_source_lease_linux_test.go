//go:build linux

package imaging

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

func TestPrepareInputFallsBackWithExistingContainerWriter(t *testing.T) {
	raw := testRawImage()
	path := filepath.Join(t.TempDir(), "disk.img.gz")
	writeGZIP(t, path, raw)
	resolved, identity := inspectIdentity(t, path)
	writer, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	var events []PrepareProgress
	prepared, err := PrepareInput(context.Background(), resolved, identity, func(progress PrepareProgress) {
		events = append(events, progress)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	if !prepareMessagesContain(events, "conservative pre/post") {
		t.Fatalf("fallback message missing: %#v", events)
	}
}

func TestPrepareInputLeaseBreakCancelsAndRemovesPrivateOutput(t *testing.T) {
	raw := make([]byte, 16*1024*1024+123)
	for index := range raw {
		raw[index] = byte((index*13 + 7) % 251)
	}
	path := filepath.Join(t.TempDir(), "disk.img.gz")
	writeGZIP(t, path, raw)
	resolved, identity := inspectIdentity(t, path)
	before, err := filepath.Glob("/var/tmp/.rufusarm64-input-*")
	if err != nil {
		t.Fatal(err)
	}
	known := make(map[string]struct{}, len(before))
	for _, entry := range before {
		known[entry] = struct{}{}
	}

	var once sync.Once
	var triggerErr error
	writerDone := make(chan error, 1)
	prepared, err := PrepareInput(context.Background(), resolved, identity, func(progress PrepareProgress) {
		if progress.Stage != "prepare" || progress.Done == 0 {
			return
		}
		once.Do(func() {
			probe, openErr := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0)
			if probe != nil {
				_ = probe.Close()
			}
			triggerErr = openErr
			go func() {
				writer, writerErr := os.OpenFile(path, os.O_WRONLY, 0)
				if writer != nil {
					_ = writer.Close()
				}
				writerDone <- writerErr
			}()
		})
	})
	if prepared != nil {
		_ = prepared.Close()
		t.Fatal("lease-broken preparation returned a prepared image")
	}
	if !errors.Is(triggerErr, syscall.EAGAIN) {
		t.Fatalf("conflicting writer trigger error=%v", triggerErr)
	}
	if !errors.Is(err, sourcefile.ErrReadLeaseBroken) || !strings.Contains(err.Error(), "no USB data was changed") {
		t.Fatalf("lease-break preparation error=%v", err)
	}
	select {
	case writerErr := <-writerDone:
		if writerErr != nil {
			t.Fatalf("blocked writer after cleanup=%v", writerErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("blocked container writer was not released")
	}
	after, err := filepath.Glob("/var/tmp/.rufusarm64-input-*")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range after {
		if _, existed := known[entry]; !existed {
			t.Fatalf("lease-broken preparation left private output %s", entry)
		}
	}
}

func prepareMessagesContain(events []PrepareProgress, wanted string) bool {
	for _, event := range events {
		if strings.Contains(event.Message, wanted) {
			return true
		}
	}
	return false
}
