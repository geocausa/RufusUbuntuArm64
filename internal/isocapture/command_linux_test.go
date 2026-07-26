//go:build linux

package isocapture

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRunProcessGroupKillsDescendantsOnCancellation(t *testing.T) {
	directory := t.TempDir()
	pidPath := filepath.Join(directory, "child.pid")
	script := filepath.Join(directory, "provider")
	if err := os.WriteFile(script, []byte(`#!/bin/sh
/bin/sleep 30 &
child=$!
printf '%s' "$child" > "$1"
wait "$child"
`), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	command := exec.Command(script, pidPath)
	done := make(chan error, 1)
	go func() { done <- runProcessGroup(ctx, command) }()

	var childPID int
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(pidPath)
		if err == nil {
			childPID, err = strconv.Atoi(strings.TrimSpace(string(data)))
			if err != nil {
				t.Fatal(err)
			}
			break
		}
		if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if childPID <= 0 {
		cancel()
		<-done
		t.Fatal("provider child PID was not recorded")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("command cancellation error = %v", err)
	}

	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		err := syscall.Kill(childPID, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		if err != nil && !errors.Is(err, syscall.EPERM) {
			t.Fatalf("probe provider child %d: %v", childPID, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("provider child %d survived process-group cancellation", childPID)
}

func TestRunProcessGroupRejectsInvalidInputs(t *testing.T) {
	//lint:ignore SA1012 This test deliberately verifies nil-context rejection.
	if err := runProcessGroup(nil, exec.Command("/bin/true")); err == nil || !strings.Contains(err.Error(), "context") {
		t.Fatalf("nil context error = %v", err)
	}
	if err := runProcessGroup(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "command") {
		t.Fatalf("nil command error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runProcessGroup(ctx, exec.Command("/bin/true")); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled command error = %v", err)
	}
}
