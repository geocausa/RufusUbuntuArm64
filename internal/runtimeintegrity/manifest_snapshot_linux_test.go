//go:build linux

package runtimeintegrity

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func writeRuntimeManifest(t *testing.T, root string) string {
	t.Helper()
	writeFile(t, root, "payload", "data")
	manifest, err := Generate(context.Background(), root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	data, err := manifest.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, ManifestName)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVerifyRejectsManifestChangedAfterEnumeration(t *testing.T) {
	root := t.TempDir()
	manifestPath := writeRuntimeManifest(t, root)
	changed := false
	_, err := verify(context.Background(), root, Options{}, func(stage, relative string) {
		if stage != "manifest-before-open" || relative != ManifestName || changed {
			return
		}
		changed = true
		if writeErr := os.WriteFile(manifestPath, []byte("tampered manifest\n"), 0o644); writeErr != nil {
			t.Fatal(writeErr)
		}
	})
	if err == nil || !strings.Contains(err.Error(), "changed between enumeration") {
		t.Fatalf("manifest mutation error = %v", err)
	}
}

func TestVerifyRejectsManifestFIFOReplacementWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	manifestPath := writeRuntimeManifest(t, root)
	done := make(chan error, 1)
	go func() {
		var setupErr error
		_, err := verify(context.Background(), root, Options{}, func(stage, relative string) {
			if stage != "manifest-before-open" || relative != ManifestName || setupErr != nil {
				return
			}
			if removeErr := os.Remove(manifestPath); removeErr != nil {
				setupErr = removeErr
				return
			}
			setupErr = syscall.Mkfifo(manifestPath, 0o600)
		})
		if setupErr != nil {
			done <- setupErr
			return
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || (!strings.Contains(err.Error(), "changed between enumeration") && !strings.Contains(err.Error(), "regular file")) {
			t.Fatalf("manifest FIFO error = %v", err)
		}
	case <-time.After(time.Second):
		writer, err := os.OpenFile(manifestPath, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			_ = writer.Close()
		}
		select {
		case <-done:
		case <-time.After(time.Second):
		}
		t.Fatal("opening a FIFO runtime manifest blocked")
	}
}
