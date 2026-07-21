//go:build linux

package secureboot

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testUEFITraversalLimits(maxFiles, maxEntries, maxDepth int, maxTotalBytes int64) *uefiTraversalLimits {
	return &uefiTraversalLimits{
		maxFiles:      maxFiles,
		maxEntries:    maxEntries,
		maxDepth:      maxDepth,
		maxTotalBytes: maxTotalBytes,
	}
}

func TestUEFITraversalAcceptsExactEntryDepthAndByteLimits(t *testing.T) {
	root := t.TempDir()
	data := syntheticUEFIPE(imageFileMachineARM64, imageSubsystemEFIApp)
	writeSyntheticEFI(t, root, "EFI/BOOT/BOOTAA64.EFI", data)
	limits := testUEFITraversalLimits(1, 3, 2, int64(len(data)))

	resolved, files, warnings, err := openUEFIMediaTreeWithLimits(context.Background(), root, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resolved == "" || len(files) != 1 || files[0].relative != "EFI/BOOT/BOOTAA64.EFI" || len(warnings) != 0 {
		t.Fatalf("unexpected bounded traversal result: resolved=%q files=%#v warnings=%#v", resolved, files, warnings)
	}
	if limits.entries != 3 || limits.totalBytes != int64(len(data)) {
		t.Fatalf("unexpected traversal accounting: %#v", limits)
	}
}

func TestUEFITraversalBoundsAllEntriesNotOnlyExecutables(t *testing.T) {
	root := t.TempDir()
	for index := 0; index < 4; index++ {
		path := filepath.Join(root, fmt.Sprintf("unrelated-%02d.txt", index))
		if err := os.WriteFile(path, []byte("not an EFI executable"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_, _, _, err := openUEFIMediaTreeWithLimits(
		context.Background(),
		root,
		testUEFITraversalLimits(4, 3, 4, 4096),
		nil,
	)
	if err == nil || !strings.Contains(err.Error(), "more than 3 total entries") {
		t.Fatalf("unrelated-entry bound was not enforced: %v", err)
	}
}

func TestUEFITraversalReadsMoreThanOneBoundedDirectoryBatch(t *testing.T) {
	root := t.TempDir()
	for index := 0; index < uefiDirectoryReadBatch+1; index++ {
		path := filepath.Join(root, fmt.Sprintf("entry-%04d.txt", index))
		if err := os.WriteFile(path, []byte("bounded"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	limits := testUEFITraversalLimits(4, uefiDirectoryReadBatch+1, 4, 4096)
	_, files, _, err := openUEFIMediaTreeWithLimits(context.Background(), root, limits, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 || limits.entries != uefiDirectoryReadBatch+1 {
		t.Fatalf("bounded batches were not fully accounted: files=%d limits=%#v", len(files), limits)
	}
}

func TestUEFITraversalBoundsDirectoryDepth(t *testing.T) {
	root := t.TempDir()
	deep := filepath.Join(root, "one", "two", "three")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := openUEFIMediaTreeWithLimits(
		context.Background(),
		root,
		testUEFITraversalLimits(4, 8, 2, 4096),
		nil,
	)
	if err == nil || !strings.Contains(err.Error(), "2-level directory-depth") || !strings.Contains(err.Error(), "one/two/three") {
		t.Fatalf("directory-depth bound was not enforced: %v", err)
	}
}

func TestUEFITraversalBoundsAggregateExecutableBytesBeforeRead(t *testing.T) {
	root := t.TempDir()
	first := syntheticUEFIPE(imageFileMachineARM64, imageSubsystemEFIApp, syntheticUEFISection{name: ".text", data: []byte("first")})
	second := syntheticUEFIPE(imageFileMachineARM64, imageSubsystemEFIApp, syntheticUEFISection{name: ".text", data: []byte("second")})
	writeSyntheticEFI(t, root, "EFI/BOOT/BOOTAA64.EFI", first)
	writeSyntheticEFI(t, root, "EFI/tools/second.efi", second)
	limit := int64(len(first) + len(second) - 1)

	_, _, _, err := openUEFIMediaTreeWithLimits(
		context.Background(),
		root,
		testUEFITraversalLimits(2, 5, 2, limit),
		nil,
	)
	if err == nil || !strings.Contains(err.Error(), "aggregate safety limit") || !strings.Contains(err.Error(), "second.efi") {
		t.Fatalf("aggregate executable-byte bound was not enforced: %v", err)
	}
}

func TestUEFITraversalRejectsLimitsAboveProductionSafetyMaxima(t *testing.T) {
	tests := []struct {
		name   string
		limits *uefiTraversalLimits
		want   string
	}{
		{
			name:   "files",
			limits: testUEFITraversalLimits(maximumUEFIMaxFiles+1, 1, 1, 1),
			want:   "executable limit",
		},
		{
			name:   "entries",
			limits: testUEFITraversalLimits(1, defaultUEFIMaxEntries+1, 1, 1),
			want:   "total-entry limit",
		},
		{
			name:   "depth",
			limits: testUEFITraversalLimits(1, 1, defaultUEFIMaxDepth+1, 1),
			want:   "directory-depth limit",
		},
		{
			name:   "bytes",
			limits: testUEFITraversalLimits(1, 1, 1, defaultUEFIMaxTotalBytes+1),
			want:   "aggregate-byte limit",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, _, err := openUEFIMediaTreeWithLimits(context.Background(), t.TempDir(), test.limits, nil)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("excessive %s was not rejected: %v", test.name, err)
			}
		})
	}
}

func TestUEFITraversalRejectsReusedAccountingState(t *testing.T) {
	limits := testUEFITraversalLimits(1, 1, 1, 1)
	limits.entries = 1
	_, _, _, err := openUEFIMediaTreeWithLimits(context.Background(), t.TempDir(), limits, nil)
	if err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("reused traversal state was not rejected: %v", err)
	}
}
