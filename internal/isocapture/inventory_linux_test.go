//go:build linux

package isocapture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func TestScanBuildsDeterministicContentInventory(t *testing.T) {
	firstRoot := buildInventoryFixture(t)
	secondRoot := buildInventoryFixture(t)

	first := scanDirectoryPath(t, context.Background(), firstRoot, Limits{})
	second := scanDirectoryPath(t, context.Background(), secondRoot, Limits{})

	if first.Schema != InventorySchema || first.Profile != ProfileISO9660JolietUDF {
		t.Fatalf("unexpected inventory header: %+v", first)
	}
	if first.Files != 2 || first.Directories != 2 || first.TotalBytes != uint64(len("arm64-efi")+len("readme")) {
		t.Fatalf("unexpected inventory totals: %+v", first)
	}
	wantPaths := []string{"EFI", "EFI/BOOT", "EFI/BOOT/BOOTAA64.EFI", "README.TXT"}
	gotPaths := make([]string, 0, len(first.Entries))
	for _, entry := range first.Entries {
		gotPaths = append(gotPaths, entry.Path)
	}
	if !reflect.DeepEqual(gotPaths, wantPaths) {
		t.Fatalf("paths = %#v, want %#v", gotPaths, wantPaths)
	}
	wantEFI := sha256.Sum256([]byte("arm64-efi"))
	wantReadme := sha256.Sum256([]byte("readme"))
	if first.Entries[2].SHA256 != hex.EncodeToString(wantEFI[:]) || first.Entries[3].SHA256 != hex.EncodeToString(wantReadme[:]) {
		t.Fatalf("unexpected file digests: %+v", first.Entries)
	}
	if len(first.BindingSHA256) != 64 || len(first.ContentSHA256) != 64 {
		t.Fatalf("incomplete inventory digests: %+v", first)
	}
	if first.ContentSHA256 != second.ContentSHA256 {
		t.Fatalf("content digest changed across equivalent trees: %s != %s", first.ContentSHA256, second.ContentSHA256)
	}
	if first.BindingSHA256 == second.BindingSHA256 {
		t.Fatal("binding digest did not distinguish separate source roots")
	}

	if err := os.WriteFile(filepath.Join(secondRoot, "README.TXT"), []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	changed := scanDirectoryPath(t, context.Background(), secondRoot, Limits{})
	if changed.ContentSHA256 == first.ContentSHA256 {
		t.Fatal("content digest did not change after source content changed")
	}
}

func TestScanRejectsUnsupportedSourceObjects(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		root := t.TempDir()
		if err := os.Symlink("target", filepath.Join(root, "LINK")); err != nil {
			t.Fatal(err)
		}
		requireScanError(t, root, Limits{}, "symbolic link")
	})

	t.Run("hard-link", func(t *testing.T) {
		root := t.TempDir()
		first := filepath.Join(root, "FIRST")
		if err := os.WriteFile(first, []byte("data"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(first, filepath.Join(root, "SECOND")); err != nil {
			t.Fatal(err)
		}
		requireScanError(t, root, Limits{}, "hard links")
	})

	t.Run("fifo", func(t *testing.T) {
		root := t.TempDir()
		if err := syscall.Mkfifo(filepath.Join(root, "PIPE"), 0o600); err != nil {
			t.Fatal(err)
		}
		requireScanError(t, root, Limits{}, "unsupported file type")
	})

	t.Run("case-collision", func(t *testing.T) {
		root := t.TempDir()
		for _, name := range []string{"README", "readme"} {
			if err := os.WriteFile(filepath.Join(root, name), []byte(name), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		requireScanError(t, root, Limits{}, "collide case-insensitively")
	})

	for _, name := range []string{".HIDDEN", "TRAILING.", "HAS SPACE", "UNICODE-É"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, name), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
			requireScanError(t, root, Limits{}, "path component")
		})
	}
}

func TestScanEnforcesReviewedLimits(t *testing.T) {
	t.Run("entries", func(t *testing.T) {
		root := t.TempDir()
		for _, name := range []string{"A", "B"} {
			if err := os.WriteFile(filepath.Join(root, name), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		requireScanError(t, root, Limits{MaxEntries: 1}, "maximum entries")
	})

	t.Run("depth", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "A", "B"), 0o755); err != nil {
			t.Fatal(err)
		}
		requireScanError(t, root, Limits{MaxDepth: 1}, "maximum depth")
	})

	t.Run("component", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "LONG"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		requireScanError(t, root, Limits{MaxComponentBytes: 3}, "valid UTF-8")
	})

	t.Run("path-length", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "AB", "CD"), 0o755); err != nil {
			t.Fatal(err)
		}
		requireScanError(t, root, Limits{MaxPathLength: 4}, "maximum length")
	})

	t.Run("aggregate-path-bytes", func(t *testing.T) {
		root := t.TempDir()
		for _, name := range []string{"AAA", "BBB"} {
			if err := os.WriteFile(filepath.Join(root, name), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		requireScanError(t, root, Limits{MaxPathBytes: 5}, "aggregate bytes")
	})

	t.Run("file-bytes", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "FILE"), []byte("1234"), 0o644); err != nil {
			t.Fatal(err)
		}
		requireScanError(t, root, Limits{MaxFileBytes: 3}, "size 4 exceeds")
	})

	t.Run("total-bytes", func(t *testing.T) {
		root := t.TempDir()
		for _, name := range []string{"A", "B"} {
			if err := os.WriteFile(filepath.Join(root, name), []byte("12"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		requireScanError(t, root, Limits{MaxTotalBytes: 3}, "maximum total bytes")
	})
}

func TestScanRejectsInvalidRootAndCancellation(t *testing.T) {
	if _, err := Scan(context.Background(), nil, Limits{}); err == nil || !strings.Contains(err.Error(), "requires an open root") {
		t.Fatalf("nil root error = %v", err)
	}

	filePath := filepath.Join(t.TempDir(), "FILE")
	if err := os.WriteFile(filePath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(filePath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := Scan(context.Background(), file, Limits{}); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("file root error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	root, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := Scan(ctx, root, Limits{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled scan error = %v", err)
	}
}

func TestNormalizeLimitsRejectsNegativeValues(t *testing.T) {
	if _, err := normalizeLimits(Limits{MaxEntries: -1}); err == nil || !strings.Contains(err.Error(), "positive") {
		t.Fatalf("negative limit error = %v", err)
	}
}

func buildInventoryFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "EFI", "BOOT"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "EFI", "BOOT", "BOOTAA64.EFI"), []byte("arm64-efi"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "README.TXT"), []byte("readme"), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func scanDirectoryPath(t *testing.T, ctx context.Context, path string, limits Limits) Inventory {
	t.Helper()
	root, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	inventory, err := Scan(ctx, root, limits)
	if err != nil {
		t.Fatal(err)
	}
	return inventory
}

func requireScanError(t *testing.T, path string, limits Limits, want string) {
	t.Helper()
	root, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	_, err = Scan(context.Background(), root, limits)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("scan error = %v, want text %q", err, want)
	}
}
