//go:build linux

package linuxmedia

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMergeManifestOverlayAddsFallbackAcrossApprovedRoots(t *testing.T) {
	baseRoot := t.TempDir()
	overlayRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(baseRoot, "kernel"), []byte("linux"), 0o644); err != nil {
		t.Fatal(err)
	}
	boot := filepath.Join(overlayRoot, "EFI", "BOOT")
	if err := os.MkdirAll(boot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(boot, "BOOTAA64.EFI"), []byte("arm64-efi"), 0o644); err != nil {
		t.Fatal(err)
	}
	base, err := Inspect(context.Background(), baseRoot, Options{Architecture: "arm64"})
	if err != nil {
		t.Fatal(err)
	}
	overlay, err := Inspect(context.Background(), overlayRoot, Options{Architecture: "arm64", RequireUEFI: true})
	if err != nil {
		t.Fatal(err)
	}
	merged, err := MergeManifestOverlay(base, overlay, Options{Architecture: "arm64", RequireUEFI: true, RequireFAT32: true})
	if err != nil {
		t.Fatal(err)
	}
	if merged.UEFIBootPath != "EFI/BOOT/BOOTAA64.EFI" || len(merged.SourceRoots) != 2 || merged.Files != 2 {
		t.Fatalf("unexpected merged manifest: %#v", merged)
	}
	destination := t.TempDir()
	if err := CopyAndVerify(context.Background(), merged, destination, CopyOptions{}); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(destination, "EFI", "BOOT", "BOOTAA64.EFI")); err != nil || string(data) != "arm64-efi" {
		t.Fatalf("copied fallback=%q err=%v", data, err)
	}
}

func TestMergeManifestOverlayRejectsConflicts(t *testing.T) {
	for name, paths := range map[string][2]string{
		"exact conflict": {"EFI/BOOT/BOOTAA64.EFI", "EFI/BOOT/BOOTAA64.EFI"},
		"case conflict":  {"EFI/BOOT/BOOTAA64.EFI", "efi/boot/bootaa64.efi"},
	} {
		t.Run(name, func(t *testing.T) {
			baseRoot := t.TempDir()
			overlayRoot := t.TempDir()
			for index, item := range []struct{ root, path, data string }{{baseRoot, paths[0], "base"}, {overlayRoot, paths[1], "overlay"}} {
				_ = index
				full := filepath.Join(item.root, filepath.FromSlash(item.path))
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, []byte(item.data), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			base, err := Inspect(context.Background(), baseRoot, Options{Architecture: "arm64"})
			if err != nil {
				t.Fatal(err)
			}
			overlay, err := Inspect(context.Background(), overlayRoot, Options{Architecture: "arm64"})
			if err != nil {
				t.Fatal(err)
			}
			_, err = MergeManifestOverlay(base, overlay, Options{Architecture: "arm64"})
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), "collision") && !strings.Contains(strings.ToLower(err.Error()), "conflict") {
				t.Fatalf("conflict error=%v", err)
			}
		})
	}
}

func TestMergeManifestOverlayRequiresDistinctRoots(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "one"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	base, err := Inspect(context.Background(), root, Options{Architecture: "arm64"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MergeManifestOverlay(base, base, Options{Architecture: "arm64"}); err == nil || !strings.Contains(err.Error(), "distinct") {
		t.Fatalf("same-root overlay error=%v", err)
	}
}

func TestCopyRejectsEntryOutsideEveryApprovedRoot(t *testing.T) {
	root := t.TempDir()
	other := t.TempDir()
	destination := t.TempDir()
	path := filepath.Join(other, "file")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{SourceRoot: root, SourceRoots: []string{root}, Architecture: "arm64", Files: 1, TotalBytes: 1,
		Entries: []Entry{{Path: "file", SourcePath: path, Size: 1, SHA256: strings.Repeat("0", 64)}}}
	if err := CopyAndVerify(context.Background(), manifest, destination, CopyOptions{}); err == nil || !strings.Contains(err.Error(), "approved source roots") {
		t.Fatalf("outside-root error=%v", err)
	}
}
