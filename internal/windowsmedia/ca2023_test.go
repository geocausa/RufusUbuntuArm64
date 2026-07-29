//go:build linux

package windowsmedia

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geocausa/RufusArm64/internal/windowsconfig"
)

func TestInspectWindowsCA2023CapabilityPrefersSetupIndexTwo(t *testing.T) {
	originalMetadata := inspectWindowsCA2023Metadata
	originalPath := inspectWindowsCA2023WIMPath
	originalWIM := windowsCA2023WIMExecutable
	inspectWindowsCA2023Metadata = func(context.Context, string) (windowsconfig.MediaMetadata, error) {
		return windowsconfig.MediaMetadata{ImageCount: 2}, nil
	}
	windowsCA2023WIMExecutable = func() (string, error) { return "fake-wimlib", nil }
	var indexes []int
	inspectWindowsCA2023WIMPath = func(_ context.Context, executable, image string, index int, path string) (bool, error) {
		if executable != "fake-wimlib" || image != "boot.wim" || path == "" {
			t.Fatalf("unexpected probe: %q %q %d %q", executable, image, index, path)
		}
		indexes = append(indexes, index)
		return true, nil
	}
	t.Cleanup(func() {
		inspectWindowsCA2023Metadata = originalMetadata
		inspectWindowsCA2023WIMPath = originalPath
		windowsCA2023WIMExecutable = originalWIM
	})

	capability, err := InspectWindowsCA2023Capability(context.Background(), "boot.wim")
	if err != nil {
		t.Fatal(err)
	}
	if !capability.Available || capability.ImageIndex != 2 {
		t.Fatalf("capability = %+v", capability)
	}
	for _, index := range indexes {
		if index != 2 {
			t.Fatalf("index 1 was probed after index 2 was complete: %v", indexes)
		}
	}
}

func TestInspectWindowsCA2023CapabilityFallsBackToIndexOne(t *testing.T) {
	originalMetadata := inspectWindowsCA2023Metadata
	originalPath := inspectWindowsCA2023WIMPath
	originalWIM := windowsCA2023WIMExecutable
	inspectWindowsCA2023Metadata = func(context.Context, string) (windowsconfig.MediaMetadata, error) {
		return windowsconfig.MediaMetadata{ImageCount: 2}, nil
	}
	windowsCA2023WIMExecutable = func() (string, error) { return "fake-wimlib", nil }
	inspectWindowsCA2023WIMPath = func(_ context.Context, _, _ string, index int, path string) (bool, error) {
		if index == 2 && path == windowsCA2023FontsPath {
			return false, nil
		}
		return true, nil
	}
	t.Cleanup(func() {
		inspectWindowsCA2023Metadata = originalMetadata
		inspectWindowsCA2023WIMPath = originalPath
		windowsCA2023WIMExecutable = originalWIM
	})

	capability, err := InspectWindowsCA2023Capability(context.Background(), "boot.wim")
	if err != nil {
		t.Fatal(err)
	}
	if !capability.Available || capability.ImageIndex != 1 {
		t.Fatalf("capability = %+v", capability)
	}
}

func TestStageApplyAndVerifyWindowsCA2023(t *testing.T) {
	originalExtract := extractWindowsCA2023Paths
	originalInspect := inspectWindowsCA2023PE
	extractWindowsCA2023Paths = func(_ context.Context, _ string, index int, destination string) error {
		if index != 2 {
			return errors.New("wrong image index")
		}
		writeCA2023TestFile(t, filepath.Join(destination, "Windows", "Boot", "EFI_EX", "bootmgfw_EX.efi"), "new-fallback")
		writeCA2023TestFile(t, filepath.Join(destination, "Windows", "Boot", "EFI_EX", "bootmgr_EX.efi"), "new-bootmgr")
		writeCA2023TestFile(t, filepath.Join(destination, "Windows", "Boot", "Fonts_EX", "segmono_boot.ttf"), "new-font")
		return nil
	}
	inspectWindowsCA2023PE = func(path string) (windowsCA2023PEEvidence, error) {
		return windowsCA2023PEEvidence{Machine: 0xaa64, AuthenticodeSHA256: filepath.Base(path), WindowsCA2023CertificateEvidence: true}, nil
	}
	t.Cleanup(func() {
		extractWindowsCA2023Paths = originalExtract
		inspectWindowsCA2023PE = originalInspect
	})

	isoRoot := t.TempDir()
	writeCA2023TestFile(t, filepath.Join(isoRoot, "EFI", "BOOT", "BOOTAA64.EFI"), "old-fallback")
	writeCA2023TestFile(t, filepath.Join(isoRoot, "bootmgr.efi"), "old-bootmgr")
	writeCA2023TestFile(t, filepath.Join(isoRoot, "EFI", "Microsoft", "Boot", "Fonts", "segmono_boot.ttf"), "old-font")
	plan, err := StageWindowsCA2023(context.Background(), "boot.wim", isoRoot, t.TempDir(), WindowsCA2023Capability{Available: true, ImageIndex: 2})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Architecture != "arm64" || len(plan.Assets) != 3 || plan.ManifestSHA256 == "" {
		t.Fatalf("plan = %+v", plan)
	}
	for _, relative := range []string{"efi/boot/bootaa64.efi", "BOOTMGR.EFI", "EFI/Microsoft/Boot/Fonts/segmono_boot.ttf"} {
		if !plan.Replaces(relative) {
			t.Fatalf("replacement path was not bound: %s", relative)
		}
	}

	usbRoot := t.TempDir()
	writeCA2023TestFile(t, filepath.Join(usbRoot, "EFI", "BOOT", "BOOTAA64.EFI"), "old-fallback")
	writeCA2023TestFile(t, filepath.Join(usbRoot, "bootmgr.efi"), "old-bootmgr")
	writeCA2023TestFile(t, filepath.Join(usbRoot, "EFI", "Microsoft", "Boot", "Fonts", "segmono_boot.ttf"), "old-font")
	var progressed uint64
	if err := applyWindowsCA2023(context.Background(), usbRoot, plan, func(size uint64) { progressed += size }); err != nil {
		t.Fatal(err)
	}
	if progressed != plan.ReplacementBytes {
		t.Fatalf("progress = %d, want %d", progressed, plan.ReplacementBytes)
	}
	if err := verifyWindowsCA2023(usbRoot, plan); err != nil {
		t.Fatal(err)
	}
	writeCA2023TestFile(t, filepath.Join(usbRoot, "bootmgr.efi"), "tampered")
	if err := verifyWindowsCA2023(usbRoot, plan); err == nil || !strings.Contains(err.Error(), "bootmgr.efi") {
		t.Fatalf("tamper error = %v", err)
	}
}

func TestStageWindowsCA2023RejectsNonCA2023Signer(t *testing.T) {
	originalExtract := extractWindowsCA2023Paths
	originalInspect := inspectWindowsCA2023PE
	extractWindowsCA2023Paths = func(_ context.Context, _ string, _ int, destination string) error {
		writeCA2023TestFile(t, filepath.Join(destination, "Windows", "Boot", "EFI_EX", "bootmgfw_EX.efi"), "fallback")
		writeCA2023TestFile(t, filepath.Join(destination, "Windows", "Boot", "EFI_EX", "bootmgr_EX.efi"), "bootmgr")
		writeCA2023TestFile(t, filepath.Join(destination, "Windows", "Boot", "Fonts_EX", "font.ttf"), "font")
		return nil
	}
	inspectWindowsCA2023PE = func(string) (windowsCA2023PEEvidence, error) {
		return windowsCA2023PEEvidence{Machine: 0xaa64, WindowsCA2023CertificateEvidence: false}, nil
	}
	t.Cleanup(func() {
		extractWindowsCA2023Paths = originalExtract
		inspectWindowsCA2023PE = originalInspect
	})
	isoRoot := t.TempDir()
	writeCA2023TestFile(t, filepath.Join(isoRoot, "EFI", "BOOT", "BOOTAA64.EFI"), "old")
	writeCA2023TestFile(t, filepath.Join(isoRoot, "bootmgr.efi"), "old")
	_, err := StageWindowsCA2023(context.Background(), "boot.wim", isoRoot, t.TempDir(), WindowsCA2023Capability{Available: true, ImageIndex: 2})
	if err == nil || !strings.Contains(err.Error(), "certificate-chain evidence") {
		t.Fatalf("signer error = %v", err)
	}
}

func TestPrepareCA2023DestinationRejectsSymlinkParent(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "EFI")); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareCA2023Destination(root, "EFI/BOOT/BOOTAA64.EFI"); err == nil || !strings.Contains(err.Error(), "not a real directory") {
		t.Fatalf("symlink-parent error = %v", err)
	}
}

func writeCA2023TestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
