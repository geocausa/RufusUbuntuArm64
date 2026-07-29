//go:build linux

package windowsmedia

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geocausa/RufusArm64/internal/windowsconfig"
)

func qualifiedCA2023Metadata() windowsconfig.MediaMetadata {
	return windowsconfig.MediaMetadata{
		ProductName:      "Windows 11 Pro",
		Version:          "10.0.26100",
		Architecture:     "arm64",
		InstallationType: "Client",
	}
}

func TestValidateWindowsCA2023Selection(t *testing.T) {
	capability := WindowsCA2023Capability{Available: true, ImageIndex: 2, Architecture: "arm64"}
	if err := validateWindowsCA2023Selection(qualifiedCA2023Metadata(), capability, "uefi", "fat32"); err != nil {
		t.Fatalf("qualified selection rejected: %v", err)
	}
	if err := validateWindowsCA2023Selection(qualifiedCA2023Metadata(), capability, "bios", "fat32"); err == nil || !strings.Contains(err.Error(), "UEFI") {
		t.Fatalf("expected BIOS refusal, got %v", err)
	}
	if err := validateWindowsCA2023Selection(qualifiedCA2023Metadata(), capability, "uefi", "ntfs"); err == nil || !strings.Contains(err.Error(), "UEFI:NTFS") {
		t.Fatalf("expected NTFS trust-chain refusal, got %v", err)
	}
	server := qualifiedCA2023Metadata()
	server.ProductName = "Windows Server 2025"
	server.InstallationType = "Server"
	if err := validateWindowsCA2023Selection(server, capability, "uefi", "fat32"); err == nil {
		t.Fatal("server media unexpectedly accepted")
	}
}

func TestFinalizePlanAccountsForCA2023ReplacementDelta(t *testing.T) {
	plan := mediaPlan{
		OtherBytes:  1000,
		InstallSize: 2000,
		Filesystem:  "fat32",
		CA2023: &WindowsCA2023Plan{
			OriginalBytes:    100,
			ReplacementBytes: 160,
		},
	}
	if err := finalizePlan(&plan); err != nil {
		t.Fatal(err)
	}
	if plan.CopyBytes != 3060 {
		t.Fatalf("copy bytes=%d, want 3060", plan.CopyBytes)
	}
}

func TestCopyTreeSkipsOnlyExactCA2023Destinations(t *testing.T) {
	source := t.TempDir()
	destination := t.TempDir()
	fallback := filepath.Join(source, "EFI", "BOOT", "BOOTAA64.EFI")
	normal := filepath.Join(source, "EFI", "Microsoft", "Boot", "BCD")
	for path, data := range map[string][]byte{fallback: []byte("old"), normal: []byte("keep")} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	plan := &WindowsCA2023Plan{replacements: map[string]struct{}{
		strings.ToLower(filepath.ToSlash(filepath.Join("EFI", "BOOT", "BOOTAA64.EFI"))): {},
	}}
	if err := copyTreeWithWindowsCA2023(context.Background(), source, destination, "", "", plan, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(destination, "EFI", "BOOT", "BOOTAA64.EFI")); !os.IsNotExist(err) {
		t.Fatalf("replaced fallback should be excluded, stat err=%v", err)
	}
	if data, err := os.ReadFile(filepath.Join(destination, "EFI", "Microsoft", "Boot", "BCD")); err != nil || string(data) != "keep" {
		t.Fatalf("ordinary file was not copied: data=%q err=%v", data, err)
	}
}

func TestApplyWindowsCA2023RejectsChangedStaging(t *testing.T) {
	root := t.TempDir()
	staged := filepath.Join(t.TempDir(), "bootmgfw_EX.efi")
	if err := os.WriteFile(staged, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest, err := fileSHA256(staged)
	if err != nil {
		t.Fatal(err)
	}
	plan := &WindowsCA2023Plan{Assets: []WindowsCA2023Asset{{
		Destination: filepath.ToSlash(filepath.Join("EFI", "BOOT", "BOOTAA64.EFI")),
		Size:        5,
		SHA256:      fmtDigest(digest),
		sourcePath:  staged,
	}}}
	if err := os.WriteFile(staged, []byte("later"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := applyWindowsCA2023(context.Background(), root, plan, nil); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("expected changed staging refusal, got %v", err)
	}
}

func fmtDigest(value [32]byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 64)
	for i, b := range value {
		out[i*2] = digits[b>>4]
		out[i*2+1] = digits[b&15]
	}
	return string(out)
}

func TestVerifyWindowsCA2023StagingRejectsChangedAssetBeforeErase(t *testing.T) {
	staged := filepath.Join(t.TempDir(), "bootmgfw_EX.efi")
	if err := os.WriteFile(staged, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest, err := fileSHA256(staged)
	if err != nil {
		t.Fatal(err)
	}
	plan := &WindowsCA2023Plan{Assets: []WindowsCA2023Asset{{
		Destination: "EFI/BOOT/BOOTAA64.EFI",
		Size:        5,
		SHA256:      fmtDigest(digest),
		sourcePath:  staged,
	}}}
	if err := os.WriteFile(staged, []byte("later"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyWindowsCA2023Staging(plan); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("expected final pre-erasure staging refusal, got %v", err)
	}
}

func TestVerifyWindowsCA2023RejectsSymlinkedReadbackParent(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "EFI"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "EFI", "BOOT")); err != nil {
		t.Fatal(err)
	}
	plan := &WindowsCA2023Plan{Assets: []WindowsCA2023Asset{{
		Destination: "EFI/BOOT/BOOTAA64.EFI",
		Size:        1,
		SHA256:      strings.Repeat("0", 64),
	}}}
	if err := verifyWindowsCA2023(root, plan); err == nil || !strings.Contains(err.Error(), "not a real directory") {
		t.Fatalf("expected symlinked readback-parent refusal, got %v", err)
	}
}
