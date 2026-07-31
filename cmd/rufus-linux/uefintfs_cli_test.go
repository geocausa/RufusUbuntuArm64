package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/geocausa/RufusArm64/internal/uefintfs"
)

func TestRunUEFINTFSInspectPublishesPinnedArchitectureReport(t *testing.T) {
	path := filepath.Join("..", "..", "vendor", "uefi-ntfs", "uefi-ntfs.img")
	output, err := captureStdout(t, func() error {
		return runUEFINTFS([]string{"inspect", "--image", path, "--json"})
	})
	if err != nil {
		t.Fatal(err)
	}
	var report uefintfs.ArchitectureReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatal(err)
	}
	if report.Schema != 1 || report.ImageSHA256 != uefintfs.ImageSHA256 || len(report.Architectures) != 5 {
		t.Fatalf("unexpected report: %#v", report)
	}
	if report.Architectures[3].Name != "riscv64" || report.Architectures[3].Fallback.Machine != 0x5064 {
		t.Fatalf("missing RISC-V64 evidence: %#v", report.Architectures)
	}
}

func TestRunUEFINTFSInspectRejectsUnsafeArgumentsAndModifiedImage(t *testing.T) {
	if err := runUEFINTFS(nil); err == nil {
		t.Fatal("missing subcommand accepted")
	}
	if err := runUEFINTFS([]string{"inspect", "unexpected"}); err == nil {
		t.Fatal("positional argument accepted")
	}
	path := filepath.Join(t.TempDir(), "modified.img")
	if err := os.WriteFile(path, make([]byte, uefintfs.ImageSize), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runUEFINTFS([]string{"inspect", "--image", path, "--json"}); err == nil {
		t.Fatal("modified UEFI:NTFS image accepted")
	}
}
