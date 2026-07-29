package main

import (
	"strings"
	"testing"

	"github.com/geocausa/RufusArm64/internal/imaging"
)

func TestSelectWriteModeRefusesBareSquashFSWithoutForce(t *testing.T) {
	inspection := imaging.ImageInfo{HasSquashFS: true}
	if _, err := selectWriteMode("auto", inspection, false); err == nil || !strings.Contains(err.Error(), "recognized SquashFS") {
		t.Fatalf("bare SquashFS automatic mode was not refused clearly: %v", err)
	}
}

func TestSelectWriteModeAllowsDeliberateForcedSquashFSCopy(t *testing.T) {
	inspection := imaging.ImageInfo{HasSquashFS: true}
	mode, err := selectWriteMode("auto", inspection, true)
	if err != nil {
		t.Fatal(err)
	}
	if mode != "raw" {
		t.Fatalf("forced SquashFS mode=%q, want raw", mode)
	}
}

func TestSelectWriteModeKeepsSquashFSBackedDiskImageRaw(t *testing.T) {
	inspection := imaging.ImageInfo{HasSquashFS: true, HasMBR: true, HasMBRPartition: true}
	mode, err := selectWriteMode("auto", inspection, false)
	if err != nil {
		t.Fatal(err)
	}
	if mode != "raw" {
		t.Fatalf("SquashFS-backed disk mode=%q, want raw", mode)
	}
}
