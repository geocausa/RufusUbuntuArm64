//go:build linux

package linuxmedia

import (
	"strings"
	"testing"

	"github.com/geocausa/RufusArm64/internal/uefintfs"
)

func TestPlanExtractedMediaAutomaticFAT32(t *testing.T) {
	manifest := testExtractedFilesystemManifest(Entry{Path: "casper/initrd", Size: 16 * 1024 * 1024, SHA256: strings.Repeat("a", 64)})
	plan, err := PlanExtractedMedia(manifest, "auto", "gpt", "ubuntu", 4096, 8*1024*1024*1024, 512)
	if err != nil {
		t.Fatal(err)
	}
	if plan.FilesystemSelection.Selected != ExtractedFilesystemFAT32 || plan.PartitionScheme != "gpt" {
		t.Fatalf("plan selection = %+v", plan)
	}
	if plan.VolumeLabel != "UBUNTU" || plan.ClusterSize != 4096 {
		t.Fatalf("label/cluster = %q/%d", plan.VolumeLabel, plan.ClusterSize)
	}
	if plan.Data.Number != 1 || plan.Boot != nil || plan.UEFINTFSImageSHA256 != "" {
		t.Fatalf("unexpected FAT32 layout evidence = %+v", plan)
	}
	if plan.RequiredDataBytes <= manifest.TotalBytes {
		t.Fatalf("required bytes = %d, total = %d", plan.RequiredDataBytes, manifest.TotalBytes)
	}
}

func TestPlanExtractedMediaAutomaticNTFSBindsUEFINTFSEvidence(t *testing.T) {
	manifest := testExtractedFilesystemManifest(Entry{Path: "images/rootfs.img", Size: fat32MaxFileSize + 1, SHA256: strings.Repeat("b", 64)})
	for _, scheme := range []string{"mbr", "gpt"} {
		plan, err := PlanExtractedMedia(manifest, "auto", scheme, "Linux_日本", 8192, 8*1024*1024*1024, 512)
		if err != nil {
			t.Fatalf("PlanExtractedMedia(%s): %v", scheme, err)
		}
		if plan.FilesystemSelection.Selected != ExtractedFilesystemNTFS || !strings.Contains(plan.FilesystemSelection.FAT32Refusal, "single-file limit") {
			t.Fatalf("%s selection = %+v", scheme, plan.FilesystemSelection)
		}
		if plan.VolumeLabel != "Linux_日本" || plan.ClusterSize != 8192 {
			t.Fatalf("%s label/cluster = %q/%d", scheme, plan.VolumeLabel, plan.ClusterSize)
		}
		if plan.Data.Number != 1 || plan.Boot == nil || plan.Boot.Number != 2 {
			t.Fatalf("%s partition evidence = %+v", scheme, plan)
		}
		if plan.Boot.SizeBytes != uefintfs.ImageSize || plan.UEFINTFSImageSize != uefintfs.ImageSize || plan.UEFINTFSImageSHA256 != uefintfs.ImageSHA256 {
			t.Fatalf("%s UEFI:NTFS evidence = %+v", scheme, plan)
		}
		shared, err := uefintfs.PlanLayout(scheme, plan.TargetSize, plan.SectorSize)
		if err != nil {
			t.Fatal(err)
		}
		if plan.Data.StartBytes != shared.Data.StartBytes || plan.Data.SizeBytes != shared.Data.SizeBytes || plan.Boot.StartBytes != shared.Boot.StartBytes {
			t.Fatalf("%s plan diverges from shared layout: plan=%+v shared=%+v", scheme, plan, shared)
		}
	}
}

func TestPlanExtractedMediaExplicitChoicesFailClosed(t *testing.T) {
	large := testExtractedFilesystemManifest(Entry{Path: "images/rootfs.img", Size: fat32MaxFileSize + 1, SHA256: strings.Repeat("c", 64)})
	if _, err := PlanExtractedMedia(large, "fat32", "gpt", "LINUX", 4096, 8*1024*1024*1024, 512); err == nil || !strings.Contains(err.Error(), "FAT32 is incompatible") {
		t.Fatalf("explicit FAT32 error = %v", err)
	}

	ordinary := testExtractedFilesystemManifest(Entry{Path: "casper/initrd", Size: 1024, SHA256: strings.Repeat("d", 64)})
	if _, err := PlanExtractedMedia(ordinary, "ntfs", "gpt", strings.Repeat("x", 33), 4096, 8*1024*1024*1024, 512); err == nil || !strings.Contains(err.Error(), "32 UTF-16") {
		t.Fatalf("NTFS label error = %v", err)
	}
	if _, err := PlanExtractedMedia(ordinary, "ntfs", "gpt", strings.Repeat("😀", 17), 4096, 8*1024*1024*1024, 512); err == nil || !strings.Contains(err.Error(), "32 UTF-16") {
		t.Fatalf("NTFS surrogate-pair label error = %v", err)
	}
	if _, err := PlanExtractedMedia(ordinary, "ntfs", "gpt", "LINUX", 65536, 8*1024*1024*1024, 512); err == nil || !strings.Contains(err.Error(), "4096, 8192, 16384, or 32768") {
		t.Fatalf("NTFS cluster error = %v", err)
	}
}

func TestPlanExtractedMediaRefusesInsufficientNTFSDataSpace(t *testing.T) {
	manifest := testExtractedFilesystemManifest(Entry{Path: "payload.bin", Size: 100 * 1024 * 1024, SHA256: strings.Repeat("e", 64)})
	if _, err := PlanExtractedMedia(manifest, "ntfs", "gpt", "LINUX", 4096, minimumExtractedDiskSize, 512); err == nil || !strings.Contains(err.Error(), "verified media tree needs") {
		t.Fatalf("capacity error = %v", err)
	}
}

func TestEstimateExtractedNTFSBytesIncludesMarginAndEntries(t *testing.T) {
	manifest := testExtractedFilesystemManifest(
		Entry{Path: "one", Size: 10, SHA256: strings.Repeat("f", 64)},
		Entry{Path: "two", Size: 20, SHA256: strings.Repeat("1", 64)},
	)
	required, err := estimateExtractedNTFSBytes(manifest)
	if err != nil {
		t.Fatal(err)
	}
	want := manifest.TotalBytes + 64*1024*1024 + uint64(len(manifest.Entries))*4096
	if required != want {
		t.Fatalf("required = %d, want %d", required, want)
	}
}
