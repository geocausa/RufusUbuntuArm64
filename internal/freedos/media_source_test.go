package freedos

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type mediaGeometryPin struct {
	Schema     int    `json:"schema"`
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	Source     struct {
		Path        string `json:"path"`
		GitBlobSHA1 string `json:"git_blob_sha1"`
	} `json:"source"`
	InitialScope struct {
		LogicalSectorSize    uint16 `json:"logical_sector_size"`
		PartitionStartSector uint32 `json:"partition_start_sector"`
		ReservedTailSectors  uint32 `json:"reserved_tail_sectors"`
		PartitionType        string `json:"partition_type"`
		ActivePartition      bool   `json:"active_partition"`
		SectorsPerTrack      uint16 `json:"sectors_per_track"`
		Heads                uint16 `json:"heads"`
	} `json:"initial_scope"`
	FAT32 struct {
		BaseReservedSectors          uint32 `json:"base_reserved_sectors"`
		FATCount                     uint32 `json:"fat_count"`
		BackupBootSector             uint32 `json:"backup_boot_sector"`
		FSInfoSector                 uint32 `json:"fsinfo_sector"`
		RootCluster                  uint32 `json:"root_cluster"`
		DataAlignmentSectors         uint32 `json:"data_alignment_sectors"`
		MinimumClusterCount          uint32 `json:"minimum_cluster_count"`
		MaximumClusterCount          uint32 `json:"maximum_cluster_count"`
		MaximumTotalSectorsExclusive uint64 `json:"maximum_total_sectors_exclusive"`
		MediaDescriptor              byte   `json:"media_descriptor"`
		ClusterSizes                 []struct {
			PartitionBytesBelow uint64 `json:"partition_bytes_below"`
			Bytes               uint64 `json:"bytes"`
		} `json:"cluster_size_bytes"`
	} `json:"fat32"`
}

func TestPinnedRufusFAT32GeometrySource(t *testing.T) {
	path := filepath.Join("..", "..", "vendor", "rufus", "FREEDOS-FAT32-GEOMETRY.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read FAT32 geometry pin: %v", err)
	}
	var pin mediaGeometryPin
	if err := json.Unmarshal(data, &pin); err != nil {
		t.Fatalf("decode FAT32 geometry pin: %v", err)
	}
	if pin.Schema != 1 || pin.Repository != "https://github.com/pbatard/rufus" {
		t.Fatalf("unexpected geometry source envelope: %+v", pin)
	}
	if pin.Commit != PinnedManifest().RufusReferenceCommit {
		t.Fatalf("geometry source commit %s does not match the feasibility manifest", pin.Commit)
	}
	if pin.Source.Path != "src/format_fat32.c" || pin.Source.GitBlobSHA1 != "fa75f16eecb194f0854eacd1ab4e76d0ae7aa602" || !validHex(pin.Source.GitBlobSHA1, 40) {
		t.Fatalf("unexpected Rufus FAT32 source pin: %+v", pin.Source)
	}
	scope := pin.InitialScope
	if scope.LogicalSectorSize != freeDOSLogicalSectorSize ||
		scope.PartitionStartSector != freeDOSPartitionStartSector ||
		scope.ReservedTailSectors != freeDOSReservedTailSectors ||
		scope.PartitionType != "0x0c" || !scope.ActivePartition ||
		scope.SectorsPerTrack != 63 || scope.Heads != 255 {
		t.Fatalf("pinned initial geometry differs from code: %+v", scope)
	}
	fat := pin.FAT32
	if fat.BaseReservedSectors != 32 || fat.FATCount != freeDOSFATCount ||
		fat.BackupBootSector != fat32BackupSector || fat.FSInfoSector != freeDOSFSInfoSector ||
		fat.RootCluster != freeDOSRootCluster || fat.DataAlignmentSectors != freeDOSDataAlignmentSectors ||
		fat.MinimumClusterCount != freeDOSMinimumClusterCount || fat.MaximumClusterCount != freeDOSMaximumClusterCount ||
		fat.MaximumTotalSectorsExclusive != 0xffffffff || fat.MediaDescriptor != 0xf8 {
		t.Fatalf("pinned FAT32 geometry differs from code: %+v", fat)
	}
	if len(fat.ClusterSizes) != 7 {
		t.Fatalf("unexpected cluster-size table length: %d", len(fat.ClusterSizes))
	}
	for _, entry := range fat.ClusterSizes {
		got, err := defaultFreeDOSClusterBytes(entry.PartitionBytesBelow - 1)
		if err != nil {
			t.Fatalf("cluster size below %d: %v", entry.PartitionBytesBelow, err)
		}
		if got != entry.Bytes {
			t.Fatalf("cluster size below %d = %d; want %d", entry.PartitionBytesBelow, got, entry.Bytes)
		}
	}
}
