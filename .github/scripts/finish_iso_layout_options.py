#!/usr/bin/env python3
"""Finish and audit the ISO layout patch after the primary applicator."""

from pathlib import Path
import sys

ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path.cwd()


def replace(path: str, old: str, new: str) -> None:
    target = ROOT / path
    text = target.read_text(encoding="utf-8")
    if new in text:
        return
    if old not in text:
        raise SystemExit(f"expected finish context not found in {path}: {old[:100]!r}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


replace(
    "internal/linuxmedia/extracted_layout_options.go",
    "const (\n\textractedPartitionMBR = \"mbr\"\n\textractedPartitionGPT = \"gpt\"\n)\n",
    "const (\n\textractedPartitionMBR  = \"mbr\"\n\textractedPartitionGPT  = \"gpt\"\n\tminimumFAT32Clusters   = uint64(65525)\n)\n",
)
replace(
    "internal/linuxmedia/extracted_layout_options.go",
    "func WriteExtractedPartitionTable(target layoutTarget, layout ExtractedLayout, scheme, label string) error {\n",
    "func validateExtractedFAT32Capacity(partitionBytes, clusterBytes uint64) error {\n\tif clusterBytes == 0 || partitionBytes/clusterBytes < minimumFAT32Clusters {\n\t\treturn fmt.Errorf(\"the selected FAT32 cluster size %d leaves too few clusters on the target\", clusterBytes)\n\t}\n\treturn nil\n}\n\nfunc WriteExtractedPartitionTable(target layoutTarget, layout ExtractedLayout, scheme, label string) error {\n",
)
replace(
    "internal/linuxmedia/extracted.go",
    "\tlayout, err := PlanExtractedLayoutForScheme(opts.TargetSize, sectorSize, fat32Bytes, partitionScheme)\n\tif err != nil {\n\t\treturn result, err\n\t}\n\tresult = ExtractedCreateResult{\n",
    "\tlayout, err := PlanExtractedLayoutForScheme(opts.TargetSize, sectorSize, fat32Bytes, partitionScheme)\n\tif err != nil {\n\t\treturn result, err\n\t}\n\tif err := validateExtractedFAT32Capacity(layout.Partition.SizeBytes, clusterBytes); err != nil {\n\t\treturn result, err\n\t}\n\tresult = ExtractedCreateResult{\n",
)
replace(
    "internal/linuxmedia/extracted_layout_options_test.go",
    "func TestNormalizeExtractedClusterSize(t *testing.T) {\n",
    "func TestExtractedFAT32CapacityRejectsTooFewClusters(t *testing.T) {\n\tif err := validateExtractedFAT32Capacity(128*1024*1024, 32768); err == nil {\n\t\tt.Fatal(\"accepted a cluster size that cannot produce a valid FAT32 cluster count\")\n\t}\n\tif err := validateExtractedFAT32Capacity(4*1024*1024*1024, 32768); err != nil {\n\t\tt.Fatal(err)\n\t}\n}\n\nfunc TestNormalizeExtractedClusterSize(t *testing.T) {\n",
)
replace(
    ".github/workflows/iso-image-loop-qualification.yml",
    "    name: MBR/FAT32 extracted-media qualification\n",
    "    name: MBR/GPT FAT32 extracted-media qualification\n",
)
replace(
    ".github/workflows/iso-image-loop-qualification.yml",
    "            -test.run '^TestCreateExtractedOnRealLoopDevice$' \\\n",
    "            -test.run '^TestCreateExtractedOnRealLoopDevice(MBR|GPT)?$' \\\n",
)
# Rename the original function so the selector and transcript identify both layouts.
replace(
    "internal/linuxmedia/extracted_loop_test.go",
    "func TestCreateExtractedOnRealLoopDevice(t *testing.T) {\n",
    "func TestCreateExtractedOnRealLoopDeviceMBR(t *testing.T) {\n",
)
# Ensure the generated source no longer contains the temporary reader scaffold.
for path in ("internal/linuxmedia/extracted_layout_options.go",):
    text = (ROOT / path).read_text(encoding="utf-8")
    for forbidden in ("cryptoRandRead", "randReader{}", "systemRandomReader"):
        if forbidden in text:
            raise SystemExit(f"temporary random-reader scaffold remained in {path}: {forbidden}")

print("ISO layout-options finishing checks applied")
