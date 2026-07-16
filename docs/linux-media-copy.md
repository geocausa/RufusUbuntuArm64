# Verified writable Linux media-tree copy

The 0.9 development line includes an internal `linuxmedia` package for turning a read-only mounted Linux ISO tree into a reviewed manifest and then copying that manifest into a private writable boot tree.

This is a prerequisite for persistence creation. Raw ISOHybrid writing preserves the ISO9660 boot tree, which cannot be safely edited to add the `persistent` or `persistence` kernel argument.

## Inspection contract

`Inspect` walks a caller-mounted, read-only source tree and records every directory and regular-file payload. The default safety limits are 250,000 entries and 16 GiB of copied data; callers may reduce either limit.

The inspector:

- requires local relative paths and valid UTF-8;
- can enforce FAT32 component, reserved-name, path-length, case-collision, and 4 GiB single-file constraints;
- requires the architecture-specific fallback UEFI loader when requested (`BOOTAA64.EFI`, `BOOTX64.EFI`, or `BOOTIA32.EFI`);
- never follows a directory symbolic link;
- accepts a file symbolic link only when its fully resolved target is a regular file beneath the same source root, then records that target as bytes to materialize at the link path;
- hashes each stable source file with SHA-256 and rejects a file that changes during inspection.

This policy deliberately turns supported file links into ordinary files because FAT32 cannot represent POSIX symbolic links. Directory links and external links remain unsupported until a distro-specific compatibility policy can justify them.

## Copy contract

`CopyAndVerify` accepts only a previously generated manifest and an empty, real destination directory. The future privileged orchestrator must mount a newly formatted boot partition privately and retain the whole-disk lock while calling it.

For each file the copier:

- revalidates that the manifest source remains beneath the pinned source root;
- refuses source and destination trees that overlap;
- refuses symbolic-link destination path components;
- copies into a same-directory temporary file;
- verifies the streamed byte count and SHA-256 against the manifest;
- fsyncs the temporary file, atomically renames it, and fsyncs the parent directory;
- hashes every destination file again before reporting success.

The destination must be private to the process. This prevents another process from racing the final non-replacing checks on filesystems that do not provide a portable `renameat2(RENAME_NOREPLACE)` primitive.

## What remains before a public persistence mode

The copy engine is not connected to `write` or the GUI. A complete orchestration tranche must still:

1. identity-bind and mount the selected ISO read-only;
2. choose a supported MBR/GPT and FAT32 boot-partition layout;
3. format and privately mount the writable boot partition;
4. inspect, copy, and verify the Linux media tree;
5. patch only the approved boot configuration files;
6. create and verify the ext4 persistence partition;
7. repeat source/target safety checks across destructive boundaries;
8. qualify Ubuntu and Debian images on physical ARM64 hardware and firmware.
