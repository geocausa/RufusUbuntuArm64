# RufusArm64 0.11.0

RufusArm64 0.11.0 adds two complementary UEFI safety features: a read-only structural and Secure Boot analyzer, and an optional boot-time media-integrity validator for the supported ARM64 persistent Ubuntu/Debian writable-copy path.

## Highlights

- Validate mounted or extracted media for the architecture-specific fallback loader, PE/COFF structure, DBX revocations, SBAT metadata, and trusted local or running-firmware SBAT policy.
- Generate and verify Rufus-compatible `md5sum.txt` manifests through the unprivileged CLI.
- Optionally install a transactional ARM64 `uefi-md5sum` wrapper when creating supported persistent Ubuntu/Debian media. The original fallback loader is preserved and chainloaded after validation.
- Reproduce the package-private loader from exact upstream `uefi-md5sum` v1.2 and EDK2 commits in two independent builds, retaining provenance and corresponding source.
- Qualify unchanged and intentionally corrupted GPT/FAT32 media under pinned AArch64 QEMU firmware, including original-loader chainload and complete diagnostic evidence.

## Important boundaries

The runtime-validation option is off by default and is limited to the guarded ARM64 persistent writable-copy workflow. Raw-image, Windows, NTFS, compressed-stream, and virtual-disk writers do not expose it.

The current runtime loader is **unsigned**. Secure Boot compatibility is not established. The QEMU test mode suppresses the normal interactive error prompt so CI can require deterministic success, corruption reporting, chainload, and shutdown behavior.

Software and QEMU qualification are not universal firmware or hardware guarantees. Physical Surface Pro 11 boot and persistence start/reboot/verify evidence remains a separate qualification step for the exact ISO, USB media, controller, firmware, Secure Boot state, and computer.

## Supply-chain and release assets

The tagged release builds and publishes the ARM64 Debian package, checksum sidecar, deterministic project source archive, pinned WIM corresponding source, and deterministic `uefi-md5sum` corresponding source. The unsigned EFI wrapper remains package-private rather than being published as a standalone boot binary.
