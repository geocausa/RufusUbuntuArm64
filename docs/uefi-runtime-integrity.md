# UEFI runtime media integrity

Rufus upstream's **Enable runtime UEFI media validation** option installs [`uefi-md5sum`](https://github.com/pbatard/uefi-md5sum), which verifies a root `md5sum.txt` at boot and then chainloads the original removable-media fallback loader. This differs from RufusArm64's read-only UEFI structural, SBAT, DBX, and Secure Boot analyzer.

## Implemented in the 0.11 development line

The `internal/runtimeintegrity` package generates, parses, and verifies the strict interoperable subset of `md5sum.txt` used by `uefi-md5sum`. It uses descriptor-rooted, no-symlink traversal, stable inode/type/size/time checks, deterministic `./path` ordering, lowercase MD5 records, and the `md5sum_totalbytes` progress extension. Verification reports changed, missing, unexpected, and total-byte mismatches.

The parser and generator retain upstream's published safety ceilings: a 64 MiB manifest, 100,000 records, and 512-byte paths. MD5 is used only because it is the on-media interoperability contract; RufusArm64 continues to use SHA-256 for download, source-identity, loader provenance, and destructive-write assurance.

The ARM64 loader is rebuilt reproducibly from:

- `pbatard/uefi-md5sum` v1.2 commit `6195f2ef754c2ad390bda6590628708f410d55f6`;
- `tianocore/edk2` `edk2-stable202508.01` commit `3d244c3b364bd4e21261380662186d064659161c`.

The canonical unsigned loader is 40,960 bytes with SHA-256 `543615a8e97fed1cb5293bee7bdfe10f9feb6979f191b20ab32dafdcf097b502`. It is packaged privately as `/usr/lib/rufusarm64/bootaa64-uefi-md5sum.efi` together with exact source and provenance. It is never downloaded at runtime.

The guarded persistent Ubuntu/Debian writable-copy creator can install the loader transactionally as:

```text
EFI/BOOT/BOOTAA64.EFI            runtime-integrity loader
EFI/BOOT/bootaa64_original.efi   original removable-media fallback loader
md5sum.txt                       root integrity manifest
```

The transaction validates both EFI applications, preserves the original before replacement, publishes the wrapper and manifest atomically, verifies the resulting manifest, and restores the exact original tree after every tested failure boundary. Raw-image, Windows, NTFS, compressed-stream, and virtual-disk writers do not accept this option.

## QEMU qualification contract

`.github/workflows/uefi-runtime-qemu.yml` builds the exact loader, pinned EDK2 AArch64 firmware, and a deterministic original-loader marker application. It constructs ordinary 64 MiB GPT media with a FAT32 EFI System Partition and generates `md5sum.txt` through the production Go command.

The workflow boots two images under `qemu-system-aarch64` using the same upstream test-mode SMBIOS vendor string, `GitHub Actions Test`:

1. an unchanged image must report zero failed files and chainload the original-loader marker;
2. an image whose covered payload is changed after manifest generation must report a checksum error and still prove the documented test-mode chainload path.

A timeout is always a failure. QEMU must shut down through the upstream test-mode path. Serial logs, compressed disk images, firmware, hashes, loader provenance, and the production verifier's corruption report are retained as workflow artifacts.

Upstream test mode suppresses the normal interactive `Continue with boot? [y/n]` prompt, chainloads after reporting errors, and shuts down QEMU after the original loader returns. Normal firmware preserves the interactive decision. The automated gate therefore proves execution, success, corruption detection, and chainload, but does not substitute for physical keyboard/firmware qualification.

## Secure Boot and physical qualification boundary

The current loader has no Authenticode certificate table. QEMU qualification runs with Secure Boot disabled and does **not** establish Secure Boot compatibility. A future signed path would require certificate-chain, SBAT, DBX, and target-firmware trust qualification.

Release readiness still requires physical ARM64 boot and persistence start/reboot/verify evidence on the intended device. Software, QEMU, and PE checks cannot guarantee that a particular firmware will accept or correctly boot the media.
