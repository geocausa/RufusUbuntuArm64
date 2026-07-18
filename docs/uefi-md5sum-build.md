# Pinned ARM64 `uefi-md5sum` build

RufusArm64 does not download or trust a floating bootloader binary. The 0.11 development line rebuilds the ARM64 runtime-integrity loader from exact source revisions and records the result before any installation path is considered.

## Exact inputs

| Component | Upstream reference | Resolved commit |
|---|---|---|
| `pbatard/uefi-md5sum` | `v1.2` | `6195f2ef754c2ad390bda6590628708f410d55f6` |
| `tianocore/edk2` | `edk2-stable202508.01` | `3d244c3b364bd4e21261380662186d064659161c` |

The build uses the Ubuntu 24.04 AARCH64 GCC cross-toolchain in EDK2 `RELEASE` mode:

```text
build -a AARCH64 -b RELEASE -t GCC -p Md5SumPkg.dsc
```

The script fetches each exact commit into a new repository, verifies `HEAD`, initializes the EDK2 submodules selected by the pinned parent, and uses a fixed locale, timezone, Python hash seed, and `SOURCE_DATE_EPOCH`.

## Reproducibility gate

The dedicated workflow performs two independent builds. It compares the loader, checksum sidecars, source archive, source metadata, and provenance JSON byte-for-byte. The canonical artifact is published only when every comparison succeeds.

The artifact contract contains:

- `bootaa64.efi`
- `bootaa64.efi.sha256`
- `provenance.json`
- `SOURCE-COMMITS.txt`
- `uefi-md5sum-v1.2-source.tar.gz`
- `uefi-md5sum-v1.2-source.tar.gz.sha256`
- `REPRODUCIBILITY.txt`

The exact corresponding GPL-2.0-or-later `uefi-md5sum` source is retained as a deterministic archive. The EDK2 source is identified by exact repository and commit and is fetched reproducibly by the build script.

## Binary validation and signing status

`scripts/inspect-uefi-pe.py` requires:

- PE/COFF machine `0xAA64` (ARM64)
- PE32+ optional header
- subsystem 10 (EFI application)
- a well-formed certificate-table range when present

The source-built loader is expected to have no Authenticode certificate table. CI verifies that state independently with `sbverify` and records:

> The loader is unsigned and is not claimed Secure Boot compatible.

An Authenticode table alone would not establish firmware trust. A future signed-loader path would require independent certificate-chain, SBAT, DBX, and target-firmware qualification before any Secure Boot claim.

## Chainload contract

The upstream ARM64 loader expects:

```text
EFI/BOOT/BOOTAA64.EFI            runtime-integrity loader
EFI/BOOT/bootaa64_original.efi   original removable-media fallback loader
md5sum.txt                       root integrity manifest
```

This tranche builds and audits the loader only. It does not place these files onto media, rename a fallback loader, add a writer option, invoke privilege elevation, or modify firmware.
