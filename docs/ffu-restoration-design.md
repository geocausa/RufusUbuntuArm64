# FFU restoration design

Status: **read-only inspection foundation**. No FFU target can be written by the code in this tranche.

Tracking issue: #269

## Why FFU is a separate workflow

Microsoft Full Flash Update (`.ffu`) is a sector-based image containing an entire disk layout rather than files for one partition. Microsoft documents `/Apply-FFU` as targeting a physical drive, and describes application as cleaning the whole destination drive. That makes FFU closer to an identity-bound whole-device restoration operation than to ordinary ISO extraction or WIM application.

Primary references:

- <https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/dism-image-management-command-line-options-s14?view=windows-10#apply-ffu>
- <https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/deploy-windows-using-full-flash-update--ffu?view=windows-11>
- <https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/wim-vs-ffu-image-file-formats?view=windows-11>

Windows Rufus uses the Windows virtual-disk/FFU provider. Its source explicitly treats FFU as a provider-backed Windows path rather than a raw file that can safely be copied directly:

- <https://github.com/pbatard/rufus/blob/master/src/vhd.c>
- <https://github.com/pbatard/rufus/blob/master/src/vhd.h>

The historical MIT-licensed `ffu2img.py` implementation is useful as a format cross-check for version-2 header boundaries, but it warns that it was tested against one 2015 Raspberry Pi image. It is not accepted as a production restoration provider or conformance oracle:

- <https://github.com/t0x0/random/blob/master/ffu2img.py>

## Known container regions

The read-only parser recognizes and bounds the following regions:

1. Security header (`SignedImage `), signed catalog, and chunk hash table.
2. Chunk-aligned image header (`ImageFlash  `) and manifest.
3. Chunk-aligned Full Flash store header.
4. Validation descriptor table.
5. Write descriptor table.
6. Chunk-aligned payload.

The current parser accepts the known Full Flash major versions 2 and 3. Version 3 adds a compression-algorithm field and has a larger minimum write-descriptor record. Unknown versions are rejected rather than guessed.

## Current guarantees

`internal/ffu.Inspect`:

- reads from `io.ReaderAt` only;
- performs no device discovery, mounting, authentication, or writing;
- validates known signatures and exact known header sizes;
- uses checked addition, multiplication, and alignment for every untrusted boundary;
- refuses missing catalog/hash metadata, inconsistent chunk sizes, unsupported Full Flash versions, invalid block geometry, empty/undersized descriptor tables, invalid table ranges, and truncated regions;
- reports all known offsets and sizes as immutable JSON-compatible data;
- always reports `restoration_supported: false`.

`cmd/rufus-ffu-inspect` is a developer-only read path. It reuses the repository's source-file identity binding, opens the selected regular file without following a replacement symlink, and emits either a human-readable report or JSON. It is intentionally not part of the privileged writer.

## What remains before a loop-file restore

The next tranche must parse every descriptor and produce a deterministic plan. It must establish, for each payload unit:

- source payload range and compression semantics;
- destination disk access method and exact destination byte range;
- logical block count and ordering;
- overlap and out-of-range rejection;
- relationship to validation descriptors and the security hash table;
- minimum target surface and whether any resizing semantics are present.

Unknown disk-access methods, split SFU sets, optimized/resizable FFUs, unrecognized compression, duplicate/overlapping destinations, and arithmetic overflow remain hard refusals.

Only after that plan is stable may an executor target a regular file or disposable loop device. A physical removable drive is a later gate.

## Physical-device boundary

A future privileged FFU restore must reuse the existing RufusArm64 safety model:

- exact source identity retained from inspection through execution;
- exact target identity and size bound into a fresh plan;
- running-system and mounted-target refusals;
- a dedicated confirmation phrase naming FFU, source identity, and target path;
- no erase before every source, target, descriptor, integrity, and capacity preflight succeeds;
- cancellation with conservative changed/incomplete reporting;
- flush and explicitly scoped destination readback;
- no claim that software verification proves a particular computer will boot.

FFU capture, split SFU application, optimized resize semantics, Windows To Go, encrypted persistence, and unreviewed arbitrary bootloader writes are outside this first implementation.
