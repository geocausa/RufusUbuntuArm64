# FFU restoration design

Status: **read-only common-prefix inspection**. No FFU target can be written by the code in this tranche.

Tracking issues: #269 and #271

## Why FFU is a separate workflow

Microsoft Full Flash Update (`.ffu`) is a sector-based image containing an entire disk layout rather than files for one partition. Microsoft documents `/Apply-FFU` as targeting a physical drive and describes application as cleaning the whole destination drive. FFU therefore belongs in an identity-bound whole-device restoration workflow, not ordinary ISO extraction or WIM application.

Primary references:

- <https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/dism-image-management-command-line-options-s14?view=windows-10#apply-ffu>
- <https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/deploy-windows-using-full-flash-update--ffu?view=windows-11>
- <https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/wim-vs-ffu-image-file-formats?view=windows-11>

Windows Rufus uses the Windows virtual-disk/FFU provider rather than treating FFU as a raw file:

- <https://github.com/pbatard/rufus/blob/master/src/vhd.c>
- <https://github.com/pbatard/rufus/blob/master/src/vhd.h>

Independent structural cross-checks:

- NXP FFU definitions: <https://github.com/nxp-imx/mfgtools/blob/59c76388743cd1fb78375469b5bac6beacddb1ae/libuuu/ffu_format.h>
- Historical MIT `ffu2img.py`: <https://github.com/t0x0/random/blob/master/ffu2img.py>

The historical converter is not accepted as a production provider or conformance oracle. NXP's definitions are used only to prevent overconfident boundary assumptions until supported real-image fixtures and further independent agreement exist.

## Independently established regions

The read-only parser currently establishes:

1. the 32-byte security header (`SignedImage `);
2. the signed catalog and chunk hash-table lengths;
3. the chunk-aligned 24-byte image header (`ImageFlash  `);
4. the manifest length and boundary;
5. the chunk-aligned start of the store metadata;
6. the 248-byte store prefix through `dwFinalTableCount`.

The 248 bytes are a **common prefix**, not a complete versioned store header. Known FFU layouts can append additional fixed or variable fields before validation descriptors, write descriptors and payload data. Consequently the parser deliberately does not report descriptor-table or payload offsets yet.

## Current guarantees

`internal/ffu.Inspect`:

- reads from `io.ReaderAt` only;
- performs no device discovery, mounting, authentication or writing;
- validates known signatures and exact security/image header sizes;
- uses checked addition, multiplication and alignment for every established boundary;
- refuses missing catalog/hash metadata, inconsistent chunk sizes, invalid block geometry, empty or impossibly short declared descriptor tables, inconsistent validation metadata, invalid table-index/count ranges and truncated common regions;
- records reported version fields as metadata without using them to guess a variable extension size;
- reports `descriptor_layout_resolved: false`, `payload_layout_resolved: false` and `restoration_supported: false` for every image.

`cmd/rufus-ffu-inspect` is a developer-only read path. It reuses source-file identity binding, opens the selected regular file without following a replacement symlink and emits JSON or a plain report. It explicitly says that descriptor and payload offsets are unresolved.

## What remains before descriptor planning

The next research gate must identify and validate the complete store extension for each supported layout. It must establish, from multiple independent implementations and real redistributable fixtures:

- exact extension length and variable device-path encoding;
- validation descriptor start and record boundaries;
- write descriptor start and variable location records;
- payload start, padding and compression semantics;
- multi-store relationships and per-store payload sizes.

Unknown layouts remain useful for common-prefix inspection but cannot produce a restoration plan.

## What remains before a loop-file restore

After a store layout is supported, every descriptor must produce a deterministic immutable plan containing:

- source payload range and compression semantics;
- destination disk-access method and exact destination byte range;
- logical block count and ordering;
- overlap and out-of-range rejection;
- relationship to validation descriptors and security hash metadata;
- minimum target surface and any resize semantics.

Unknown disk-access methods, split SFU sets, optimized/resizable FFUs, unrecognized compression, duplicate or overlapping destinations and arithmetic overflow remain hard refusals.

Only after that plan is stable may an executor target a regular file or disposable loop device. A physical removable drive is a later gate.

## Physical-device boundary

A future privileged FFU restore must reuse the existing RufusArm64 safety model:

- exact source identity retained from inspection through execution;
- exact target identity and size bound into a fresh plan;
- running-system and mounted-target refusals;
- a dedicated confirmation phrase naming FFU, source identity and target path;
- no erase before every source, target, descriptor, integrity and capacity preflight succeeds;
- cancellation with conservative changed/incomplete reporting;
- flush and explicitly scoped destination readback;
- no claim that software verification proves a particular computer will boot.

FFU capture, split SFU application, optimized resize semantics, Windows To Go, encrypted persistence and unreviewed arbitrary bootloader writes remain outside this first implementation.
