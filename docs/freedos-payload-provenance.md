# FreeDOS minimal payload provenance

Status: **payload provenance and kernel configuration resolved; no product exposure**.

This checkpoint proves that the minimal Rufus-style FreeDOS payload can be
reproduced on an Ubuntu ARM64 host without executing x86 code. It does not
format media, authorize a device operation, or claim physical boot success.

## Official distribution path

- Distribution: FreeDOS 1.4 FullUSB
- Outer archive: `FD14-FullUSB.zip`
- Archive SHA-256: `cd440cd165f5a8a184870cb615f525af182660c15f9bcf1e9d198ca19cedcaff`
- Disk image member: `FD14FULL.img`
- Logical sector size: 512 bytes
- First partition start: logical sector 63

The first partition is read as an ordinary image through `mtools`; no loop
device or root privilege is required for extraction.

## Nested package records

| Package | Size | SHA-256 |
|---|---:|---|
| `PACKAGES/BASE/FREECOM.ZIP` | 2,037,468 | `2529cf15c2ee7d7030ed99a6a88df2cf5eef87b9fe10f1c0fb643c38ea6aaa8e` |
| `PACKAGES/BASE/KERNEL.ZIP` | 772,721 | `38ce3c63e399c8f18ab6230d8988a5d1a1aa9be4e109d15c6f4842b5e8fe61e6` |

## Payload records

| Output | Official member or derivation | Size | SHA-256 | Rufus Git blob |
|---|---|---:|---|---|
| `COMMAND.COM` | `BIN/COMMAND.COM` | 87,772 | `077808379e896476f7f69d62e6c8989d8fc23e8ef58d1c8492db1ac106784107` | `255525acc562e0411e3e5f000bc1ba788733056d` |
| `KERNL386.SYS` | `BIN/KERNL386.SYS` | 46,256 | `932c0c155701eddb7b902f7269a1b2ce31f5c82a6dc195172f2336d18a74e1fb` | `bfe7cdfe616dc71ded366bc57fa8c370a548faa6` |
| `KERNEL.SYS` | `KERNL386.SYS` with byte `0x0d` changed from `0x00` to `0x01` | 46,256 | `57504a0d5e1d57a0407d995e77fcebb9627da2c0dbe0f1cbf7c5fa901d2efc6c` | `6b524a99481f2286a5ddcb06c4fbccfe2bc5cfbd` |

The extractor and Go validator require every other kernel byte to remain
identical. The configured output matches Rufus 4.15 exactly.

## Corresponding source and licence material

| Source archive | Size | SHA-256 | Required licence member |
|---|---:|---|---|
| `freecom-sources.zip` | 1,236,304 | `beef029a2268cac4dd5b729a649ea4e23f30c9cfee1788c4bbd64b4d4ddb093b` | `license` |
| `kernel-sources.zip` | 539,853 | `fda372721899e6a9cabbfa6beed259be19dafd0fe16d90b8f4da1a9397fde574` | `COPYING` |

Both official package metadata files identify GNU GPL version 2. The exact
FreeCOM and kernel GPLv2 texts, LSM records, and corresponding source archives
are retained under `vendor/freedos/`.

## Validation contract

`python3 scripts/extract-freedos-payload.py --check` validates the committed
manifest and all payload/source/licence files without network access. Go tests
independently validate embedded payload sizes and SHA-256 values, the exact
one-byte `FORCELBA` derivation, defensive-copy behavior, manifest synchronization,
and plausible byte tampering.

The next gate is complete ordinary-file FAT32 media construction and
verification: allocation chains, root-directory entries, hidden-sector and BPB
geometry, boot-code regions, payload placement, and final readback. Only after
that may loop-device and guarded executor integration begin.
