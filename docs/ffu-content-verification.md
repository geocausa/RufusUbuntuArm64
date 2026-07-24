# FFU source-content verification

Status: **read-only integrity planning only**. This document does not define or authorize a target binder or executor.

Tracking issues: #269 and #276

## Scope

`internal/ffu.VerifyHashTableContent` validates every supported FFU SHA-256 hash-table entry against the corresponding source chunk. `internal/ffu.PlanVerifiedSingleStoreV1` then binds that completed comparison to the existing single-store-v1 descriptor plan.

This tranche establishes source consistency with the embedded table. It does **not** authenticate that table, its catalog signer, or its publisher.

## Coverage model

The covered byte stream starts at the already validated, chunk-aligned `ImageFlash  ` image-header offset and continues through the exact end of the FFU file.

Consequently, the comparison excludes:

- the 32-byte `SignedImage ` security header;
- the embedded catalog;
- the embedded hash table itself;
- security-area padding before the image header.

It includes every subsequent source byte:

- image header and manifest;
- alignment padding;
- store metadata;
- validation and write descriptor tables;
- payload alignment;
- payload blocks;
- any trailing source bytes.

This model follows the Microsoft imaging verifier recovered in `Microsoft.WindowsPhone.Imaging.ImageSigner`: it seeks to `StartOfImageHeader`, hashes one declared chunk at a time, and continues until EOF. The paired `SecurityWrapper` builder requires the generated covered stream to be chunk aligned and emits exactly one SHA-256 entry per chunk.

Independent FFU readers also place the image header after the complete security header, catalog, hash table and chunk-boundary padding:

- https://github.com/Empyreal96/WP_Common_Tools/blob/e8428c1c9fdec80006ecfffdb39f21d57f18c3d9/src/imagecommon/Microsoft.WindowsPhone.Imaging/ImageSigner.cs
- https://github.com/Empyreal96/WP_Common_Tools/blob/e8428c1c9fdec80006ecfffdb39f21d57f18c3d9/src/imagecommon/Microsoft.WindowsPhone.Imaging/SecurityWrapper.cs
- https://github.com/nijel8/emmcdl/blob/3c5ac42189eb1ddc66afd58bc71e25577859f355/src/ffu.cpp
- https://github.com/t0x0/random/blob/ba2e3a2be8a3f990abe88048dc8db78cfc992559/ffu2img.py3

These implementations are conformance evidence, not a substitute for a published Microsoft wire-format guarantee. Unsupported layouts and algorithms remain fail-closed.

## Chunk and final-tail rules

Only the structural tranche's explicit `CALG_SHA_256` contract is accepted.

For each entry:

1. derive the exact source offset with checked arithmetic;
2. stream at most one declared chunk through SHA-256 using a bounded 64 KiB buffer;
3. if EOF leaves a final partial chunk, append zero bytes to the hash input until the declared chunk size is reached;
4. compare the computed and embedded 32-byte digests in constant time.

The zero-fill rule matches the verifier's full-size zero-initialized chunk buffer before its final short read. Normal Microsoft-generated images are expected to be chunk aligned; reporting final zero padding therefore preserves evidence when inspecting a noncanonical tail rather than silently treating it as ordinary.

The declared table must contain exactly `ceil(covered_bytes / chunk_size)` entries. Missing, extra, reordered, truncated, or mismatched entries are hard failures. The table is rehashed after all chunk comparisons and must still match the structural plan's initial table digest.

## Deterministic plan binding

The content-verification digest binds:

- source size and covered range;
- algorithm and digest size;
- table offset, length, entry count and SHA-256;
- chunk size and expected/verified counts;
- final data and zero-padding lengths;
- mismatch location and expected/actual digests when present;
- explicit authentication state.

The outer integrity-descriptor digest additionally binds:

- the existing descriptor-plan SHA-256;
- the structural hash-table-plan SHA-256;
- the completed content-verification SHA-256;
- coverage geometry and final-padding evidence;
- target-binding and execution states.

The digest is a deterministic review identifier, not a signature.

## Source consistency

`rufus-ffu-integrity-plan` opens the selected regular file through the repository's identity-bound source boundary.

On Linux filesystems that support read leases, the command holds an `F_RDLCK` lease throughout descriptor planning and chunk verification, fails closed on a lease-break request, rechecks the lease, and revalidates the pinned descriptor before releasing it.

When a read lease is unavailable or conflicts with existing writable access, the command uses the conservative fallback:

1. full-file SHA-256 before planning;
2. descriptor and content-integrity planning;
3. pinned source-identity revalidation;
4. full-file SHA-256 after planning;
5. exact before/after digest equality.

## Trust-state separation

A successful comparison sets `content_matches_hash_table: true` only.

It continues to report:

- `hash_table_catalog_authenticated: false`;
- `integrity_authenticated: false`;
- `execution_supported: false`.

Microsoft documents the catalog signature as the mechanism that authenticates the table of hashes. Parsing CMS/PKCS#7 is not sufficient by itself: a later tranche must define an explicit signer and trust-root policy before the table can be treated as authenticated.

Reference:

- https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/efi-checksig-protocolefichecksignatureandhash

## Command boundary

```text
rufus-ffu-integrity-plan --image IMAGE.ffu [--json]
```

The command accepts no target option. It opens no block device and contains no destination write, validation, flush, readback, regular-file executor, loop-device executor, or physical-device executor.

## Acceptance coverage

Focused fixtures cover:

- aligned and final-partial content;
- zero-filled final-chunk hashing;
- missing and extra table entries;
- wrong and reordered entries;
- deterministic mismatch location and digest evidence;
- a table changing during verification;
- bounded read requests;
- cancellation;
- deterministic plan digests;
- fuzz no-panic behavior;
- a command contract with no target argument.

Complete repository CI, native ARM64 execution, static and vulnerability audit, reproducible packaging, and the existing privileged loop qualification suites remain mandatory before merge.
