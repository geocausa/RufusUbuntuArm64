# FFU hash-table structural plan

Status: **read-only metadata planning only**. This document does not define catalog trust, source-content verification, target binding, or restoration.

Tracking issue: #276

## Scope

`internal/ffu.PlanHashTable` reuses the existing structural inspector, then validates the security header's hash algorithm and table shape before streaming the catalog and hash table through SHA-256.

The development command is:

```text
rufus-ffu-hash-plan --image image.ffu [--json]
```

It accepts no target argument, opens the selected source read-only through the repository's identity-bound regular-file boundary, and cannot write a regular file, loop device, or physical device.

## Accepted algorithm

This tranche accepts only Windows `CALG_SHA_256` (`0x0000800c`). Microsoft defines that ALG_ID as SHA-256, whose digest length is 32 bytes.

References:

- https://learn.microsoft.com/en-us/windows/win32/seccrypto/alg-id
- https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/efi-checksig-protocolefichecksignatureandhash
- https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/wim-vs-ffu-image-file-formats?view=windows-11

Unknown algorithm identifiers are refused rather than mapped to a guessed digest length.

## Hash-table shape

The declared hash-table length must be:

- non-zero;
- an exact multiple of 32 bytes;
- fully contained within the already validated FFU security region.

The plan derives `hash_entry_count = hash_table_length / 32` with overflow-safe unsigned arithmetic. A malformed or empty table is rejected before any content-verification claim can be made.

Catalog and hash-table bytes are read with a bounded 64 KiB buffer. They are not loaded into memory as complete regions. Caller cancellation is checked during both streaming passes.

## Recorded metadata

The plan records:

- source file size;
- algorithm identifier, name, and digest size;
- catalog offset, length, and SHA-256;
- hash-table offset, length, SHA-256, and entry count;
- a deterministic plan SHA-256 over all material fields;
- explicit false status fields for catalog authentication and source-content verification.

The catalog and table SHA-256 values are reproducibility and review identifiers. They are not signatures and do not establish publisher authenticity.

## Authentication boundary

Microsoft documents two separate checks:

1. the signed catalog authenticates the hash table;
2. the hash table validates FFU image content when the image is applied.

This tranche performs neither check. It deliberately reports:

- `catalog_authentication_attempted: false`;
- `hash_table_catalog_authenticated: false`;
- `content_verification_attempted: false`;
- `content_matches_hash_table: false`.

A future catalog tranche must define an explicit trust-root policy before setting catalog authentication true. Successful CMS/PKCS#7 parsing alone is not a trust decision.

## Still unresolved

Content verification remains disabled until independent evidence establishes:

- the exact first byte covered by entry zero;
- whether security metadata, aligned padding, image metadata, descriptors, payload, and trailing bytes are covered;
- the padding rule for a short final chunk;
- whether a partial final chunk is hashed at its physical length or a padded length;
- the exact expected entry count for each supported layout.

Until those rules are established from multiple independent implementations and fixtures, no source chunk is compared with a table entry and the descriptor planner's integrity-authenticated status remains false.
