# FFU authenticated trust-bundle publication

Status: **durable storage and recovery for an authenticated but inactive trust bundle**. This tranche does not activate a certificate, build an Authenticode chain, make a publisher-trust decision, access a target device, perform a network request, or enable FFU restoration.

## Storage contract

`internal/ffu.PublishAuthenticatedTrustBundle` accepts the exact bundle bytes, signed metadata envelope, explicit public-key policy, and evaluation time already required by `AuthenticateTrustBundleMetadata`. Publication is refused unless the resulting plan is structurally valid, threshold-authenticated, and still on the inactive side of every trust boundary.

The caller supplies a dedicated existing directory. It must:

- resolve without any symbolic-link component;
- be owned by the effective user;
- be a real directory with mode `0700`;
- remain bound to the same device and inode for the transaction.

The implementation opens and locks that directory, then performs descendant operations relative to open directory descriptors. Exact-case name checks, `openat` with `O_NOFOLLOW`, `fstat`, ownership, link-count, permission, size, and device/inode checks prevent path substitution and unsafe object types from becoming publication input.

## Immutable generations

Each accepted generation is named from its authenticated sequence, bundle SHA-256, and envelope SHA-256:

```text
generations/generation-<20-digit-sequence>-<bundle-sha256>-<envelope-sha256>/
```

A generation contains exactly:

- `bundle.json` — exact authenticated trust-bundle bytes;
- `metadata.json` — exact signed metadata-envelope bytes;
- `evidence.json` — canonical publication evidence.

Files are written with mode `0400`, individually `fsync`ed, and checked as single-link regular files. The staging directory is then changed to mode `0500`, `fsync`ed, and published with Linux `renameat2(RENAME_NOREPLACE)`. Generation names are immutable; a colliding name must reproduce the same authenticated evidence or publication fails.

At most 256 immutable generations are accepted. Unknown entries, case-equivalent aliases, malformed private temporary names, excessive entries, symlinks, foreign ownership, hard links, and unexpected modes are refused.

## Evidence and rollback binding

`evidence.json` binds:

- exact bundle and envelope sizes and SHA-256 digests;
- signed-metadata SHA-256;
- authenticated plan SHA-256;
- key-set version, key-set SHA-256, threshold, and signing key ids;
- the previous durable sequence and bundle SHA-256 used for rollback validation;
- the canonical UTC evaluation time used when the generation was published;
- `trust_anchors_activated: false`.

Recovery first reproduces the historical publication plan using that previous rollback state and publication time. It then reauthenticates at the caller's current evaluation time so expiration and current policy are enforced without losing the ability to prove what was originally committed.

## Single atomic commit point

The immutable generation is durable before it can become active. One small canonical file, `active.json`, is the only commit point. It binds the selected generation and all generation/evidence digests.

- The first publication uses `RENAME_NOREPLACE`.
- An update uses `RENAME_EXCHANGE`, verifies that the exchanged-out inode and bytes are the exact previously validated active record, and keeps them until final verification completes.
- The storage root is `fsync`ed after the active-record operation.

This design does not claim that several independent file renames form one atomic transaction. The generation is immutable and complete first; only the active-record exchange changes the selected state.

## Rollback and interruption recovery

Every publication stage has a deterministic test hook. On an error or cancellation, rollback:

- restores the previous active record after an exchange;
- removes an uncommitted first active record only when it still matches the attempted record;
- removes newly published or staged generation data through the original directory descriptors;
- `fsync`s the generations and root directories.

`RecoverAuthenticatedTrustBundle` removes only strictly named private temporaries after validating their type, ownership, mode, and link count. It then validates the active record, exact generation layout, every digest, historical publication evidence, current authentication policy, path-to-descriptor identity, and inactive-trust flags.

Previous immutable generations are retained after successful updates. Automatic pruning, trust-anchor activation, and administrative rollback selection remain separate reviewed work.

## Resource limits

- bundle: existing 4 MiB trust-bundle limit;
- signed metadata envelope: 256 KiB;
- publication evidence: 128 KiB;
- active record: 32 KiB;
- immutable generations: 256;
- private temporary entries: bounded by the existing metadata-signature limit.

## Acceptance coverage

Tests cover:

- first publication, exact reuse, update, and recovery;
- rollback at every first-publication and update stage;
- context cancellation before and during publication;
- competing process lock refusal;
- stale known-temporary cleanup;
- root and `generations` path substitution;
- active-record mutation before commit;
- bundle/evidence/layout tampering;
- symlink roots, unsafe modes, hard links, unexpected names, and duplicate JSON members;
- deterministic canonical evidence with inactive trust anchors;
- no-panic fuzzing of canonical store records;
- native and cross-compiled Linux ARM64 package execution through repository CI.
