# FFU identity-bound restore target plan

Status: **non-privileged review planning only**. This boundary does not open a target, execute FFU validation descriptors, write media, flush, read back, or enable restoration.

Tracking issues: #269, #277, and #289

## Plain-language purpose

The authenticated-integrity boundary proves that an approved publisher signed the exact FFU hash table and that every covered source byte matches it.

This tranche answers the next separate question:

> If that authenticated FFU were restored to this exact selected drive, where would every payload extent go, and is the drive large enough and geometrically compatible?

The answer is calculated before administrator authentication and without opening the target path.

## Caller-provided target facts

`BindAuthenticatedSingleStoreV1Target` accepts immutable facts discovered by an unprivileged caller:

- one canonical absolute path beneath `/dev`;
- one exact refreshed target identity token;
- exact target capacity in bytes;
- logical sector size; and
- physical sector size.

The request is rejected when the path or identity is noncanonical, capacity is zero or misaligned, sector sizes are not bounded powers of two, physical sectors are smaller than logical sectors, or the geometry is internally inconsistent.

These facts are review inputs, not authority. A future privileged provider must rediscover and revalidate every field immediately before any mutation.

## Source authentication prerequisite

Target planning re-runs the complete read-only single-store-v1 source-authentication pipeline. It requires:

- bounded descriptor and payload planning;
- catalog-to-hash-table authentication under an explicit approved publisher;
- complete SHA-256 source-chunk comparison; and
- `integrity_authenticated: true`.

A target cannot be bound from partially parsed or unauthenticated FFU metadata.

## Geometry and capacity

The target must:

- be at least the descriptor plan's conservative minimum target size;
- contain an integral number of FFU store blocks;
- be aligned to both logical and physical sector sizes; and
- use sector sizes that divide the FFU store block size exactly.

This tranche supports only the existing single-store header version `1.0` contract.

## Destination resolution

Each write descriptor consumes one sequential source payload extent. Every destination location is converted into an exact target block and byte range.

Beginning-anchored locations resolve directly from block zero.

For an end-anchored location with recorded block index `i` and descriptor block count `n`, the existing descriptor parser records `block_end = i + n`. On a target containing `T` store blocks, the resolved start is:

```text
T - block_end
```

The resolved end is the start plus `n`.

Every range must remain within the target. Resolved extents are sorted deterministically and any overlap—whether same-anchor or beginning-versus-end—is refused. The plan never guesses write precedence for overlapping mappings.

## Deterministic evidence

The target plan binds:

- authenticated-integrity plan SHA-256;
- descriptor plan SHA-256;
- exact catalog and hash-table SHA-256 values;
- source size;
- canonical target path and exact identity token;
- capacity and logical/physical sector geometry;
- store block size and target block count;
- minimum target size;
- every resolved source-payload and target byte range;
- total planned mutation bytes;
- validation-descriptor count;
- safety-state booleans;
- exact warnings and limitations; and
- a deterministic plan SHA-256.

The plan digest is tamper evidence for review and hand-off. It is not a signature and does not grant permission to access the target.

## Exact confirmation phrase

A validated plan produces:

```text
RESTORE AUTHENTICATED FFU TO /dev/DEVICE SIZE N BYTES
```

The phrase binds the canonical selected device path and exact reviewed capacity. A future privileged command must also require the independently rediscovered target identity and the complete plan evidence; text entry alone can never authorize mutation.

## Deliberate remaining boundaries

A successful target plan sets:

```text
source_integrity_authenticated: true
target_identity_bound: true
target_geometry_bound: true
destination_map_resolved: true
destination_overlap: false
confirmation_required: true
```

It deliberately retains:

```text
validation_checks_resolved: false
execution_supported: false
```

The following remain separate future tranches:

- exact target-side interpretation and execution of validation descriptors;
- privileged source and target reopening with descriptor-safe identity revalidation;
- removable/system-disk policy and mounted-filesystem handling;
- destructive command authorization;
- interruption and cancellation state transitions;
- ordered payload writes;
- synchronized flush and close;
- bounded readback and verification-scope reporting;
- loop-device qualification;
- GTK integration; and
- real-device restoration and boot evidence.

No regular-file, loop-device, or physical-device FFU executor exists in this tranche.

## Acceptance coverage

Deterministic synthetic coverage includes:

- successful exact target binding;
- beginning- and end-relative destination resolution;
- target-specific cross-anchor overlap refusal;
- too-small and misaligned capacity refusal;
- invalid path, identity, and sector geometry refusal;
- evidence and confirmation tamper refusal;
- deterministic repeated planning;
- nil and cancelled context handling; and
- a permanent source contract forbidding path opening, network access, writes, validation success, and executor enablement.

Complete exact-head Go 1.22 CI, native ARM64 execution, static and vulnerability audit, reproducible packaging, and both existing loop qualification suites remain mandatory before merge.
