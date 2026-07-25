# FFU full-flash validation gate

Status: **read-only policy resolution only**. This document does not define or authorize a target provider.

Tracking issue: #277  
Prerequisite target plan: #305

## Purpose

The authenticated target-bound plan establishes one exact FFU, one exact selected target, and every exact destination range. Before a future provider can be designed, the store update class and validation-descriptor requirement must also be resolved without guessing.

Microsoft's FFU format description states that the validation section is used only for partial updates. Each partial-update validation entry identifies data that must already exist on the target, and all entries must match before that partial update is safe to apply.

The initial RufusArm64 provider is for complete full-flash restoration, not in-place partial servicing. It therefore accepts only the independently observed full-flash update type `0` with an empty validation-descriptor region.

## Accepted profile

`ResolveAuthenticatedSingleStoreV1FullFlash` re-runs the complete authenticated source and exact target-bound planning chain. It advances the validation gate only when all of the following are true:

- the source remains a supported single-store `1.0` FFU;
- the signed catalog, explicit certificate chain, publisher policy, hash table, and every covered source chunk authenticate successfully;
- the exact target identity, capacity, logical sector size, physical sector size, and destination map remain valid;
- `Store.UpdateType` is exactly `0`;
- validation descriptor count is zero;
- validation descriptor length is zero;
- the parsed descriptor list is empty; and
- the prerequisite target plan does not claim that validation has already been resolved.

The deterministic result binds the target-plan digest, authenticated-integrity digest, descriptor-plan digest, catalog and hash-table digests, target identity and geometry, mutation-byte count, update type, zero validation count, exact confirmation phrase, warnings, limitations, and all explicit state flags.

## Hard refusals

The gate refuses:

- partial update type `1`;
- every unknown update type;
- a nominal full-flash image that nevertheless contains validation descriptors;
- any disagreement between header counts, parsed descriptors, or target-plan evidence;
- malformed or noncanonical target facts;
- altered plan evidence, warning text, limitation text, or confirmation phrase;
- nil or already-cancelled contexts; and
- any failure in the prerequisite source-authentication or target-binding chain.

Partial updates are not converted, ignored, or approximated as full restoration. Supporting them would require a separate design that reads and compares each target range before mutation and proves the update-specific safety model.

## State transition

A successful plan records:

- `full_flash_update_confirmed: true`;
- `validation_descriptors_absent: true`;
- `validation_checks_resolved: true`;
- `confirmation_required: true`; and
- `execution_supported: false`.

The exact destructive phrase remains:

```text
RESTORE AUTHENTICATED FFU TO /dev/DEVICE SIZE N BYTES
```

The phrase identifies the reviewed path and capacity but grants no authority to open or mutate the target.

## Remaining provider boundary

This tranche deliberately performs no:

- device discovery or target opening;
- mounted-target or running-system-disk decision;
- privilege or Polkit authorization;
- source or target revalidation immediately before mutation;
- exclusive target locking;
- write ordering or safe GPT phase execution;
- cancellation or changed-media reporting;
- flush, readback, or verification;
- loop-device provider qualification;
- GTK integration; or
- physical boot or hardware-health claim.

A later provider must independently re-establish every source and target fact under the held descriptors before the first destructive action. Execution remains disabled until that provider and its interruption semantics pass separate review and qualification.

## Conformance basis

The policy is based on the historical Microsoft FFU format description for `VALIDATION_ENTRY`, which describes the validation section as partial-update-only and requires every target comparison to succeed before applying a partial image. The structure is independently reproduced by NXP's `ffu_format.h` and by decompiled Microsoft imaging types.

These sources support the fail-closed classification used here. They do not justify implementing partial-update target reads in this tranche.
