# FFU single-phase write-order boundary

Stage 3 accepts no destructive FFU execution merely because the source, target,
and confirmation phrase have been authenticated. The order in which FFU payload
blocks would be applied is a separate safety boundary.

## Accepted profile

The initial provider recognizes only the unambiguous single-phase profile:

- store-header version 1.0;
- full-flash update type `0`;
- zero validation descriptors;
- an empty, canonical initial-table range;
- an empty, canonical flash-only-table range; and
- one final-table range beginning at payload block zero and covering every
  sequential payload block exactly.

This profile is useful for desktop-style FFUs whose payload is already described
as one complete final image. The planner preserves the FFU write-descriptor order
and, within each descriptor, the declared location order. A payload extent reused
at multiple target locations produces one ordered operation per location.

## Refused profiles

Any non-empty initial or flash-only table range is treated as a staged-GPT or
mobile-style profile and refused. A partial, shifted, truncated, or otherwise
non-covering final-table range is also refused.

The public format material identifies initial, flash-only, and final GPT payload
ranges, but it does not provide a sufficiently complete, independently qualified
transaction order for all staged profiles. RufusArm64 therefore does not infer an
order from field names or from one third-party implementation.

## Correlation checks

`PlanSinglePhaseFullFlashWriteOrder` validates and correlates:

- the unchanged single-store-v1 descriptor-plan digest;
- the authenticated-integrity identifier;
- the exact target-plan digest;
- the full-flash validation-plan digest;
- catalog and hash-table SHA-256 identifiers;
- source size and payload geometry;
- target identity, capacity, block geometry, and mutation accounting; and
- every descriptor/location pair against exactly one resolved target extent.

Missing, duplicate, substituted, or extra target extents are rejected. Descriptor
indexes, location indexes, sequential payload offsets, block counts, target
ranges, and source ranges must remain exact. The resulting operations are bound
into a deterministic SHA-256 plan in declaration order rather than target-offset
order.

## Capability boundary

The planner is pure evidence construction. It:

- opens no source or target;
- exposes no descriptor;
- performs no read, write, seek, synchronization, ioctl, unmount, or privilege
  operation;
- does not consume the destructive confirmation capability; and
- leaves both `mutation_permitted` and `execution_supported` false.

A later provider tranche must separately bind the still-live authenticated source
lease, exclusive target session, exact confirmation capability, cancellation
state, first-mutation authorization, flush policy, readback verification, and
changed-media result reporting.

## Qualification scope

Synthetic tests cover deterministic declaration order, payload reuse, staged-GPT
refusal, incomplete final-table refusal, prerequisite substitution, and missing,
duplicate, or extra target extents. Focused race, static-analysis, Go 1.22, and
Linux ARM64 compilation checks are required in addition to the repository's full
CI and loop-device qualification suites.

This boundary makes no physical bootability or complete-device-health claim.
