# FFU single-store v1 descriptor plan

Status: **read-only planning only**. This document does not define or authorize an executor.

Tracking issue: #269  
+Planner PR: #275

## Supported layout

`internal/ffu.PlanSingleStoreV1` accepts only FFU store-header version `1.0`.

Multiple independent implementations agree that this legacy single-store layout places the validation descriptor table immediately after the 248-byte common store header, followed by the write descriptor table and a chunk-aligned payload. Store versions greater than `1.0` can append additional fixed or variable metadata and remain a hard refusal.

The common-prefix inspector remains available for newer layouts, but it reports descriptor and payload locations as unresolved.

## Input and source identity

The development command `rufus-ffu-plan`:

- accepts only `--image` and optional `--json`;
- uses the repository's regular-source identity inspection and replacement protection;
- has no target argument;
- opens the source read-only;
- returns an error for store layouts other than version `1.0`.

The plan records source file size, security chunk size and store block size. These values, every resolved table and payload boundary, every parsed descriptor and location, the payload GPT-table ranges and overlap evidence are bound into a deterministic plan SHA-256.

The plan digest is a reproducibility and review identifier. It is **not** a signature and does not authenticate the FFU security catalog or hash table.

## Validation descriptors

Each validation descriptor contains:

- sector index;
- byte offset within the referenced sector context;
- comparison byte count;
- source-table offset;
- comparison-data offset;
- SHA-256 of the comparison bytes.

Comparison bytes are not retained in the plan. Zero-length records, table overrun and unconsumed declared table bytes are rejected.

The planner does not apply validation descriptors to any destination. Their target-side semantics remain part of the future identity-bound execution design.

## Write descriptors and payload

Each write descriptor contains a block count and one or more destination location expressions. The payload is sequential: one payload extent is consumed for each descriptor, while multiple destination locations reuse that descriptor's same payload bytes.

Only the independently observed disk access methods are accepted:

- `0`: block index measured from the beginning of the future target;
- `2`: block index measured backwards from the end of the future target.

Unknown access methods, zero locations, zero block counts, arithmetic overflow, descriptor-table overrun, unconsumed table bytes and payload truncation are hard refusals.

The payload offset is the write-table end rounded up to the FFU security chunk size. Total payload bytes are the sum of descriptor block counts multiplied by the store block size. Trailing source bytes are reported but not interpreted.

## GPT table payload ranges

The initial, flash-only and final GPT table fields are ranges in the sequential payload. For a supported v1 plan, every non-empty range must end at or before the parsed total payload block count.

These fields do not identify write descriptors and are never compared with descriptor count.

## Destination expressions and minimum target surface

The read-only plan does not bind a target. It records beginning-anchored and end-anchored block expressions separately.

A conservative minimum target block count is:

- the greatest end block of all beginning-anchored locations;
- plus the greatest end-relative block extent of all end-anchored locations.

This ensures the two anchor regions can be separated on a later target. A future target binder must still verify exact byte ranges, target sector geometry, capacity, source/target identities, target-specific cross-anchor overlap and every validation operation.

Same-anchor overlaps are deterministic without a target size and are reported in the plan. Their presence never enables execution; the current plan always reports `execution_supported: false`.

## Resource limits

Read-only planning refuses inputs exceeding the current defensive limits:

- 262,144 validation or write descriptors;
- 1,048,576 destination locations;
- 256 MiB for either declared descriptor table.

These are parser resource limits, not FFU format limits or compatibility claims.

## Explicitly unresolved

The planner does not yet provide:

- signed catalog validation;
- chunk hash-table validation;
- target identity or size binding;
- conversion of end-relative expressions into target byte offsets;
- target-side validation descriptor checks;
- destination writes, flush or readback;
- split SFU support;
- optimized/resizable FFU semantics;
- multi-store layouts;
- FFU capture;
- physical boot qualification.

No regular-file, loop-device or physical-device executor exists in this tranche.
