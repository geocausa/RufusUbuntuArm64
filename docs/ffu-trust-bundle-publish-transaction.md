# FFU signed trust-bundle publish transaction

This tranche executes an already authenticated `publish` operation from the
FFU trust-bundle update planner. It deliberately does not execute withdrawal,
activate roots, construct certificate chains, trust publishers, consult the
host TLS store, access targets, or perform network requests.

## Transaction boundary

`ApplyAuthenticatedTrustBundlePublishOperation` opens and exclusively locks the
trust-store root, then keeps the same descriptor identities alive while it:

1. reproduces the current active generation at its authenticated publication
   time;
2. verifies the canonical signed operation against the current policy and,
   during rotation, the replacement policy as well;
3. authenticates the exact candidate bundle and metadata under the replacement
   policy;
4. publishes a private `0500` generation containing three `0400` files;
5. atomically exchanges `active.json`, the single commit point;
6. replays the newly committed generation from durable evidence before removing
   the previous active-record temporary.

A failure before final verification restores the previous active record and
removes only a generation created by the failed transaction.

## Durable update evidence

The generation still contains only `bundle.json`, `metadata.json`, and
`evidence.json`. Update evidence additionally binds and embeds canonical padded
base64 copies of:

- the exact signed update-operation envelope;
- the current public authorization policy;
- the replacement public authorization policy.

It also records their sizes and SHA-256 digests, the read-only update-plan
digest, current and replacement signer IDs, and the complete previous active
record. The evidence remains bounded to 1 MiB.

Recovery validates canonical JSON and base64, all byte sizes and digests, the
previous active record, policy versions and thresholds, and then recursively
replays earlier immutable generations. History must move strictly backwards in
sequence and is capped by the existing 256-generation limit.

Legacy three-file generations remain readable. A signed-update generation is
accepted only when the caller-provided policy exactly equals the embedded
replacement policy.

## Exclusions

Withdrawal is not represented by deleting `active.json`. A later tranche must
define and test a durable signed tombstone/withdrawal commit point. Published
roots remain inactive throughout this transaction.
