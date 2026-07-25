# FFU signed trust-bundle withdrawal tombstone transaction

This transaction executes an already authenticated `withdraw` operation from
the FFU trust-bundle update planner. It does not delete the active record or any
historical bundle. It commits an explicit, durable withdrawn state and keeps
trust-anchor activation, certificate-chain construction, publisher trust, host
TLS fallback, networking, target access, and image execution outside the
boundary.

## Commit model

`ApplyAuthenticatedTrustBundleWithdrawalOperation` opens and exclusively locks
the trust-store root, then keeps the same descriptor identities alive while it:

1. reproduces the complete current signed publication history;
2. verifies the canonical withdrawal operation under the unchanged current
   authorization policy;
3. reopens the exact active generation and copies its byte-identical bundle and
   metadata into a new immutable tombstone generation;
4. writes canonical evidence containing the exact operation and public policy;
5. publishes the generation with no-replace semantics and directory `fsync`;
6. atomically exchanges `active.json`, the single commit point; and
7. replays the newly committed withdrawal generation before final cleanup.

Every failure before final verification restores the previous active record and
removes only a generation created by the failed transaction.

## Durable tombstone evidence

The tombstone generation remains a sealed `0500` directory containing three
`0400` regular files: `bundle.json`, `metadata.json`, and `evidence.json`. The
first two preserve the exact historical bytes instead of erasing the basis for
past trust decisions. The evidence binds:

- the exact signed withdrawal envelope;
- the unchanged current and replacement public authorization policies;
- the read-only authorization-plan digest and signer IDs;
- the previous active record and its immutable generation; and
- the historical bundle, metadata, authentication, and publication-plan
  digests.

Recovery recursively verifies the full signed publish/withdraw history with the
existing 256-generation bound. The caller-provided policy must exactly match the
policy embedded in the tombstone evidence.

## Fail-closed state

A withdrawn active record cannot be activated, withdrawn again, or replaced by
the older direct publication API. A later higher-sequence `publish` operation
may supersede it only after the normal signed planner authenticates the exact
tombstone state, candidate bytes, and unchanged or deliberately rotated public
authorization policy. The succeeding generation records that its predecessor
was withdrawn, so recovery still replays the complete history.
