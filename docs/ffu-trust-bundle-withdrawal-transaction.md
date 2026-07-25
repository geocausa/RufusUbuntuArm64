# FFU signed trust-bundle withdrawal transaction

This tranche executes an authenticated `withdraw` operation without deleting
`active.json` or any immutable bundle generation. It deliberately does not
activate roots, construct certificate chains, trust publishers, consult the
host TLS store, access targets, or perform network requests.

## Durable tombstone

`ApplyAuthenticatedTrustBundleWithdrawalOperation` keeps the trust-store root
locked while it replays the current signed history, authenticates the exact
withdrawal operation, and writes a sealed tombstone generation. The tombstone
copies the current `bundle.json` and `metadata.json` bytes and adds bounded
withdrawal evidence containing:

- the exact signed withdrawal envelope;
- the unchanged current and next public authorization policies;
- current-threshold signer IDs;
- the complete previous active record;
- the deterministic read-only withdrawal-plan digest; and
- the prior authentication and distrust evidence.

The new `active.json` uses purpose `ffu-trust-bundle-withdrawn`. Its atomic
exchange is the single commit point. Historical generations remain immutable,
and rollback restores the previous active record after every injected failure
stage.

## Recovery and activation behavior

`RecoverAuthenticatedTrustBundleWithdrawal` verifies and reports the tombstone,
including the preserved distrust set. Ordinary bundle recovery and explicit
root activation first verify the complete tombstone history and then fail with
`ErrTrustBundleWithdrawn`; a withdrawal is never treated as an absent bundle or
an active trust source.

Signed publish/withdraw history replay is bounded by the existing 256-generation
limit. A later re-enrollment design must be separately authenticated and cannot
silently overwrite the tombstone semantics introduced here.
