# FFU signed trust-bundle update planning

This stage defines the review boundary for offline FFU trust-bundle changes. It authenticates a signed operation, verifies the exact candidate bytes when publishing, and reports the complete root, distrust, withdrawal, and authorization-policy delta. It does not change the durable trust store.

## Signed operation

The canonical `signed` payload identifies:

- schema `1` and purpose `ffu-trust-bundle-operation`;
- a strictly increasing operation sequence;
- action `publish` or `withdraw`;
- canonical generation and expiry times;
- the exact current active generation, bundle sequence and SHA-256, metadata-envelope SHA-256, generation-evidence SHA-256, and publication-plan SHA-256;
- the current authorization-policy version, canonical digest, and threshold;
- the proposed next authorization-policy version, canonical digest, and threshold;
- for `publish`, the exact candidate bundle and metadata-envelope sizes and SHA-256 values.

Signatures use self-authenticating Ed25519 key IDs and canonical padded base64. Every supplied signature must be sorted, distinct, authorized by the current or replacement policy, canonical, and valid.

## Authorization rules

Every operation must satisfy the current policy threshold. When policy content changes, the replacement version must advance exactly by one and the same operation payload must also satisfy the replacement policy's own threshold. This mirrors the repository's existing dual-authorization root-rotation rule: the old authority approves relinquishing control and the new authority proves possession before taking control.

A publish candidate is independently authenticated under the proposed next policy. Its sequence must equal the operation sequence and exceed the durable current sequence. The candidate metadata is checked against the current rollback state. Candidate bundle and metadata generation times may not regress behind the currently published material.

Withdrawal carries no candidate bundle or metadata. It removes every active root while preserving the current distrust set for the later tombstone transaction. Policy rotation is intentionally refused during withdrawal; rotation must accompany a fully authenticated replacement publication.

## Expired current metadata

Expiry cannot permanently lock operators out of recovery. The current immutable generation is reproduced using its authenticated publication evaluation time and durable evidence. The new signed operation and any candidate are still evaluated at the caller's current explicit time. The plan reports when current metadata is expired.

This historical verification is only sufficient to authorize replacement or withdrawal. It does not reactivate expired roots or make any certificate or publisher trusted.

## Delta report

The deterministic plan reports:

- added and removed root IDs and fingerprints;
- same-ID certificate replacements;
- added and removed distrust fingerprints;
- emergency distrust where a certificate that was previously an active root is absent from the candidate roots and explicitly blocked;
- current and proposed authorization policy evidence and the signing key IDs satisfying each threshold;
- candidate authentication, expiry, and plan digests;
- exact operation payload and envelope digests.

## Deliberate boundaries

Planning preserves the active record and every immutable generation. It does not publish, withdraw, update rollback state, activate roots, consult the host TLS store, build a certificate chain, trust a publisher, perform revocation or timestamp validation, access a target, make a network request, or execute an FFU operation.

A later transaction may consume only the exact authenticated plan and byte digests produced here. It must revalidate the active record and descriptors before committing any change.
