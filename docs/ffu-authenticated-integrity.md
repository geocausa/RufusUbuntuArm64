# FFU authenticated source-integrity boundary

Status: **read-only source authentication only**. This boundary does not accept a target, write a disk, enable an executor, or claim physical bootability.

Tracking issues: #269, #277, #284, and #289

## Plain-language purpose

Earlier Stage 3 tranches established these facts independently:

1. the FFU contains a structurally valid SHA-256 chunk table;
2. every covered source chunk can be compared with that table;
3. the Windows catalog contains exactly one supported `HashTable.blob` member matching the complete table;
4. the catalog signature is mathematically valid;
5. the signer builds to an explicitly activated Authenticode root;
6. an explicit caller-supplied policy approves the signer identity under that exact root.

This tranche joins those facts without weakening their separate gates.

A successful result means:

> the approved publisher signed the catalog member that authenticates this exact hash table, and every covered FFU source chunk matches that table.

It does not mean that restoration is enabled.

## Catalog authentication

`AuthenticateCatalogHashTable` re-runs the complete catalog-member, SignerInfo, certificate-chain, activation-capability, and publisher-policy pipeline.

The function requires agreement on:

- source size;
- exact catalog SHA-256;
- exact hash-table SHA-256 and length;
- the supported `HashTable.blob` member;
- successful cryptographic signature verification;
- one explicit-root code-signing certificate path; and
- one unambiguous explicit publisher-policy match.

Only after all of those checks succeed does `hash_table_catalog_authenticated` become true.

The legacy SHA-1 value encoded by the supported Windows catalog member remains confined to catalog-to-table consistency. Certificate, policy, plan, catalog, and table identities continue to use SHA-256.

## Complete source authentication

`AuthenticateSingleStoreV1Integrity` additionally:

- re-plans the bounded single-store-v1 descriptor map;
- re-runs complete SHA-256 source-chunk comparison;
- requires the catalog-authentication and content-verification passes to agree on catalog and hash-table geometry and digests;
- requires every expected chunk to be verified;
- preserves the defined zero-filled final partial-chunk rule; and
- binds all preceding deterministic plan digests into one authenticated-integrity plan.

A successful plan sets:

```text
hash_table_catalog_authenticated: true
content_matches_hash_table: true
integrity_authenticated: true
```

## Evidence chain

The catalog-authentication plan binds:

- hash-table structural plan SHA-256;
- catalog-member plan SHA-256;
- catalog-signature plan SHA-256;
- certificate-chain plan SHA-256;
- publisher-authorization plan SHA-256;
- exact catalog and hash-table SHA-256 values;
- hash-entry count; and
- every completed or deliberately incomplete policy state.

The authenticated-integrity plan additionally binds:

- descriptor-plan SHA-256;
- final authenticated hash-table plan SHA-256;
- catalog-authentication plan SHA-256;
- content-verification SHA-256;
- source coverage and chunk geometry; and
- exact verified-chunk accounting.

## Deliberate remaining boundaries

A successful source-authentication result still reports:

```text
revocation_checked: false
timestamp_verified: false
execution_supported: false
```

No host TLS store is consulted and no network request is performed. The certificate path is evaluated at the explicit caller-supplied policy time without substituting an unverified signing timestamp.

The result does not perform or authorize:

- target enumeration or selection;
- target identity, capacity, sector-size, or end-relative binding;
- destructive confirmation;
- destination validation;
- regular-file, loop-device, or physical-device writes;
- flush or readback verification;
- FFU provider execution;
- GTK exposure; or
- physical-device or boot qualification claims.

## Next practical gate

The next safe tranche may use this immutable read-only evidence to define an identity-bound restore plan for an exact target. The executor must remain absent until target geometry, end-relative descriptor resolution, confirmation, cancellation, changed-media handling, write ordering, flush, readback scope, loop qualification, and native ARM64 evidence are complete.

## Acceptance coverage

Synthetic deterministic fixtures cover:

- exact certificate and SPKI publisher policies;
- complete catalog-to-table authentication;
- complete source-chunk authentication;
- deterministic linked evidence;
- unapproved publisher refusal;
- changed source-content refusal;
- cancelled and nil contexts;
- catalog/content hash-plan disagreement; and
- a permanent source contract forbidding host-store, network, target, write, revocation/timestamp-success, and executor primitives.

Complete exact-head Go 1.22 CI, native ARM64 execution, static and vulnerability audit, reproducible packaging, and both existing loop qualification suites remain mandatory before merge.
