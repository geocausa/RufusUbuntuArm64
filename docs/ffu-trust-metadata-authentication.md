# FFU trust-bundle metadata authentication

Status: **read-only threshold authentication of an inactive bundle**. This tranche does not publish a bundle, update rollback state, activate a root, build an Authenticode chain, trust a publisher, accept a target, or execute an FFU restore.

## Authorization boundary

`internal/ffu.AuthenticateTrustBundleMetadata` accepts three separate inputs:

1. the exact trust-bundle JSON bytes;
2. a strict signed metadata envelope;
3. an explicit caller-provisioned `TrustMetadataPolicy` containing only Ed25519 public keys.

The repository contains no production default key set and no private signing key. An empty policy is rejected. Test private keys exist only in `_test.go` fixtures and cannot become a production default.

Each public-key id is the lowercase SHA-256 of the 32-byte Ed25519 public key. Policies require a non-zero version, a valid threshold, sorted unique keys, canonical padded base64 verified by decode-and-reencode equality, and the supported `ed25519` algorithm. A deterministic policy SHA-256 covers the version, threshold, key ids, algorithms, and public-key encodings.

## Canonical signed payload

The envelope has two members:

- `signed`: the exact canonical JSON encoding of `TrustMetadataDocument`;
- `signatures`: a sorted list of key id, algorithm, and strict base64 signature.

The signed document binds:

- schema and purpose;
- trust-bundle sequence;
- key-set version, policy SHA-256, and threshold;
- canonical UTC generation and expiry times;
- exact bundle byte length and SHA-256.

Canonical JSON is the compact `encoding/json` struct encoding in declared field order. Whitespace, reordered members, duplicate object members, unknown members, multiple JSON values, or alternate encodings are refused rather than normalized before signature verification.

## Verification order

The verifier:

1. validates the caller-provisioned policy and rollback evidence;
2. parses bounded metadata and requires canonical signed bytes;
3. checks metadata policy binding and validity times;
4. hashes the exact bundle bytes and compares size and SHA-256;
5. verifies sorted, distinct Ed25519 signatures and the required threshold;
6. refuses sequence decrease and same-sequence reuse with different bytes;
7. structurally validates the already-authenticated bundle and its root/distrust entries;
8. returns a deterministic `TrustBundlePlan` with authentication evidence.

`bundle_signature_authenticated` becomes true only after the threshold succeeds. `trust_anchors_activated`, `certificate_chain_built`, and `publisher_trusted` remain false.

## Resource limits

- trust bundle: existing 4 MiB limit;
- metadata envelope: 256 KiB;
- policy keys: 32;
- envelope signatures: 64;
- JSON nesting: 16 levels;
- metadata lifetime: 366 days.

Unknown algorithms, invalid key ids, duplicate keys/signatures, unknown signing keys, malformed or noncanonical base64, insufficient threshold, altered bundle bytes, policy mismatch, expiry, rollback, and sequence reuse are hard failures.

## Deferred work

Issue #288 delivery B and later stages remain separate:

- descriptor-bound persistent rollback state;
- synchronized no-replace publication and recovery;
- path-to-descriptor revalidation;
- root addition/removal and emergency distrust transactions;
- offline import/update UX;
- trust-anchor activation;
- Authenticode chain construction and publisher policy.
