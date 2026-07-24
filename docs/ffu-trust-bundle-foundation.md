# FFU Authenticode trust-bundle foundation

Status: **read-only trust-metadata structure only**. The bundle parser does not authenticate the bundle publisher, activate roots, build a certificate chain, trust an FFU publisher, bind a target, or authorize restoration.

Tracking issues: #269, #276, and #284

## Why a separate trust bundle is required

A mathematically valid PKCS#7 signature proves only that the catalog was signed by the private key corresponding to its embedded certificate. It does not establish that the certificate chains to a root accepted by Windows Authenticode policy or belongs to an approved Microsoft or OEM FFU publisher.

The generic Linux TLS CA store is not silently treated as an Authenticode policy source. TLS server authentication and Windows code-signing trust have different policy, update, distrust, usage, and publisher boundaries.

The first trust-policy tranche therefore defines a separate, explicit, offline bundle contract before any root is allowed to participate in FFU chain construction.

## External JSON contract

The strict document contains:

```json
{
  "schema": 1,
  "purpose": "ffu-authenticode",
  "sequence": 1,
  "generated_at": "2026-07-01T00:00:00Z",
  "expires_at": "2027-07-01T00:00:00Z",
  "roots": [
    {
      "id": "example.root",
      "certificate_der_base64": "...",
      "certificate_sha256": "..."
    }
  ],
  "distrusted_sha256": []
}
```

The parser rejects unknown fields, multiple JSON values, unsupported schema or purpose, noncanonical timestamps, zero sequence numbers, rollback below the caller-provided floor, future or expired bundles, empty root sets, and resource-limit violations.

Current defensive limits are:

- 4 MiB bundle bytes;
- 64 root certificates;
- 4,096 explicit distrust fingerprints;
- 64 KiB DER per root certificate.

These are parser resource limits, not compatibility claims.

## Rollback and validity

The caller supplies:

- a minimum accepted sequence derived from persistent rollback state;
- an explicit evaluation time.

A bundle is refused when its sequence is below the rollback floor, when evaluation occurs before `generated_at`, or when evaluation is at or after `expires_at`.

The parser does not itself persist rollback state. A later signed-publication integration must update rollback state transactionally only after the bundle signature, policy, and durable publication gates succeed.

## Root validation

Each root entry requires:

- a restricted stable identifier using lowercase letters, digits, `.`, `_`, or `-`;
- strict standard base64 DER;
- an independently recorded lowercase SHA-256 fingerprint matching the exact DER;
- one parseable X.509 certificate;
- valid CA Basic Constraints;
- certificate-signing key usage;
- identical subject and issuer encodings;
- a valid self-signature;
- a nonempty validity interval.

Duplicate root identifiers and duplicate root certificates are refused. Roots are normalized by identifier and fingerprint for deterministic reporting.

Certificate validity at the current wall clock is not used to decide whether a root may appear in the bundle. Historical Authenticode verification may later evaluate a signer at a trusted timestamp. The root metadata records its validity interval, while chain and timestamp policy remain separate gates.

## Explicit distrust

The bundle carries a sorted, duplicate-free list of lowercase SHA-256 certificate fingerprints.

A certificate cannot appear simultaneously as an active root candidate and an explicit distrust entry. The parser rejects that ambiguous state.

The initial contract does not yet define intermediate or publisher-level distrust semantics; those remain part of chain and publisher policy.

## Deterministic plan

The plan records:

- schema, purpose, sequence, rollback floor, generation, expiry, and evaluation time;
- exact bundle SHA-256;
- normalized root metadata and SHA-256 fingerprints;
- normalized distrust fingerprints;
- every activation and trust-state boolean;
- a deterministic plan SHA-256.

The exact bundle fingerprint is included so two byte-distinct documents cannot silently share a plan identity even when their semantic fields are similar.

## Trust-state separation

A structurally valid bundle sets only:

```text
bundle_structure_validated: true
```

It deliberately retains:

```text
bundle_signature_authenticated: false
trust_anchors_activated: false
host_tls_store_consulted: false
certificate_chain_built: false
publisher_trusted: false
```

No root is usable merely because it appears in valid JSON or carries a self-signature. A self-signature proves key possession, not authorization to become a RufusArm64 FFU trust anchor.

## Required next gate

Before roots can be activated, the bundle must be authenticated through a separately reviewed signed metadata policy with:

- explicit offline verification keys or threshold roots;
- versioned key rotation and expiry;
- rollback prevention;
- durable no-replace publication;
- emergency distrust and bundle withdrawal;
- reproducible source and generation evidence;
- no private signing key in source, packages, CI, or artifacts.

The repository's existing signed acquisition-channel foundations may be reusable, but FFU trust metadata requires an independently reviewed policy and cannot inherit production trust accidentally.

## Safety boundary

This tranche performs no:

- built-in root provisioning;
- host TLS-store consultation;
- bundle signature verification;
- root activation;
- certificate-chain construction;
- publisher identity decision;
- online revocation or timestamp lookup;
- target identity or capacity binding;
- destination validation, write, flush, or readback;
- regular-file, loop-device, or physical-device executor.

Restoration remains disabled.

## Acceptance coverage

Synthetic deterministic fixtures cover:

- valid Microsoft/OEM-style root entries;
- normalized root ordering and deterministic plan digests;
- rollback, future, and expired bundles;
- strict unknown/trailing JSON refusal;
- unsupported purpose, zero sequence, and noncanonical timestamps;
- empty roots;
- wrong fingerprints;
- duplicate identifiers and certificates;
- non-CA certificates;
- trust/distrust collisions;
- nil, zero-time, and oversized inputs;
- fuzz no-panic parsing.

Complete exact-head CI, native ARM64 execution, static and vulnerability audit, reproducible packaging, and both existing privileged loop qualification suites remain mandatory before merge.
