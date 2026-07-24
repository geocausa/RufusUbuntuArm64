# FFU catalog cryptographic signature verification

Status: **read-only cryptographic verification only**. This document does not define certificate-chain trust, publisher authorization, target binding, or restoration execution.

Tracking issues: #269, #276, and #282

## Purpose

The preceding FFU integrity tranches establish three independent consistency links:

1. every covered source chunk matches the embedded SHA-256 table;
2. the supported `HashTable.blob` catalog member matches the complete embedded table;
3. the catalog exposes bounded certificate and SignerInfo metadata without claiming trust.

`internal/ffu.VerifyCatalogSignature` adds the next independent link: it verifies the signed attributes and mathematical PKCS#7 SignerInfo signature using exactly one embedded signer certificate.

A valid signature proves only that the catalog was signed by the private key corresponding to that embedded certificate. It does not establish that the certificate chains to a trusted root or represents an approved FFU publisher.

## Supported SignedData profile

The verifier requires:

- outer PKCS#7 SignedData OID `1.2.840.113549.1.7.2`;
- encapsulated Microsoft CTL content OID `1.3.6.1.4.1.311.10.1`;
- the CTL bytes carried as a DER OCTET STRING;
- at least one bounded embedded X.509 certificate;
- exactly one supported SignerInfo;
- the SignerInfo digest algorithm to be present in the SignedData digest-algorithm set;
- exactly one deterministic certificate match for the signer identifier.

Issuer-and-serial and subject-key-identifier signer forms are parsed independently. Missing, duplicate, ambiguous, malformed, or unsupported identifiers are refused.

## Signed attributes

The supported SignerInfo must contain signed attributes under the CMS implicit context-specific `[0]` field.

The verifier requires exactly one of each mandatory PKCS#9 attribute:

- content type `1.2.840.113549.1.9.3`, whose single value must be the Microsoft CTL OID;
- message digest `1.2.840.113549.1.9.4`, whose single value must be an OCTET STRING.

Duplicate mandatory attributes, missing attributes, empty values, unsupported multi-value forms, malformed DER, and a content-type mismatch are hard failures.

CMS signs the DER `SET OF` encoding of the attributes even though SignerInfo stores that same content under the implicit `[0]` tag. The verifier preserves the exact encoded length and attribute bytes and changes only the outer tag from context-specific `[0]` to universal SET before cryptographic verification. It does not reserialize the attributes from application-level values.

## Encapsulated-content digest

The SignerInfo digest algorithm is applied to the exact OCTET STRING contents representing the Microsoft CTL DER value.

The calculated digest must match the signed message-digest attribute in constant time before signature verification is attempted. A digest mismatch records deterministic evidence and returns with:

```text
content_digest_verified: false
signature_verification_attempted: false
cryptographic_signature_verified: false
```

The initial supported digest algorithms are explicit rather than inferred. Unknown OIDs or unsupported parameter encodings remain refusals.

## Signature verification

The verifier resolves the SignerInfo identifier against exactly one embedded certificate and invokes the Go X.509 implementation for the explicitly supported digest/signature combination.

The initial supported combinations are:

- RSA PKCS#1 v1.5 with SHA-256;
- RSA PKCS#1 v1.5 with explicitly declared legacy SHA-1;
- ECDSA with SHA-256;
- Ed25519 SignerInfo signatures with a SHA-256 content digest.

Unknown algorithms, mismatched digest/signature combinations, malformed parameters, wrong keys, altered signed attributes, or any signature mismatch are hard failures.

Legacy SHA-1 is accepted only when the catalog explicitly declares it. It is not used as a new trust primitive and cannot by itself make a publisher trusted.

## Trust-state separation

A successful cryptographic verification sets:

```text
content_digest_verified: true
signature_verification_attempted: true
cryptographic_signature_verified: true
```

It deliberately retains:

```text
certificate_chain_built: false
publisher_trusted: false
hash_table_catalog_authenticated: false
```

The final catalog-authentication state remains the conjunction of separate gates. A later tranche must define and satisfy all of the following before it can change:

- explicit root-store policy;
- deterministic chain construction;
- certificate validity time;
- key usage and extended key usage;
- revocation policy;
- timestamp policy;
- approved publisher identity policy.

A self-signed or attacker-supplied embedded certificate can produce a mathematically valid signature, which is why cryptographic validity alone cannot authorize restoration.

## Deterministic plan binding

The signature plan digest binds:

- source size;
- prior catalog-member plan digest;
- catalog and encapsulated-content SHA-256 fingerprints;
- content length and content-type OID;
- signer identifier and selected certificate fingerprints;
- digest and signature algorithm OIDs and names;
- exact signed-attributes SHA-256 and attribute OID list;
- encoded and calculated message digests;
- every verification and trust-state boolean.

The plan digest is a reproducibility and review identifier, not a signature or trust assertion.

## Safety boundary

This tranche accepts no target argument and performs no:

- host or bundled trust-store consultation;
- certificate-chain construction;
- revocation, timestamp, or online lookup;
- target identity or capacity binding;
- target-side validation descriptor execution;
- destination write, flush, or readback;
- regular-file, loop-device, or physical-device executor;
- release or hardware compatibility claim.

Restoration remains disabled.

## Acceptance coverage

Deterministic synthetic fixtures cover:

- successful Ed25519 signature verification;
- deterministic plan digests;
- wrong encapsulated-content digest;
- corrupted signature;
- a matching signer identifier with the wrong embedded public key;
- duplicate matching certificates;
- missing and duplicate mandatory signed attributes;
- unsupported signature algorithms;
- missing certificates;
- cancellation and nil context;
- fuzz no-panic signature-envelope parsing.

Complete exact-head CI, native ARM64 execution, static and vulnerability audit, reproducible packaging, and both existing privileged loop qualification suites remain mandatory before merge.
