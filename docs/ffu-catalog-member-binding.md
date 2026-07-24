# FFU catalog member binding

Status: **read-only catalog-to-hash-table consistency only**. This document does not define publisher trust, target binding, or restoration execution.

Tracking issues: #269, #276, and #280  
Implementation PR: #281

## Purpose

The FFU security region contains two related objects:

1. a Windows catalog encoded as PKCS#7 SignedData with Microsoft CTL content;
2. the FFU chunk hash table used to validate source content.

The previous integrity tranches establish that:

- the hash table has an explicitly supported SHA-256 shape;
- every covered source chunk matches its corresponding embedded table entry.

`internal/ffu.PlanCatalogMember` adds the next independent link: it proves that the supported `HashTable.blob` catalog member identifies the exact complete embedded hash table.

That result is **catalog-to-table consistency**, not publisher authentication.

## Bounded catalog structure

The parser accepts only the supported DER structure:

- outer PKCS#7 SignedData OID `1.2.840.113549.1.7.2`;
- encapsulated Microsoft CTL OID `1.3.6.1.4.1.311.10.1`;
- one bounded CTL member list;
- bounded certificate and SignerInfo sets.

It rejects:

- BER indefinite lengths;
- high-tag-number form;
- non-minimal DER lengths and integers;
- arithmetic overflow and truncation;
- trailing bytes after the outer ContentInfo;
- unsupported or duplicate structural fields;
- oversized catalogs, member lists, attribute sets, certificate sets, and signer sets.

The current defensive limits are:

- 16 MiB catalog bytes;
- 4,096 DER values;
- 1,024 catalog members;
- 128 attributes per bounded attribute set;
- 32 embedded certificates;
- 8 signer records.

The parser follows a fixed supported schema rather than recursively interpreting arbitrary ASN.1 values. Unknown structures remain fail-closed.

## Supported catalog member

The supported member must contain:

- catalog name/value attribute OID `1.3.6.1.4.1.311.12.2.1`;
- plain UTF-16LE name `HashTable.blob`;
- exactly one `SPC_INDIRECT_DATA_CONTENT` attribute OID `1.3.6.1.4.1.311.2.1.4`;
- SHA-1 digest algorithm OID `1.3.14.3.2.26`;
- exactly 20 digest bytes.

Missing, duplicate, malformed, base64-name, unsupported-algorithm, or wrong-length members are refused.

The complete embedded FFU hash-table region is streamed through SHA-1 with a bounded 64 KiB buffer and compared with the encoded member digest in constant time.

SHA-1 is used here only because the supported Windows catalog member explicitly encodes that legacy digest. It is not introduced as a new trust primitive. SHA-256 remains the format used for the catalog fingerprint, hash-table fingerprint, certificate fingerprints, and deterministic plan digest.

## Certificate and signer metadata

The parser reports embedded certificate metadata:

- subject and issuer;
- serial number;
- SHA-256 fingerprint;
- validity window;
- public-key algorithm;
- certificate signature algorithm.

It also reports bounded SignerInfo metadata:

- signer identifier form and deterministic fingerprint;
- digest algorithm OID;
- signature algorithm OID;
- signed-attribute OIDs.

These records describe what the catalog contains. An embedded certificate is not trusted merely because it parses successfully.

## Explicit trust states

A successful member comparison sets:

```text
signature_structure_parsed: true
hash_table_member_matches: true
```

It deliberately retains:

```text
cryptographic_signature_verified: false
certificate_chain_built: false
publisher_trusted: false
hash_table_catalog_authenticated: false
```

The final authentication state cannot become true until separate future gates have all succeeded:

1. cryptographic verification of the PKCS#7 signature and signed attributes;
2. deterministic signer-to-certificate resolution;
3. certificate-chain construction under an explicit root policy;
4. validity, usage, revocation, and timestamp policy;
5. an explicit decision about which publisher identities are trusted for FFU restoration.

Parsing, member matching, or a self-signed certificate alone cannot satisfy those gates.

## Deterministic plan binding

The catalog-member plan digest binds:

- source size and catalog boundaries;
- catalog and hash-table SHA-256 fingerprints;
- PKCS#7 and CTL content-type OIDs;
- member count, name, digest algorithm, encoded digest, and calculated digest;
- every explicit trust-state boolean;
- embedded certificate metadata;
- signer metadata and signed-attribute OIDs.

The plan digest is a reproducibility and review identifier, not a signature.

## Safety boundary

This tranche accepts no target argument and performs no:

- target identity or capacity binding;
- end-relative destination resolution;
- target-side validation descriptor execution;
- regular-file, loop-device, or physical-device restoration;
- destination write, flush, or readback;
- release or hardware compatibility claim.

The existing descriptor and source-content plans remain read-only, and restoration remains disabled.

## Conformance evidence

The supported member model is consistent with:

- Microsoft's recovered FFU imaging implementation, which creates a member named `HashTable.blob` and compares its encoded SHA-1 digest with SHA-1 of the complete hash table;
- Microsoft's catalog and `WINTRUST_CATALOG_INFO` documentation, which keeps catalog-member matching distinct from catalog-signature trust;
- the Windows catalog structures implemented by osslsigncode.

References:

- https://github.com/Empyreal96/WP_Common_Tools/blob/e8428c1c9fdec80006ecfffdb39f21d57f18c3d9/src/imagecommon/Microsoft.WindowsPhone.Imaging/ImageSigner.cs
- https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_catalog_info
- https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-spc_indirect_data_content
- https://learn.microsoft.com/en-us/windows/win32/api/mscat/ns-mscat-cryptcatmember
- https://learn.microsoft.com/en-us/windows-hardware/drivers/install/catalog-files
- https://github.com/mtrojnar/osslsigncode/blob/edad27d59b176a7027377d288ef23284fec3f747/cat.c

These sources are conformance evidence for the narrow supported contract. Unknown catalog layouts remain refusals rather than compatibility guesses.

## Acceptance gates

Focused synthetic fixtures cover:

- valid member, certificate, and signer metadata;
- deterministic plan digests;
- wrong hash-table digest;
- missing and duplicate members;
- unsupported member-digest algorithm;
- malformed and trailing DER;
- cancellation and nil context;
- bounded catalog reads;
- fuzz no-panic parsing.

Complete exact-head CI, native ARM64 execution, static and vulnerability audit, reproducible packaging, and both existing privileged loop qualification suites remain mandatory before merge.
