# FFU catalog publisher authorization policy

This tranche adds the publisher-identity gate after the catalog member,
SignerInfo signature, and explicit-root Authenticode certificate chain have all
succeeded. It still does not authenticate the catalog hash table or authorize
restoration.

## Explicit policy only

`AuthorizeCatalogPublisher` accepts a caller-supplied,
versioned `ffu-catalog-publisher-policy`. The package contains no production
publisher allowlist and does not treat every signer chaining to an activated
root as an approved FFU publisher.

A policy records:

- a canonical policy id and non-zero version;
- canonical UTC generation and expiry times;
- one or more strictly sorted authorization rules; and
- an exact activated root id and root certificate SHA-256 for every rule.

The policy is evaluated at the same explicit UTC policy time used for
certificate-chain construction. Expired, not-yet-valid, noncanonical, empty,
oversized, unsorted, duplicate-selector, or unsupported policies are rejected.

This is the clearly disclosed operator-provided path required by the roadmap.
The caller remains responsible for provisioning the policy. A future signed
publisher-policy publication mechanism can wrap this exact deterministic policy
without weakening the authorization boundary.

## Publisher identities

Each rule selects one of two stable pin types:

1. `certificate_sha256` pins the complete DER signer certificate; or
2. `subject_public_key_info_sha256` pins the signer public key material and can
   survive certificate reissuance using the same key.

Both forms must also match the exact activated root id and root certificate
fingerprint selected by certificate-chain construction. Subject or issuer text
is reported as evidence but is never used as a security selector.

A successful authorization requires exactly one matching rule. Zero matches are
untrusted. Multiple overlapping matches, including simultaneous certificate and
SPKI rules, are rejected as ambiguous rather than resolved by order.

## Revalidation and evidence

The API re-runs the complete catalog-signature and certificate-chain gates,
re-reads the catalog, and rejects any change before publisher authorization. It
then records deterministic evidence binding:

- the updated catalog-signature and certificate-chain plan digests;
- the exact catalog SHA-256;
- policy id, version, validity time and policy SHA-256;
- matched rule id, identity kind and fingerprint;
- signer certificate and SubjectPublicKeyInfo SHA-256 fingerprints;
- signer subject and issuer for operator reporting; and
- the selected activated root id and fingerprint.

Only `publisher_trusted` becomes true. The catalog remains unauthenticated
because revocation, trusted timestamp, and hash-table authentication are still
separate gates.

## Preserved boundaries

The implementation does not:

- consult the host TLS certificate store;
- accept an embedded self-signed root;
- contain a default Microsoft, OEM, or test publisher policy;
- perform OCSP, CRL, timestamp, or network work;
- accept a target path or device;
- write, flush, read back, mount, or open a loop device; or
- expose an FFU image executor.

Real Microsoft- and OEM-produced catalog evidence remains required before any
trusted-restoration claim.
