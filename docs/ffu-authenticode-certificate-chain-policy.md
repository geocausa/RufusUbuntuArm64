# FFU Authenticode certificate-chain policy

This tranche builds the first trusted certificate path for an FFU catalog after
all earlier read-only gates have already succeeded. It does not approve a
publisher and does not authenticate the catalog or FFU for restoration.

## Inputs and trust source

`BuildCatalogCertificateChain` accepts the FFU reader and size, an explicit
policy evaluation time, and the in-process result of
`ActivateAuthenticatedTrustBundle`.

The activation result carries an unexported immutable capability seal set only
after the activation API has revalidated the descriptor-bound durable
generation. The seal retains the original activation digest, so a copied
activation cannot be modified and re-digested by a caller. Filling public JSON
fields or replaying a serialized plan produces no usable capability.

Only the exact DER roots in that activated bundle are added to a new certificate
pool. The host TLS store, PEM files, environment variables, and network are not
consulted.

## Deterministic path policy

The implementation re-runs catalog member and SignerInfo verification, re-reads
the catalog bytes, and rejects any change between signature and chain planning.
It then:

1. rejects duplicate embedded certificates;
2. resolves the same exact signer certificate already bound into the signature
   plan;
3. requires a non-CA signer with digital-signature key usage and an explicit
   code-signing extended key usage;
4. evaluates every certificate at the caller-provided UTC policy time;
5. permits RSA keys of at least 2048 bits, elliptic-curve keys of at least 256
   bits, and Ed25519 keys;
6. rejects legacy or unsupported certificate signature algorithms, including
   SHA-1;
7. enforces CA Basic Constraints, certificate-signing key usage, path-length
   constraints, critical-extension handling, and certificate signatures;
8. rejects any selected certificate listed by the activated distrust policy;
9. requires the path to terminate at one exact activated root; and
10. rejects the catalog when more than one distinct policy-valid path exists.

Missing EKU is not accepted as a legacy code-signing profile in this tranche.
A future compatibility profile would require an explicit, versioned policy
change and its own evidence.

## Result and remaining false states

A successful plan records the complete leaf-to-root path, exact SHA-256
fingerprints, subjects, issuers, serial numbers, validity intervals, algorithms,
embedded indexes, selected root ID, activation digest, evaluation time, and a
deterministic plan digest.

Only `certificate_chain_built` becomes true. The following remain false:

- `publisher_trusted`;
- `hash_table_catalog_authenticated`;
- `revocation_checked`;
- `timestamp_verified`; and
- `host_tls_store_consulted`.

Offline revocation status is therefore unknown, not successful. No target path,
network retrieval, write, flush, readback, loop device, physical device, or
image executor is introduced.
