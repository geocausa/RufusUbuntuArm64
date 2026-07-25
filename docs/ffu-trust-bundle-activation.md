# FFU authenticated trust-bundle activation

This stage crosses only the explicit trust-anchor activation boundary for a trust bundle that has already passed threshold authentication and durable descriptor-bound publication.

## Activation input

`ActivateAuthenticatedTrustBundle` accepts only:

- a descriptor-safe trust-store root;
- the complete caller-provisioned metadata public-key policy;
- an explicit evaluation time; and
- a context.

It does not accept bundle JSON, metadata JSON, root certificates, a host certificate store, a target, or a network location. Operator-selected unsigned JSON therefore has no path into activation.

## Required proof

Activation opens and exclusively locks the trust-store root, validates exact entry spelling and modes, recovers the active record, and reproduces the signed publication evidence. It then reopens the active immutable generation through `openat`/`O_NOFOLLOW`, reads the exact `bundle.json` regular file, verifies its descriptor and digest against the active record and authenticated plan, rejects duplicate JSON members, and extracts canonical padded-base64 DER roots.

The returned evidence binds three distinct plan states:

- `publication_plan_sha256`: the historical inactive plan committed in `active.json`;
- `pre_activation_plan_sha256`: the freshly re-evaluated inactive plan at activation time; and
- `activated_plan_sha256`: the same plan after only `trust_anchors_activated` changes to true.

`activation_sha256` also binds the active generation, sequence, bundle digest, exact root DER bytes, distrust fingerprints, metadata policy evidence, threshold, signing key identifiers, and activation time.

## Deliberate boundaries

Activation returns independent copies of the exact root DER bytes and distrust fingerprints. It does not create an `x509.CertPool`, consult the host TLS store, build or select a certificate chain, decide publisher trust, check revocation, validate a timestamp, access a target, retrieve network data, or execute an FFU operation.

The activated plan therefore requires:

- `bundle_structure_validated: true`;
- `bundle_signature_authenticated: true`;
- `trust_anchors_activated: true`;
- `host_tls_store_consulted: false`;
- `certificate_chain_built: false`; and
- `publisher_trusted: false`.

The immutable generation, active record, and rollback state are not rewritten during activation. Recovery may remove only recognized private temporary names left by an interrupted publication.
