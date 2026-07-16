# Built-in signed acquisition channel

The 0.10 development line adds a built-in acquisition channel without embedding an online signing secret in the application, package, source repository, or CI environment.

## Roles and trust

The channel uses two metadata roles:

- **root** metadata contains Ed25519 public keys and threshold rules for both the root and catalog roles;
- **catalog** metadata contains immutable image records with HTTPS URLs, exact byte counts, filenames, redirect hosts, and SHA-256 digests.

Each metadata envelope contains a canonical JSON `signed` object and a detached signature list. Key IDs are the lowercase SHA-256 digest of the raw Ed25519 public key. Signed JSON must use sorted object keys, integer numbers, and no insignificant whitespace. Duplicate JSON keys, duplicate signatures, unknown fields, non-canonical forms, malformed key IDs, and invalid authorized signatures are rejected.

The bootstrap root requires at least two valid root signatures. A replacement root must increase the version by exactly one and meet both the currently trusted root threshold and the replacement root threshold. This dual authorization prevents an online catalog key from replacing the offline trust root. Catalog metadata must meet the current catalog-role threshold.

## Rollback and freeze protection

The client stores the highest accepted root and catalog versions, their signed-payload SHA-256 digests, and the most recent trusted wall-clock observation in an owner-only state file. It rejects:

- a lower root or catalog version;
- different metadata under an already accepted version;
- missing cached root history below the recorded trusted version;
- root version jumps that skip the dual-signature transition;
- expired root or catalog metadata;
- generation times more than 24 hours in the future;
- a local clock that moves more than 24 hours behind the last accepted metadata time;
- root validity periods above two years or catalog validity periods above 90 days.

Verified root updates are published at the versioned `root_url` path containing one `{version}` token, fetched one version at a time, kept as a sequential cache, and replayed from the package-owned bootstrap root. This allows an installation that missed several rotations to verify every old/new threshold transition rather than trusting a version jump. The catalog and state are written through same-directory temporary files, `fsync`, atomic rename, and directory `fsync`. Files are mode `0600`; cache directories are descriptor-checked real directories with mode `0700`.

An unexpired cached catalog may be used when the network is unavailable. It is reverified against the complete root chain and rollback state before use. Expired metadata never receives an offline bypass.

## Network policy

Root and catalog locations come from the package-owned channel configuration. Metadata downloads require HTTPS, use TLS 1.2 or newer, disable transparent compression, enforce strict byte limits, and permit redirects only to sorted allowlisted hosts. Private, loopback, local, multicast, and unspecified hosts are refused in production. CI network tests use only injected local TLS servers.

Image payloads continue to use the existing signed URL, redirect-host, exact-size, cancellation, SHA-256, and atomic-install enforcement.

## Provisioning boundary

`packaging/acquisition/channel.json` intentionally ships with `enabled: false`. This avoids publishing pretend trust material or a private signing key. Production activation requires the project owner to:

1. Generate multiple offline root key pairs on isolated systems.
2. Store the private root keys offline and separately.
3. Generate a distinct online catalog-signing key.
4. Review and threshold-sign root version 1.
5. Publish the public root envelope, channel configuration, and first threshold-signed catalog over the allowlisted HTTPS origin.
6. Replace the disabled package configuration and add the reviewed bootstrap `root.json` in a dedicated release PR.

No private key, seed phrase, signing token, or recovery secret may be committed, uploaded as a CI artifact, stored in repository secrets for routine builds, or installed with the package.

## Graphical behavior

The **Download…** dialog attempts the built-in verified channel first and refreshes it outside the GTK main loop. It displays the accepted catalog version, generation and expiry times, signing-key IDs, and whether an unexpired verified cache was used. There is no unsafe bypass. Until provisioning is complete, the dialog clearly reports that the built-in channel is unavailable and exposes the existing local signed-catalog workflow under **Advanced recovery**.
