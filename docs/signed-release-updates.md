# Threshold-signed release metadata and verified updates

Status: **verification, persistent rollback state, and exact package download implemented; production signing and installation are not yet enabled**.

RufusArm64 release assets were already reproducible and bound by published SHA-256 sidecars. That proves that downloaded bytes match release metadata served by GitHub, but it does not create an independent project-controlled publisher signature. This tranche reuses the acquisition channel's offline Ed25519 trust model for release metadata instead of introducing CI-held private keys or a second cryptographic format.

## Trust boundary

A root envelope may optionally authorize a `release` role containing one or more Ed25519 public-key IDs and a threshold. Existing root metadata with only `root` and `catalog` roles remains valid. Release signing keys are public metadata only; no RufusArm64 command accepts a private key.

The signed release payload binds:

- metadata schema, monotonic metadata version, generation time and expiry;
- product `RufusArm64` and repository `geocausa/RufusUbuntuArm64`;
- strict `MAJOR.MINOR.PATCH` release version and matching `v<version>` tag;
- the exact lowercase 40-character Git commit;
- `stable` or `prerelease` channel;
- a sorted unique asset inventory;
- each asset's basename, exact byte count, lowercase SHA-256, exact GitHub release URL and any explicitly signed redirect hosts;
- exactly one ARM64 Debian package named `rufusarm64_<version>_arm64.deb`.

Unknown JSON fields, duplicate keys, non-canonical payloads, invalid signatures, insufficient thresholds, expired root or release metadata, wrong repository paths, URL substitution, missing packages and malformed asset records are refused.

## Offline operator workflow

The source-only administrator never signs data. It canonicalizes an unsigned draft, emits an immutable signing manifest, accepts externally produced detached signatures and verifies the assembled envelope:

```bash
rufus-channel-admin payload release \
  --root 1.root.json \
  --input release-draft.json \
  --output release.payload.json \
  --manifest release.signing-manifest.json

# Sign release.payload.json on independent offline systems.

rufus-channel-admin envelope assemble \
  --root 1.root.json \
  --payload release.payload.json \
  --signature KEY_ID_A=signature-a.bin \
  --signature KEY_ID_B=signature-b.bin \
  --output release.json

rufus-channel-admin verify release \
  --root 1.root.json \
  --release release.json \
  --json
```

A production ceremony must use independently controlled offline keys, record public-key fingerprints and custody, require the configured threshold, preserve signed root history and publish no private material. The exact production roots and signed release envelope are not yet present in the repository.

## User-side verification

The installed helper can compare authenticated metadata with the installed version without mutating the system:

```bash
rufusarm64-cli update verify \
  --root 1.root.json \
  --release release.json \
  --current-version 0.15.0 \
  --minimum-metadata-version 1 \
  --state-file "$HOME/.local/state/rufusarm64/update/state.json" \
  --json
```

The command verifies the complete root chain and release signature threshold, then commits acceptance through a locked owner-only rollback transaction. The state binds the highest accepted root version and SHA-256, release metadata version and SHA-256, release version, and monotonic acceptance time. It refuses root rollback, same-version root substitution, release metadata rollback, same-version metadata substitution, release-version rollback, and a local clock more than 24 hours behind the last accepted time. `--minimum-metadata-version` remains an additional operator floor but cannot reduce the persisted floor.

The default state path follows `$XDG_STATE_HOME/rufusarm64/update/state.json`, falling back to `$HOME/.local/state/rufusarm64/update/state.json`. The final state directory is mode 0700; the state and lock are mode 0600. State admission uses no-follow opens, owner and single-link checks, strict JSON, an exclusive process lock, atomic replacement, file and directory synchronization, and a post-read mutation check. Concurrent processes therefore cannot overwrite a higher accepted sequence with a lower one. Deleting the state as the same local user resets this local rollback memory; the production metadata channel and package bootstrap root remain separate trust anchors.

A newer authenticated package can be downloaded without installation:

```bash
rufusarm64-cli update download \
  --root 1.root.json \
  --release release.json \
  --current-version 0.15.0 \
  --minimum-metadata-version 1 \
  --state-file "$HOME/.local/state/rufusarm64/update/state.json" \
  --output "$HOME/Downloads" \
  --resume \
  --json
```

The downloader receives the package record from an internal immutable snapshot created only after threshold verification. Mutating exported inspection fields after verification cannot alter the trusted version, package URL, size, SHA-256, metadata digest, or signer evidence used for the transfer. The existing acquisition writer then enforces signed redirect hosts, TLS policy, exact response/range semantics, bounded resumable partials, available space, cancellation, complete SHA-256 verification, atomic no-replace publication, directory synchronization, and verified reuse of an existing destination. A same-version or older release is refused before any network request.

## Deliberate exclusions

This implementation does **not**:

- automatically discover or refresh release metadata from the network;
- prevent the same local account from deliberately deleting its rollback state;
- execute `dpkg`, `apt`, PackageKit or another installer;
- request privilege;
- replace the running application;
- claim that GitHub Actions possesses a release private key;
- publish production root metadata or a signed release envelope;
- provide rollback after package installation;
- make an AppImage or other portable-distribution claim.

The next safe step is a committed offline-signed production root and release envelope that the release workflow checks against freshly reproduced assets before publication, followed by authenticated metadata refresh through a pinned channel. Installation remains a separate privileged package-management design.
