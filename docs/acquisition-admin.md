# Offline acquisition-channel administration

`rufus-channel-admin` is a **source-only operator tool** for provisioning and maintaining the threshold-signed image channel. It is intentionally not installed as part of the normal RufusArm64 application package.

The executable never generates, reads, parses, uploads, or stores a private key. It handles only:

- Ed25519 public keys;
- unsigned root and catalog drafts;
- canonical payload bytes and SHA-256 signing manifests;
- externally produced detached Ed25519 signatures;
- signed public metadata envelopes;
- public channel configuration and publication directories.

Private-key operations must take place on independently controlled offline systems, hardware tokens, or HSMs. No private key, recovery seed, token export, or private-key path belongs in this repository, routine CI, application packages, issue attachments, or release artifacts.

## Build the operator tool

Build from a reviewed source checkout on the administration workstation:

```text
go build -trimpath -o rufus-channel-admin ./cmd/rufus-channel-admin
./rufus-channel-admin help
```

The regular Debian package does not install this binary.

## Recommended role separation

A practical first deployment uses at least:

- three offline root keys with a 2-of-3 root threshold;
- one or more separately controlled online catalog keys;
- a catalog threshold appropriate to the publication process;
- independent root operators who verify the payload digest before signing;
- a publication reviewer who does not control enough keys to satisfy the root threshold alone.

Root keys should remain offline except during planned ceremonies. Catalog keys can be more available, because a compromised catalog key can be revoked by a new root version, but they still require strong operational controls.

## Public-key IDs

Export only the Ed25519 public portion from each external signer, then derive the RufusArm64 key ID:

```text
./rufus-channel-admin key-id --public-key root-a.pub --json
```

The key ID is the lowercase hexadecimal SHA-256 digest of the 32-byte Ed25519 public key. Root drafts must use the exact standard-base64 public key and the derived key ID. Keys and role key lists must be sorted by key ID.

## Prepare a root payload

Create a root draft containing only public metadata. Root version 1 is the bootstrap root. Later roots must advance exactly one version at a time.

```text
./rufus-channel-admin payload root \
  --input root-1.draft.json \
  --output root-1.payload.json \
  --manifest root-1.signing.json
```

The payload file is the exact canonical byte sequence to sign. Do not reformat it, append a newline, or sign the draft instead. The signing manifest records:

- metadata type and version;
- generation and expiry times;
- exact payload byte count;
- SHA-256 digest;
- required role and threshold;
- authorized key IDs.

Every operator should independently verify the manifest and payload digest before signing.

## Sign externally

Use the selected offline signer to create a raw 64-byte Ed25519 signature over the exact payload. For example, an isolated OpenSSL 3 workflow may use:

```text
openssl pkeyutl -sign -rawin \
  -inkey /offline/root-a.key \
  -in root-1.payload.json \
  -out root-a.sig
```

This command is only an example of an **external** signing operation. The private key must remain on the isolated signer and must never be passed to `rufus-channel-admin`.

Collect signatures through a controlled transfer process. Each signature must remain associated with its public key ID and the payload SHA-256 it approved.

## Assemble and verify a bootstrap root

```text
./rufus-channel-admin envelope assemble \
  --payload root-1.payload.json \
  --signature KEY_ID_A=root-a.sig \
  --signature KEY_ID_B=root-b.sig \
  --output 1.root.json

./rufus-channel-admin verify root \
  --root 1.root.json \
  --json
```

Envelope assembly sorts signatures by key ID and is deterministic. It performs the applicable bootstrap, root-transition, or catalog-role authorization before writing the envelope. Duplicate, malformed, unknown, wrong-payload, or insufficient signatures are rejected immediately.

## Root rotation

Root version `N+1` must be authorized by both:

- the root role in version `N`; and
- the replacement root role declared in version `N+1`.

Prepare the new payload, collect enough signatures from both old and new roles, then assemble it while supplying the complete previous root chain. The assembly step refuses unknown, insufficient, or wrong-payload signatures before creating an output file:

```text
./rufus-channel-admin envelope assemble \
  --payload root-2.payload.json \
  --root 1.root.json \
  --signature OLD_KEY_ID_A=old-a.sig \
  --signature OLD_KEY_ID_B=old-b.sig \
  --signature NEW_KEY_ID_A=new-a.sig \
  --signature NEW_KEY_ID_B=new-b.sig \
  --output 2.root.json
```

Then verify the complete sequential chain:

```text
./rufus-channel-admin verify root \
  --root 1.root.json \
  --root 2.root.json \
  --root 3.root.json \
  --json
```

Skipped versions, changed content at an existing version, expired final roots, invalid signatures, and generation-time reversal are refused. Expired intermediate roots remain replayable when they form a previously valid sequential rotation chain; the final root must still be current.

## Prepare and sign a catalog

Catalog drafts contain immutable image entries sorted by ID. Every entry includes the exact filename, URL, architecture, byte count, SHA-256, and any explicitly authorized redirect hosts.

```text
./rufus-channel-admin payload catalog \
  --root 1.root.json \
  --root 2.root.json \
  --input catalog.draft.json \
  --output catalog.payload.json \
  --manifest catalog.signing.json

./rufus-channel-admin envelope assemble \
  --payload catalog.payload.json \
  --root 1.root.json \
  --root 2.root.json \
  --signature CATALOG_KEY_ID=catalog.sig \
  --output catalog-envelope.json

./rufus-channel-admin verify catalog \
  --root 1.root.json \
  --root 2.root.json \
  --catalog catalog-envelope.json \
  --json
```

The active root determines the authorized catalog keys and threshold. Catalog metadata must be unexpired when published.

## Create the public channel configuration

The bootstrap root must be version 1. Metadata URLs must be HTTPS, use the default HTTPS port, resolve through the reviewed publication layout, and use sorted allowlisted public hosts.

```text
./rufus-channel-admin channel-config \
  --bootstrap-root 1.root.json \
  --root-url https://updates.example.org/metadata/{version}.root.json \
  --catalog-url https://updates.example.org/metadata/catalog.json \
  --host updates.example.org \
  --output channel.json
```

Loopback, private, local, multicast, unspecified, non-HTTPS, user-information, fragment, non-default-port, and non-allowlisted metadata locations are rejected.

## Build a publication directory

After every envelope and the public configuration has been independently reviewed:

```text
./rufus-channel-admin publish \
  --root 1.root.json \
  --root 2.root.json \
  --catalog catalog-envelope.json \
  --config channel.json \
  --directory publication-v2
```

The destination must not already exist. The tool verifies the full chain and catalog, canonicalizes every public file, builds the directory privately, fsyncs its contents, and renames it into place atomically. It produces:

- one `<version>.root.json` file per root;
- `catalog.json`;
- `channel.json`;
- `publication.json` with public version/digest information;
- `SHA256SUMS` covering all other publication files.

Repeated runs with the same inputs produce byte-for-byte identical files.

Upload only the final public directory. Verify the remote bytes and hashes after publication before activating or updating the packaged channel configuration.

## Activation boundary

The normal package remains configured with an explicit disabled channel until the first ceremony is complete. Activation requires a separately reviewed source change that adds only:

- the signed bootstrap root envelope;
- the reviewed public metadata URLs;
- the sorted public host allowlist;
- the enabled public channel configuration.

No private material is required or permitted in that change.

## Expiry and recovery

Schedule root rotation and package recovery work well before expiry. Keep multiple geographically separated offline backups of each root key according to the organization’s key-custody policy. Test restoration without exporting secrets into general-purpose systems.

A compromised catalog key is revoked through the next root version. A compromised root key requires an immediate threshold-authorized replacement root while enough uncompromised current and replacement root keys remain available.

There is no unsafe “ignore signature”, “ignore rollback”, or “ignore expiry” switch. If the trusted root expires before a valid rotation is published, recovery requires a reviewed package/bootstrap-root update or the advanced local signed-catalog workflow described in `docs/acquisition-channel.md`.
