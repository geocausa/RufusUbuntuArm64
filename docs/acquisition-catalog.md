# Signed acquisition catalog format

RufusUbuntuArm64 0.9 introduces a security-first foundation for ISO and image downloads. The implementation accepts signed local catalogs and also supports the built-in signed acquisition channel. Remote metadata is used only after signature, expiry, schema, URL, redirect-host, size, and digest validation.

## Trust model

1. The catalog JSON is signed with Ed25519.
2. RufusUbuntuArm64 verifies the detached signature over the **exact catalog bytes** before parsing any URL.
3. The catalog must be unexpired and use the supported schema.
4. Every entry is validated for a safe filename, absolute HTTPS URL, bounded size, SHA-256 digest, and explicitly signed redirect hosts.
5. Before any image request is sent, the destination filesystem must report enough unprivileged available space for the signed bytes still required plus a 64 MiB safety reserve. Replacement downloads retain the full-image requirement because the old destination remains until atomic installation.
6. A normal download uses a private random temporary file. Explicit `--resume` mode instead uses a deterministic owner-only partial file keyed by the complete signed SHA-256, opened without following links and protected by an exclusive lock.
7. Resumed transfers rehash all retained bytes, request the exact remaining byte range, require a matching HTTP 206 `Content-Range`, and reject servers that ignore or contradict the request.
8. The complete file is size-bounded, SHA-256 verified from byte zero, synchronized, and atomically installed only after the signed size and digest both match.
9. Existing files are reused only when their complete SHA-256 and size already match. Different files are never overwritten without `--replace`.

The public key and catalog distribution policy are outside the JSON schema. Production catalogs should be distributed with a public key obtained through an independent trusted channel or embedded in a signed application release.

## Key and signature encoding

The public key may contain:

- 32 raw Ed25519 public-key bytes;
- 64 hexadecimal characters; or
- standard or unpadded base64.

The detached signature may contain:

- 64 raw Ed25519 signature bytes;
- 128 hexadecimal characters; or
- standard or unpadded base64.

## Schema 1

```json
{
  "schema": 1,
  "generated": "2026-07-16T10:00:00Z",
  "expires": "2026-08-16T10:00:00Z",
  "images": [
    {
      "id": "ubuntu-example-arm64",
      "name": "Ubuntu Desktop",
      "version": "example",
      "architecture": "arm64",
      "filename": "ubuntu-example-desktop-arm64.iso",
      "url": "https://releases.example.invalid/ubuntu-example-desktop-arm64.iso",
      "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "size": 5368709120,
      "redirect_hosts": ["cdn.example.invalid"]
    }
  ]
}
```

### Catalog fields

- `schema`: must be `1`.
- `generated`: RFC 3339 UTC or offset timestamp.
- `expires`: RFC 3339 timestamp after `generated`; validity may not exceed 366 days.
- `images`: one to 512 immutable image records.

Unknown JSON fields are rejected so misspellings cannot silently weaken validation.

### Image fields

- `id`: unique lowercase identifier using letters, numbers, dots, underscores, or hyphens.
- `name`: human-readable product name.
- `version`: release or build label.
- `architecture`: short normalized architecture label such as `arm64` or `amd64`.
- `filename`: basename only; path separators, dot-directory names, and control characters are rejected.
- `url`: absolute HTTPS URL without user information or a fragment.
- `sha256`: lowercase or uppercase 64-character hexadecimal SHA-256 digest.
- `size`: exact byte count from 1 byte through 128 GiB.
- `redirect_hosts`: optional additional DNS hostnames explicitly covered by the catalog signature. Redirects to all other hosts are refused.

## CLI

```bash
rufusarm64-cli acquire verify \
  --catalog catalog.json \
  --signature catalog.json.sig \
  --public-key catalog-ed25519.pub

rufusarm64-cli acquire list \
  --catalog catalog.json \
  --signature catalog.json.sig \
  --public-key catalog-ed25519.pub

rufusarm64-cli acquire download \
  --catalog catalog.json \
  --signature catalog.json.sig \
  --public-key catalog-ed25519.pub \
  --id ubuntu-example-arm64 \
  --output ~/Downloads \
  --resume
```

`--resume` is opt-in. A cancelled or transiently interrupted resumable transfer keeps its synchronized partial file for the next run. Without `--resume`, cancellation continues to remove temporary partials. Protocol contradictions, oversize data, signed-size mismatch, and final SHA-256 mismatch remove the retained partial rather than carrying unsafe state forward.

`--json-progress` emits the same byte/rate progress events used by the graphical application. `--json` emits the final result object, including `resumed_bytes` when applicable. CLI and graphical downloads enforce the same destination-space and signed-content checks.

## Deliberate exclusions in this tranche

- No unsigned catalog mode.
- No HTTP image URLs.
- No embedded production project signing key yet.
- No graphical resume control yet.
- No Windows ISO scraping or bypass of vendor download terms.

These features require separate threat modelling and review rather than being hidden behind an “advanced” switch.
