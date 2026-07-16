# Signed acquisition catalog format

RufusUbuntuArm64 0.9 introduces a security-first foundation for future ISO and image downloads. The initial implementation deliberately accepts **local catalog, detached signature, and public-key files only**. A remote catalogue service and graphical picker will be added only after this verifier and downloader have been exercised independently.

## Trust model

1. The catalog JSON is signed with Ed25519.
2. RufusUbuntuArm64 verifies the detached signature over the **exact catalog bytes** before parsing any URL.
3. The catalog must be unexpired and use the supported schema.
4. Every entry is validated for a safe filename, absolute HTTPS URL, bounded size, SHA-256 digest, and explicitly signed redirect hosts.
5. The image is written to a private temporary file, size-bounded, hashed while downloading, synchronized, and atomically installed only after the signed size and SHA-256 both match.
6. Existing files are reused only when their complete SHA-256 and size already match. Different files are never overwritten without `--replace`.

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
  --output ~/Downloads
```

`--json-progress` emits the same byte/rate progress events used by the graphical application. `--json` emits the final result object. Cancellation through `SIGINT` or `SIGTERM` removes the temporary partial file.

## Deliberate exclusions in this tranche

- No unsigned catalog mode.
- No HTTP image URLs.
- No automatic remote catalog update.
- No embedded project signing key yet.
- No download-resume support yet.
- No Windows ISO scraping or bypass of vendor download terms.

These features require separate threat modelling and review rather than being hidden behind an “advanced” switch.
