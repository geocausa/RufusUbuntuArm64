# Persistent Linux boot and reboot qualification

The experimental persistent Linux creator stores a canonical creation record on the writable boot partition:

```text
.rufusarm64/creation.json
.rufusarm64/creation.json.sha256
```

The record binds the creator version, source-image SHA-256, media family and architecture, target geometry, FAT32 and ext4 partition extents, persistence contract, copied-manifest totals, and patched boot paths. It provides reproducible context for a physical test; it is not a remotely signed attestation.

## Two-stage procedure

Boot the newly created USB on the ARM64 system being tested. Locate the mounted writable boot partition; Ubuntu commonly exposes it beneath `/cdrom`, but the mount point may differ.

Run the initial probe:

```bash
sudo rufusarm64-cli qualify start \
  --record /cdrom/.rufusarm64/creation.json \
  --output "$HOME/rufusarm64-initial.json"
```

The command refuses success unless the running system:

- matches the media architecture;
- was booted through UEFI;
- has the expected `boot=casper` or `boot=live` parameter;
- has the expected `persistent` or `persistence` parameter; and
- uses an overlay-style live root filesystem.

It writes a private marker under `/var/lib/rufusarm64/qualification` by default. Because this directory is inside the persistent live root, the marker must survive the next reboot.

Reboot the **same machine from the same USB**, then run:

```bash
sudo rufusarm64-cli qualify verify \
  --record /cdrom/.rufusarm64/creation.json \
  --output "$HOME/rufusarm64-verified.json"
```

Verification repeats every live-environment check, requires a different Linux boot ID, and requires the original private marker and random token to have survived. Running `verify` without an intervening reboot is rejected.

Each output has a neighbouring `.sha256` file. Preserve the initial report, verified report, their sidecars, the exact ISO checksum, device model, USB-controller description, firmware version, Secure Boot state, and any observed boot warnings as one matrix entry.

## Privacy and trust boundary

Qualification reports include the creator, media family, media/runtime architecture, UEFI and persistence checks, root-filesystem type, kernel release, OS display name, creation-record digest, and hashed reboot-marker values.

They intentionally omit:

- hostname and user identity;
- MAC or IP addresses;
- disk and USB serial numbers;
- system product UUIDs; and
- the raw kernel command line.

The creation record and report sidecars are SHA-256 integrity checks, not digital signatures. They detect accidental corruption and make evidence sets easy to compare, but anyone able to replace a JSON file can also replace its sidecar. Release-grade authenticated evidence would require a separately managed signing key and review process.

## What a passing report proves

A verified report shows that this media booted through the expected UEFI path, activated the expected live persistence contract, presented an overlay root, and retained a private marker across one reboot on the tested setup.

It does **not** prove compatibility with another firmware, USB controller, Linux image, logical-sector size, Secure Boot configuration, or ARM64 computer. GUI exposure should remain blocked until a published physical matrix contains enough independently reviewable entries for the supported scope.
