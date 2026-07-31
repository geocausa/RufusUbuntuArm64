# Support

RufusArm64 is experimental system software that can erase an entire selected drive. Before reporting a problem, stop retrying destructive operations and preserve the diagnostics from the first failure.

## Usage and bug reports

Open a GitHub issue using the appropriate template and include:

- the exact RufusArm64 version or Git commit;
- operating system and architecture;
- operation mode and selected layout/filesystem;
- source image name, size, and SHA-256 when redistribution permits;
- target model, capacity, transport, and removable state;
- the exported RufusArm64 diagnostics or JSON result;
- the first relevant kernel messages after the failure;
- whether the target was later unplugged, reset, or re-enumerated.

Redact personal paths, account names, private URLs, keys, passwords, and unrelated device identifiers. Never post credentials or private signing material.

## Storage or I/O failures

If the target reports resets, media errors, changing capacity, a changing kernel I/O error counter, or disappears during an operation:

1. Do not mount or write the target again through the unstable connection.
2. Do not assume the on-disk contents are valid.
3. Preserve the exact error report and read-only device inventory.
4. Requalify the medium and controller separately before another destructive run.

## Security reports

Do not open a public issue for a suspected wrong-disk-write bypass, privilege-boundary failure, signature/trust bypass, or another vulnerability that could endanger users or data. Follow `SECURITY.md` and contact the repository owner privately.
## Release support model

RufusArm64 is community-tested software, not a universally certified hardware product. The maintainer cannot pre-test every image, firmware, USB controller, machine, or architecture combination. Please report one reproducible problem per issue with the exact release, image identity, hardware details, operation mode, and non-sensitive diagnostics. Broad parity or open-ended roadmap requests may be closed in favour of concrete defects.
