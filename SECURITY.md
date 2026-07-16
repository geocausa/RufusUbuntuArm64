# Security policy

RufusArm64 performs destructive raw block-device operations through a small privileged helper. Safety failures are treated as release-blocking defects.

## Safety model

The current release:

- accepts only resolved paths below `/dev`;
- requires an `lsblk` whole-disk object;
- rejects partitions and read-only targets;
- refuses every physical disk backing the running root filesystem;
- shows only explicitly removable or USB-attached whole disks in the normal GUI and hides internal MMC/eMMC;
- requires `--allow-fixed` for other whole disks in the expert CLI;
- resolves and identity-binds the selected image file, then refuses both path-based and already-open images stored on the target disk;
- unmounts child filesystems before writing;
- takes an exclusive advisory writer lock, pins the kernel device, and checks that the long-held USB descriptor remains live and the same size;
- validates Windows ISO layout, architecture, FAT32 filenames, payload uniqueness, generated answer files, temporary free space, split-part size, and target capacity before repartitioning;
- flushes pending writes before verification and completion, then verifies copied Windows files by SHA-256 and checks the FAT32 filesystem;
- refuses expert bypass flags when launched through the GUI, and requires both a graphical erase confirmation and a fresh Polkit administrator authentication for every operation.

## Image acquisition trust boundary

The 0.9 acquisition foundation does not trust a URL merely because it uses HTTPS. Before any network request, it requires an unexpired Ed25519-signed catalog and validates each immutable entry. Downloads are limited to the signed byte count, redirects are restricted to signed hostnames, data are hashed while streaming, and the destination is installed atomically only after the complete SHA-256 matches. Unsigned catalogs, HTTP URLs, path-bearing filenames, private/loopback redirect hosts, and unknown JSON fields are refused.

The initial implementation accepts local catalog/signature/public-key files. A future built-in remote catalog must establish a separately reviewed key-distribution and rotation policy.

## Known limitations

- Unusual multipath, network-block, device-mapper, or vendor-specific storage topologies may not be represented by `lsblk` as expected. The helper fails closed when it cannot identify the root disk.
- A privileged expert running the helper directly with sudo can deliberately enable fixed-disk mode; the Polkit GUI path rejects this override.
- No software can make sudden power loss, USB removal, or failing flash media safe.
- Automated tests do not replace physical boot testing on each hardware and firmware combination.

Report security issues privately to the repository owner rather than publishing destructive-device bypass details in a public issue.
