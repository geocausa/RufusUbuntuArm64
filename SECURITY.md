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

The local recovery implementation accepts catalog/signature/public-key files supplied through a separately trusted path. The built-in 0.10 channel adds canonical threshold-signed root and catalog metadata, SHA-256-derived key IDs, dual authorization for root rotation, one-version-at-a-time catch-up through versioned root URLs, sequential root history, monotonic root/catalog versions, digest pinning for already accepted versions, expiry/freeze limits, clock-rollback detection, and owner-only atomic trust state. HTTPS metadata redirects are restricted to package-owned allowlisted hosts, while an unexpired cached catalog is reverified before offline use.

The installed channel configuration remains disabled until offline root keys are generated, separated, and used to sign a reviewed bootstrap root and first catalog. No private key may enter the repository, CI secrets used for routine builds, packages, or release artifacts. Expired roots have no unsafe bypass; recovery requires a reviewed package/bootstrap-root update or the advanced local signed-catalog path.

The source-only `rufus-channel-admin` executable enforces this separation: it accepts public keys and detached signatures but has no private-key argument and contains no signing path. Its output is deterministic and it creates publication directories only after verifying the complete root chain, catalog role, expiry, public URLs, and checksums. The normal Debian package does not install this operator executable.

## Persistence planning trust boundary

The 0.9 persistence command is unprivileged and read-only. It accepts a source image, a mounted or extracted media tree, and a caller-supplied target capacity solely to calculate eligibility and geometry. It does not treat the media tree or target-size value as authorization for a future write. Detection reads only bounded expected marker/configuration paths, and partition planning validates MBR or both GPT copies before returning an append-only proposal.

The materialization primitives repeat the plan against the already-open target before changing partition metadata. GPT updates write and sync the relocated backup before the primary, verify both copies and CRCs, and clear obsolete backup metadata only after the new pair is durable. Boot-tree replacement pins the root and parent descriptors, refuses symbolic-link components, rechecks the original inode, writes a same-directory temporary file, and fsyncs before and after atomic rename. Ext4 creation operates through an inherited open partition descriptor, requires the expected block-device identity and size, invokes a final caller safety callback immediately before `mkfs.ext4`, mounts with `nosuid,nodev,noexec`, initializes Debian `persistence.conf` with no-follow creation, unmounts, and runs `e2fsck -f -n`.

The writable-tree copy primitive builds a bounded SHA-256 manifest from the read-only media mount, rejects FAT32 collisions and unsafe names, refuses external or directory symbolic links, materializes only in-tree regular-file links, copies through same-directory temporary files, fsyncs around rename, and rehashes the destination. Its destination must be a private mount held under the future whole-disk orchestration lock.

The experimental CLI orchestration layer now creates the writable GPT/FAT32/ext4 layout while retaining the whole-disk lock. It hashes the pinned source before inspection, immediately before erasure, and after creation; invokes the caller target-safety callback at destructive boundaries; writes and verifies backup GPT metadata before primary metadata; requires exact kernel partition geometry; copies into a private mount; re-runs persistence detection after boot patching; checks both filesystems; and flushes target buffers before success.

The graphical privileged path rejects the experimental mode. The creator stores a canonical creation record and SHA-256 sidecar on the writable boot partition. The qualification commands verify that record, require UEFI, the expected family and persistence kernel parameters, and an overlay root, then use a private marker to demonstrate survival across a later Linux boot ID. Reports hash boot IDs and marker tokens and do not collect hostnames, MAC addresses, serial numbers, product UUIDs, or the raw kernel command line.

The creation-record checksum detects accidental or unsophisticated modification but is not an authenticated signature: an attacker able to rewrite both files can replace both. Qualification evidence proves only the observed media and one reboot sequence; physical ARM64 boot qualification remains a separate release gate. A failure after erasure must be treated as incomplete media rather than recoverable success.

## Known limitations

- Unusual multipath, network-block, device-mapper, or vendor-specific storage topologies may not be represented by `lsblk` as expected. The helper fails closed when it cannot identify the root disk.
- A privileged expert running the helper directly with sudo can deliberately enable fixed-disk mode; the Polkit GUI path rejects this override.
- No software can make sudden power loss, USB removal, or failing flash media safe.
- Automated tests do not replace physical boot testing on each hardware and firmware combination.

Report security issues privately to the repository owner rather than publishing destructive-device bypass details in a public issue.
