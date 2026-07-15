# Security policy

RufusArm64 performs destructive raw block-device operations through a small privileged helper. Safety failures are treated as release-blocking defects.

## Safety model

The current release:

- accepts only resolved paths below `/dev`;
- requires an `lsblk` whole-disk object;
- rejects partitions and read-only targets;
- refuses every physical disk backing the running root filesystem;
- shows only removable, USB, or MMC whole disks in the normal GUI;
- requires `--allow-fixed` for other whole disks in the expert CLI;
- refuses an image stored on the selected target disk;
- unmounts child filesystems before writing;
- takes an exclusive advisory writer lock;
- validates Windows ISO layout and target capacity before repartitioning;
- flushes pending writes before verification and completion;
- requires both a graphical erase confirmation and Polkit administrator authentication.

## Known limitations

- Unusual multipath, network-block, device-mapper, or vendor-specific storage topologies may not be represented by `lsblk` as expected. The helper fails closed when it cannot identify the root disk.
- A privileged expert can deliberately bypass fixed-disk policy through the command line.
- No software can make sudden power loss, USB removal, or failing flash media safe.
- Automated tests do not replace physical boot testing on each hardware and firmware combination.

Report security issues privately to the repository owner rather than publishing destructive-device bypass details in a public issue.
