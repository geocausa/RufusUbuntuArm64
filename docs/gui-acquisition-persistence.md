# Graphical acquisition and persistence analysis

The 0.10 development line begins moving previously command-line-only safety foundations into the GTK application without broadening the destructive write boundary.

## Verified image download

The **Download…** button accepts three local trust inputs:

- an acquisition catalog;
- its detached Ed25519 signature;
- the trusted Ed25519 public key.

The graphical application delegates verification and downloading to the existing unprivileged `rufusarm64-cli acquire` commands. It does not parse an unsigned remote feed or download directly with Python. The helper verifies the catalog before listing entries, restricts URLs and redirects according to signed metadata, enforces the signed byte count, calculates SHA-256 while streaming, and installs the destination atomically only after the complete digest matches.

The first graphical version intentionally uses local catalog, signature, and public-key files. A built-in online catalog requires a separately reviewed key-distribution, key-rotation, rollback, and recovery policy.

Cancellation terminates the unprivileged download process. The acquisition engine removes temporary data and does not install an unverified partial image.

## Read-only persistence compatibility

The **Linux persistence compatibility** panel accepts:

- a selected recognized Linux ISOHybrid image;
- the selected USB drive's reported capacity;
- an optional requested persistence size.

The GUI records the selected image's kernel identity before administrator authentication, then invokes only:

```text
sudo rufusarm64-cli persistence analyze ... --json
```

The helper refuses the operation if the image's device, inode, size, modification time, or change time no longer match the pre-authentication identity. It opens the image without following symlinks, mounts the pinned file descriptor in a private `0700` workspace with `loop,ro,nosuid,nodev,noexec`, runs the existing bounded persistence detector and planner, rechecks the source identity, unmounts, and removes the workspace on success, error, timeout, or cancellation.

Only the selected USB drive's capacity is supplied. No target device path is accepted or opened, and the command cannot modify a partition table, filesystem, boot configuration, image, or USB drive. The older unprivileged `persistence plan --media-root` command remains available for scripts and manually mounted media.

The GUI does not expose `--mode linux-persistent` or `--experimental-persistence`. Persistent-media creation remains command-line-only until the physical ARM64 qualification matrix and graphical recovery behavior are sufficiently mature.

## Threading and interface behavior

Downloads and persistence analysis run outside the GTK main loop. Progress and cancellation remain visible, the window refuses to close while an operation is active, and technical output is included in the exportable diagnostic log.
