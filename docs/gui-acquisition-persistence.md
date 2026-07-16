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
- a read-only mounted or extracted root of that image;
- an optional requested persistence size.

It invokes only:

```text
rufusarm64-cli persistence plan ... --json
```

The planner reads bounded expected marker and boot-configuration paths and returns the detected family, filesystem label, boot parameter, requested partition size, and boot files that a future creation operation would update. It does not open the USB for writing, modify the image, patch a boot file, create a partition, or invoke `pkexec`.

The GUI does not expose `--mode linux-persistent` or `--experimental-persistence`. Persistent-media creation remains command-line-only until the physical ARM64 qualification matrix and graphical recovery behavior are sufficiently mature.

## Threading and interface behavior

Downloads and persistence analysis run outside the GTK main loop. Progress and cancellation remain visible, the window refuses to close while an operation is active, and technical output is included in the exportable diagnostic log.
