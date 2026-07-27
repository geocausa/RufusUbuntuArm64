# Graphical acquisition and persistence analysis

The 0.10 development line begins moving previously command-line-only safety foundations into the GTK application without broadening the destructive write boundary.

## Verified image download

The composed GTK application exposes the existing **Download…** dialog and prefers the package-owned built-in channel. The Go helper, not Python, performs the network and trust work:

- replays the cached root chain from the package bootstrap root;
- accepts root rotation only when the version advances by exactly one and both the old and replacement root thresholds sign it;
- verifies the catalog-role threshold, generation and expiry times, monotonic version, and accepted-version digest;
- downloads metadata only over HTTPS to package-allowlisted hosts;
- uses only an unexpired, completely reverified cache when the network is unavailable;
- checks free storage before transfer;
- verifies the selected image's signed URL, redirect hosts, exact size, filename, and SHA-256 before atomic installation.

Catalog refresh runs outside the GTK main loop. The dialog shows the catalog version, generation and expiry times, signing-key IDs, and whether the verified cache was used. Every graphical transfer enables the native resumable mode. Its partial file is owner-only, locked, bound to the catalog image SHA-256, opened without following links, rehashed before reuse, and never installed as the selected image. Cancellation terminates the unprivileged process group and retains that private partial for a later verified resume; protocol, size, or digest contradictions remove it rather than trusting it.

The installed channel is deliberately disabled until real offline root keys and a reviewed first catalog are provisioned. While disabled, the dialog reports the trust boundary rather than offering an unsafe bypass. **Advanced recovery: local signed catalog** preserves the original catalog, detached signature, and public-key workflow for metadata obtained through a separately trusted path.

See `docs/acquisition-channel.md` for the root-rotation, rollback, cache, and provisioning model.

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
