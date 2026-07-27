# Create verified FreeDOS media

RufusArm64 can create a deliberately narrow FreeDOS 1.4 USB layout from the package's checksum-pinned kernel and FreeCOM payload.

## Compatibility boundary

The resulting media is for **x86-compatible processors** using **BIOS or UEFI Legacy/CSM firmware**. It is not an ARM64 boot path and is not suitable for UEFI-only systems. Secure Boot compatibility is not claimed. Passing software verification does not prove that a particular physical computer will boot the drive.

## Graphical workflow

1. Connect one removable USB drive.
2. Open **RufusArm64** and select the exact target drive.
3. Choose **FreeDOS…** beside the target controls.
4. Enter an uppercase FAT32 label containing 1–11 ASCII letters, digits, `-`, or `_`.
5. Review the unprivileged plan. It binds the refreshed device identity, exact capacity, 512-byte logical-sector requirement, MBR/FAT32 geometry, pinned FreeDOS distribution, complete platform warnings, and the exact byte totals that will be written and verified before authentication.
6. Type the exact phrase shown by the formatter, for example:

   ```text
   WRITE FREEDOS 1.4 TO /dev/sdX FOR X86 BIOS LEGACY
   ```

7. Select **Create FreeDOS media** and authenticate. Everything on the selected drive is erased logically: the old partition/filesystem layout is replaced and prior files are no longer accessible.
8. Keep the drive connected while RufusArm64 writes the required MBR, FAT32 boot/FSInfo regions, both FAT tables, root directory, FreeDOS payload clusters, bounded head/tail clearing regions, flushes the block device, reads those required extents back byte-for-byte, and performs the final live device-identity check.

The FAT32 partition still uses nearly the full drive. Unallocated data clusters are intentionally not overwritten during fast creation, just as with an ordinary quick format. Use the separate **Check USB** workflow when an exhaustive whole-device write/readback qualification is required.

The final report distinguishes an untouched drive from a drive changed before a cancellation or failure. A changed incomplete drive is never reported reusable.

## Terminal workflow

Planning is available without a destructive confirmation:

```bash
rufusarm64-freedos-format \
  --device /dev/sdX \
  --expected-identity IDENTITY_FROM_RUFUSARM64 \
  --label FREEDOS \
  --dry-run --json
```

Interactive creation requires root and the exact phrase printed by the command:

```bash
sudo rufusarm64-freedos-format \
  --device /dev/sdX \
  --expected-identity IDENTITY_FROM_RUFUSARM64 \
  --label FREEDOS
```

Use `rufusarm64-cli list --json` to obtain the current path and identity token. There is no fixed-disk override.

## Verification and qualification

A successful creation report proves that every required final boot/filesystem extent was written, synchronized, and read back on the selected block device, and that the resulting MBR/FAT32 structure and pinned payload satisfy the reviewed contract. It does not claim that untouched free clusters were tested.

Use **Check USB** for destructive whole-device media qualification. Physical boot qualification still requires booting that exact drive on that exact x86 computer with the intended BIOS or UEFI Legacy/CSM firmware mode.
