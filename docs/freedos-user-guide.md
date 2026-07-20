# Create verified FreeDOS media

RufusArm64 can create a deliberately narrow FreeDOS 1.4 USB layout from the package's checksum-pinned kernel and FreeCOM payload.

## Compatibility boundary

The resulting media is for **x86-compatible processors** using **BIOS or UEFI Legacy/CSM firmware**. It is not an ARM64 boot path and is not suitable for UEFI-only systems. Secure Boot compatibility is not claimed. Passing software verification does not prove that a particular physical computer will boot the drive.

## Graphical workflow

1. Connect one removable USB drive.
2. Open **RufusArm64** and select the exact target drive.
3. Choose **FreeDOS…** beside the target controls.
4. Enter an uppercase FAT32 label containing 1–11 ASCII letters, digits, `-`, or `_`.
5. Review the unprivileged plan. It binds the refreshed device identity, exact capacity, 512-byte logical-sector requirement, MBR/FAT32 geometry, pinned FreeDOS distribution, and complete platform warnings before authentication.
6. Type the exact phrase shown by the formatter, for example:

   ```text
   WRITE FREEDOS 1.4 TO /dev/sdX FOR X86 BIOS LEGACY
   ```

7. Select **Create FreeDOS media** and authenticate. Everything on the selected drive is erased.
8. Keep the drive connected while RufusArm64 streams the complete deterministic image, flushes the block device, reads every byte back, verifies the FAT32 structure and payload, and performs the final live device-identity check.

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

## Qualification

A successful report proves that the package produced and completely read back the reviewed disk image on the selected block device. It does not establish physical boot compatibility. Qualification of a particular PC still requires booting that exact drive on that exact machine with the intended firmware mode.
