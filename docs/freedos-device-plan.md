# FreeDOS identity-bound device plan

The FreeDOS device plan is the first safety-integration boundary between deterministic media construction and any future privileged executor. It is unprivileged data only: building, validating, serializing, or displaying a plan does not discover, open, lock, unmount, erase, or write a device.

## Bound facts

A canonical plan binds all of these values together:

- one canonical absolute path beneath `/dev`;
- one non-empty, already refreshed kernel-device identity string;
- the exact whole-device capacity;
- the reviewed 512-byte logical-sector requirement;
- the complete deterministic `MediaPlan`, including label and FAT32 geometry;
- the active first MBR partition, byte start, byte size, FAT32-LBA type `0x0c`, and FAT32 filesystem claim;
- FreeDOS 1.4, x86 target CPU, and BIOS or UEFI Legacy/CSM firmware scope;
- the complete destructive, platform, firmware, and physical-boot evidence warnings.

Validation reconstructs the media plan from the bound capacity and label. A plausible but altered nested plan is rejected.

## Confirmation boundary

The exact confirmation phrase is:

```text
WRITE FREEDOS 1.4 TO /dev/DEVICE FOR X86 BIOS LEGACY
```

The real selected path replaces `/dev/DEVICE`. The phrase intentionally names the target and platform boundary. It is not authorization by itself; a later command must compare exact input, authenticate through the dedicated Polkit action, and still perform final kernel-backed policy and identity checks immediately before the first write.

## Executor obligations

A privileged executor must not trust discovery facts merely because they appear in a valid plan. It must independently rediscover the selected whole disk, refuse the root disk and non-removable policy violations, verify capacity and 512-byte logical sectors, bind the open descriptor to the expected kernel identity, acquire the exclusive lock, guard unmounts, and revalidate everything immediately before destructive I/O.

No fixed-disk override is permitted in the graphical path. Cancellation after any accepted write must report that media changed and must never describe the target as reusable until complete synchronized byte-for-byte readback succeeds.
