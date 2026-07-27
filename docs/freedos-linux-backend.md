# FreeDOS Linux device backend

The Linux backend is the first implementation that can write the reviewed deterministic FreeDOS image to a real block-device descriptor. It remains package-private and has no command, Polkit action, terminal entry point, or GTK exposure.

## Required caller boundaries

Before calling `ExecuteLinuxDevice`, a future privileged helper must already have:

- parsed and validated the complete `DevicePlan`;
- compared the exact destructive confirmation phrase;
- authenticated through the dedicated FreeDOS Polkit action;
- refreshed the selected whole-disk policy, including root-disk refusal and removable-only enforcement;
- unmounted eligible removable-media descendants;
- bound the live kernel `dev_t` identity and exact capacity;
- supplied a live revalidation callback that repeats policy and identity checks.

The backend does not weaken those duties or accept a fixed-disk override.

## Descriptor and lock lifetime

The backend resolves the selected path, rejects aliases, opens it with `O_NOFOLLOW`, acquires an exclusive advisory lock, verifies the held descriptor with the kernel device identity and `BLKGETSIZE64`, and keeps that descriptor and lock alive through the complete write, flush, readback, final revalidation, and close sequence.

The `/dev` path is checked against the bound kernel identity throughout. The live callback runs after locking, immediately before the first accepted byte, and after complete readback.

## Write and verification boundary

The generic guarded executor streams the deterministic image through the held descriptor with bounded memory. Any accepted byte marks the media changed. The backend synchronizes the descriptor and kernel block buffers before complete byte-for-byte readback.

Success is reusable only after:

1. the exact planned byte count is accepted;
2. descriptor and system synchronization succeed;
3. complete readback matches the deterministic sparse source and digest;
4. mounted-descendant refusal and live policy/identity revalidation still pass;
5. final buffer flush and descriptor identity checks pass;
6. the exclusive lock and descriptor close cleanly.

The dedicated CI gate proves this sequence against a writable temporary loop device, then detaches and reattaches it read-only, requires `blkid` and `fsck.vfat -n` acceptance, and reruns the complete structural verifier.

This is destructive-device implementation evidence for a temporary loop-backed file only. It is not product exposure and is not physical x86 boot evidence.
