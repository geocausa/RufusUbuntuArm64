# Bounded FreeDOS image streaming

The deterministic ordinary-file builder is a strong byte-level oracle, but allocating a byte slice as large as the selected drive is not an acceptable production executor design. The streaming contract represents the same image as a small set of non-zero regions with implicit zero-filled gaps.

## Sparse source

The source contains only the bytes that differ from zero:

- the 512-byte MBR sector;
- primary and backup FreeDOS FAT32 boot regions and FSInfo data;
- the allocated prefix of each mirrored FAT;
- the root directory cluster;
- `COMMAND.COM` and configured `KERNEL.SYS`.

All head reservation, reserved-area gaps, unallocated FAT entries, free data clusters, payload cluster slack, and tail reservation bytes are generated as zeroes during reads. Regions are ordered, non-overlapping, and required to fit completely within the reviewed media size.

Tests require this sparse source to match the independent ordinary-file builder byte-for-byte at the FAT32 lower boundary.

## Sequential writing

`StreamMediaImage` uses a fixed 1 MiB buffer regardless of target capacity. It checks context cancellation before every chunk, reports progress only after bytes have been accepted, rejects impossible or short writer results, and publishes a SHA-256 digest only after the complete planned byte count is accepted.

A returned error may accompany a non-zero accepted-byte count. A future device executor must interpret any such result conservatively: once any byte is accepted, the selected media changed even when cancellation or an I/O failure follows.

## Complete readback

`VerifyMediaReadback` regenerates the expected sparse image and compares a seekable readback across the complete device with the same bounded memory. It reports the first mismatching byte and returns the expected whole-image digest only after every byte matches.

The future executor must perform synchronization and kernel buffer flushing before readback, retain the identity-bound descriptor lock throughout, and revalidate the open device before and after verification. This streaming layer itself opens no path and grants no device authority.
