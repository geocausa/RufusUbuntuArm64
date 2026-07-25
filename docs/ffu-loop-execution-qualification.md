# FFU privileged loop-device execution qualification

The one-shot executor is not considered qualified solely because regular-file
fixtures pass. This boundary runs the complete authenticated single-phase FFU
transaction against a real Linux loop block device under kernel exclusivity.

## Qualification transaction

The workflow creates a private 64 MiB backing file, attaches it to a loop device,
and records the loop target's kernel device identity and capacity. The test then:

1. builds a signed synthetic single-phase FFU;
2. validates its catalog, publisher policy, hash table, payload descriptors, full-
   flash profile, target plan, and write order;
3. holds the FFU source using the real Linux kernel read lease;
4. seeds the loop target with a known byte pattern;
5. opens the actual loop block descriptor with `O_RDWR | O_EXCL | O_NOFOLLOW`;
6. verifies the held block descriptor using the normal safety verifier;
7. acquires the sealed target session, exact destructive confirmation, and
   mutation authorization;
8. calls the production one-shot executor;
9. requires target synchronization and complete extent readback; and
10. compares the entire loop target with an independently constructed expected
    image, including every untouched byte.

The test also verifies that the authorization was consumed and cannot be reused.
The loop device is detached and its backing file removed on every workflow exit.

## Scope and limitations

This qualification exercises real Linux block-device writes, exclusivity,
durability, and readback. Device discovery metadata and source-target separation
are injected with exact loop-bound values because the existing production safety
and source-separation suites already test those policies independently. The test
must not be interpreted as removable-hardware, firmware-boot, or vendor-FFU
evidence.

Only the non-staged single-phase FFU profile is covered. Staged-GPT/mobile FFUs,
guarded unmount, provider integration, administrator authentication, GTK
exposure, real signed Microsoft/OEM FFUs, disposable physical media, and boot
qualification remain separate gates.

## CI policy

The permanent `FFU loop execution qualification` workflow runs for pull requests
that modify FFU code and for FFU changes merged to the Stage 3 branch. It creates
and destroys its own loop target and never receives a host disk path from a
caller.
