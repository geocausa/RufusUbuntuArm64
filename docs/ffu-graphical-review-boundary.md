# FFU graphical review boundary

This document defines the first graphical Full Flash Update (FFU) integration boundary. It is deliberately read-only.

## Purpose

The GTK front end may build and consume the existing experimental `rufusarm64-cli ffu review` transaction only after it has an exact currently selected removable whole disk and explicit operator-selected trust inputs.

The helper command binds:

- the exact absolute `.ffu` source path;
- the selected target's canonical `/dev/...` path;
- the complete current target identity token;
- exact target capacity;
- current logical and physical sector sizes;
- one durable authenticated FFU trust-store root;
- one caller-provisioned trust-metadata public-key policy; and
- one explicit catalog-publisher policy.

It includes `--experimental-ffu` and `--json`. It never includes `pkexec`, `restore`, a confirmation phrase, a fixed-disk override, an automatic-unmount request, or any ordinary raw-writer option.

## Evidence correlation

The GTK-side normalizer treats the JSON as one correlated evidence set rather than a collection of display fields. It requires agreement among the source identity, target plan, full-flash validation plan, and live target preflight for:

- descriptor and authenticated-integrity SHA-256 identifiers;
- exact target path and identity;
- capacity and logical/physical sector geometry;
- mutation byte count;
- target-plan and full-flash plan identifiers; and
- the byte-exact destructive confirmation phrase.

The normalizer additionally requires complete source authentication, a resolved non-overlapping destination map, full-flash update type `0`, zero validation descriptors, a freshly rediscovered normal removable whole disk, running-system and protected-mount exclusion, no fixed-disk override, and execution remaining disabled throughout review.

## Mount handling

Mounted removable-media descendants are reported verbatim in the review summary. The graphical review performs no unmount and grants no authority to unmount. A later destructive transaction must handle any unmount under a separate guarded privilege boundary and must rerun the entire review after that state transition.

## User-visible result

A successful review can show:

- authenticated source path and size;
- exact target model, path, capacity and sector geometry;
- exact number of bytes that restoration would change;
- current mount state; and
- the exact destructive confirmation phrase.

The summary always states that the review was read-only and did not open or modify the target.

## Deliberate exclusions

This boundary adds no GTK dialog, no restore button, no administrator authentication, no subprocess execution, no target opening, no unmount, no confirmation collection, no writer, and no hardware or firmware-boot claim. Those remain separate reviewable gates.
