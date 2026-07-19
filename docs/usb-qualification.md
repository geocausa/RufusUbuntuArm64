# USB qualification

RufusArm64 includes a separate USB qualification workflow for checking reported capacity, aliased storage, and write/read reliability before creating boot media.

## Important

Qualification is destructive. Every selected test region is overwritten and existing files or partitions are not preserved. Use an empty removable USB drive.

The normal **Create USB** workflow does not run qualification automatically and is not changed by this feature.

## Graphical workflow

1. Select the removable drive in the main RufusArm64 window.
2. Choose **Check USB…**.
3. Select the quick or full profile.
4. Review the read-only plan.
5. Type the exact erase phrase displayed by the dialog.
6. Authenticate when prompted.
7. Review the deterministic report before reusing the drive.

The graphical path is restricted to removable targets, exact device identity, guarded unmounting, JSON output, and noninteractive execution after the dialog confirmation.

## Profiles

**Quick** samples distributed regions to detect common false-capacity or aliasing behaviour with less total I/O.

**Full** verifies the complete reported capacity using address-derived data. It can take a long time and is intended for final device qualification.

## Command-line workflow

Use `rufusarm64-cli list --json` to obtain the current device path and identity token. The dedicated `rufusarm64-device-qualify` command supports a read-only dry run and explicit terminal confirmation. See `man rufusarm64-device-qualify` for the complete interface.

A device must be selected again after reconnecting it because identity and capacity are revalidated immediately before the first write and throughout the run.
