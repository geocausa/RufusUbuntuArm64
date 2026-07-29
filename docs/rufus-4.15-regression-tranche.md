# Rufus 4.15 regression tranche

This branch closes the next bounded parity regressions against pinned upstream Rufus 4.15 commit `6d8fbf98305ff37eb531c45cbd6ff44563c53917`.

Planned scope:

- direct SquashFS superblock recognition without weakening the bootable-image safety gate;
- bounded Windows WIM/ESD/SWM payload corpus and refusal coverage;
- explicit GTK runtime-validation enablement-state coverage;
- cancellation between partial write attempts and compressed preparation progress regressions.

Physical-media and universal compatibility claims remain outside this software-only tranche.
