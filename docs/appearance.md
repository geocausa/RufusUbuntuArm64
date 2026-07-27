# RufusArm64 appearance modes

RufusArm64 provides one application-scoped appearance selector in the main-window header bar.

- **System** is the default. It follows the GTK light/dark preference observed when RufusArm64 starts.
- **Light** asks GTK to use the light variant of the active desktop theme for RufusArm64.
- **Dark** asks GTK to use the dark variant of the active desktop theme for RufusArm64.

The choice applies process-wide to the composed main window and its dialogs. It does not change the desktop theme or another application's settings.

The canonical value is stored as `appearance` in the existing user settings file at `$XDG_CONFIG_HOME/rufusarm64/settings.json` (normally `~/.config/rufusarm64/settings.json`). Only `system`, `light`, and `dark` are accepted. Missing, malformed, or unknown values resolve to `system`.

Returning to **System** restores the desktop preference that was present when the current RufusArm64 process started. Restart RufusArm64 after changing the desktop-wide theme if an already-running explicit override should adopt the new system state.

Changing appearance is a presentation-only operation. It does not alter selected image or device identities, destructive confirmations, privilege separation, cancellation, verification, or operation reports.
