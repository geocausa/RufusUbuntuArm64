"""Packaged RufusArm64 entry point with all reviewed main-window integrations."""

import sys

from rufusarm64_device_qualify_dialog import install_drive_backup
from rufusarm64_freedos_dialog import install_freedos
from rufusarm64_nonbootable_dialog import install_nonbootable


def run_rufusarm64(argv=None):
    """Run the main GTK application after installing the reviewed extensions."""
    from rufusarm64 import RufusApp, RufusWindow

    install_drive_backup(RufusWindow)
    install_nonbootable(RufusWindow)
    install_freedos(RufusWindow)
    return RufusApp().run(list(sys.argv[1:] if argv is None else argv))
