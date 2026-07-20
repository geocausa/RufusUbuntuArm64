"""Packaged RufusArm64 entry point with all reviewed main-window integrations."""

import sys

from gi.repository import Gtk

from rufusarm64_device_qualify_dialog import install_drive_backup
from rufusarm64_freedos_dialog import install_freedos
from rufusarm64_nonbootable_dialog import NonBootableFormatDialog, install_nonbootable


POST_OPERATION_RESTORE = 9101
POST_OPERATION_ANOTHER = 9102


def _selected_target(window):
    index = window.target_combo.get_active()
    selected = window.devices[index] if 0 <= index < len(window.devices) else None
    return (
        str((selected or {}).get("path") or ""),
        str((selected or {}).get("identity") or ""),
    )


def install_post_operation_reuse(window_class):
    """Install explicit, non-destructive next-step actions around the main writer."""
    if getattr(window_class, "_post_operation_reuse_installed", False):
        return

    original_init = window_class.__init__
    original_start = window_class.start
    original_finish = window_class.finish
    original_set_busy = window_class.set_busy

    def integrated_init(window, app):
        original_init(window, app)
        window._post_operation_pending = ("", "")
        window._post_operation_target = ("", "")

        window.nonbootable_button.set_label("Restore / format…")
        window.nonbootable_button.set_tooltip_text(
            "Erase the selected removable drive, remove any boot layout, and create one verified data-only filesystem"
        )

        bar = Gtk.InfoBar()
        bar.set_message_type(Gtk.MessageType.INFO)
        bar.set_show_close_button(True)
        bar.set_no_show_all(True)
        bar.connect("response", window.post_operation_response)
        bar.add_button("Restore drive for storage…", POST_OPERATION_RESTORE)
        bar.add_button("Create another USB", POST_OPERATION_ANOTHER)

        label = Gtk.Label()
        label.set_xalign(0)
        label.set_line_wrap(True)
        bar.get_content_area().add(label)
        window.post_operation_bar = bar
        window.post_operation_label = label

        parent = window.progress.get_parent()
        parent.pack_start(bar, False, False, 0)
        children = parent.get_children()
        parent.reorder_child(bar, children.index(window.progress_detail) + 1)

    def integrated_start(window, *args):
        window.hide_post_operation_actions()
        window._post_operation_pending = _selected_target(window)
        result = original_start(window, *args)
        if window.active_job != "writer":
            window._post_operation_pending = ("", "")
        return result

    def integrated_finish(window, return_code):
        target = window._post_operation_pending
        mode = str(getattr(window, "active_mode", "") or "")
        was_cancelled = bool(getattr(window, "cancel_requested", False))
        result = original_finish(window, return_code)
        window._post_operation_pending = ("", "")
        if all(target):
            window._post_operation_target = target
            if return_code == 0:
                window.show_post_operation_actions(
                    "USB creation is complete. Keep this bootable medium unchanged, create another copy from the selected image, "
                    "or erase its boot layout later and restore the whole drive as ordinary storage.",
                    Gtk.MessageType.INFO,
                )
            else:
                state = "was cancelled" if was_cancelled else "failed"
                window.show_post_operation_actions(
                    f"USB creation {state}. The selected drive may contain incomplete media. Recreate it or use Restore drive for "
                    "storage before ordinary file use.",
                    Gtk.MessageType.WARNING,
                )
            window.append_log(
                f"Post-operation actions are bound to {target[0]} ({target[1]}) after mode {mode or 'unknown'}."
            )
        return result

    def integrated_set_busy(window, busy):
        original_set_busy(window, busy)
        bar = getattr(window, "post_operation_bar", None)
        if bar is not None:
            bar.set_sensitive(not busy)

    def show_post_operation_actions(window, text, message_type):
        window.post_operation_label.set_text(text)
        window.post_operation_bar.set_message_type(message_type)
        window.post_operation_bar.set_no_show_all(False)
        window.post_operation_bar.show_all()

    def hide_post_operation_actions(window):
        bar = getattr(window, "post_operation_bar", None)
        if bar is None:
            return
        bar.hide()
        bar.set_no_show_all(True)

    def post_operation_response(window, _bar, response_id):
        if response_id == POST_OPERATION_ANOTHER:
            window.hide_post_operation_actions()
            window.progress.set_fraction(0.0)
            window.progress.set_text("Ready for another USB")
            window.progress_detail.set_text(
                "The image remains selected. Connect or choose another removable drive, check it carefully, then select Create USB."
            )
            window.refresh_devices()
            window.target_combo.grab_focus()
            return
        if response_id != POST_OPERATION_RESTORE:
            window.hide_post_operation_actions()
            return

        device, identity = window._post_operation_target
        window.hide_post_operation_actions()
        if not device or not identity:
            window.progress_detail.set_text("The completed operation target is no longer available. Select the drive and refresh first.")
            return
        dialog = NonBootableFormatDialog(window, device, identity)
        dialog.run()
        if dialog.running:
            return
        dialog.closed = True
        dialog.plan_generation += 1
        dialog.run_generation += 1
        dialog._remove_cancel_path()
        dialog.destroy()
        window.save_settings()
        window.refresh_devices()

    window_class.__init__ = integrated_init
    window_class.start = integrated_start
    window_class.finish = integrated_finish
    window_class.set_busy = integrated_set_busy
    window_class.show_post_operation_actions = show_post_operation_actions
    window_class.hide_post_operation_actions = hide_post_operation_actions
    window_class.post_operation_response = post_operation_response
    window_class._post_operation_reuse_installed = True


def run_rufusarm64(argv=None):
    """Run the main GTK application after installing the reviewed extensions."""
    from rufusarm64 import RufusApp, RufusWindow

    install_drive_backup(RufusWindow)
    install_nonbootable(RufusWindow)
    install_freedos(RufusWindow)
    install_post_operation_reuse(RufusWindow)
    return RufusApp().run(list(sys.argv[1:] if argv is None else argv))
