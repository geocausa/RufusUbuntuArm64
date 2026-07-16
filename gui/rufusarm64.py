#!/usr/bin/env python3
"""RufusArm64 GTK front end.

The GUI remains unprivileged. Destructive operations are delegated to the
package-owned Go helper through pkexec after the user confirms the exact drive.
"""

import json
from datetime import datetime, timezone
import os
import platform
import shutil
import signal
import subprocess
import tempfile
import threading

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import GLib, Gtk

from rufusarm64_logic import (
    acquisition_image_label,
    build_acquisition_download_command,
    build_acquisition_list_command,
    build_persistence_plan_command,
    build_writer_command,
    device_label,
    human_bytes,
    normalize_acquisition_images,
    persistence_plan_summary,
    progress_status,
    normalize_cluster_size,
    normalize_filesystem,
    normalize_partition_scheme,
    normalize_target_system,
    normalize_volume_label,
    success_message,
    normalize_windows_locale,
    supported_image_name,
    validate_local_username,
    windows_timezone_for_iana,
)

APP_ID = "io.github.geocausa.RufusArm64"
APP_NAME = "RufusArm64"
VERSION = "0.9.0"
INSTALLED_HELPER = os.environ.get("RUFUSARM64_HELPER", "/usr/lib/rufusarm64/rufusarm64-helper")
BUNDLED_WIMLIB = os.environ.get("RUFUSARM64_WIMLIB", "/usr/lib/rufusarm64/wimlib-imagex")
PKEXEC = "/usr/bin/pkexec"


def helper_path():
    return INSTALLED_HELPER


def config_path():
    directory = os.path.join(GLib.get_user_config_dir(), "rufusarm64")
    return directory, os.path.join(directory, "settings.json")


def current_regional_settings():
    locale_value = ""
    for name in ("LC_ALL", "LC_MESSAGES", "LANG"):
        locale_value = normalize_windows_locale(os.environ.get(name, ""))
        if locale_value:
            break

    iana_zone = ""
    try:
        with open("/etc/timezone", "r", encoding="utf-8") as handle:
            iana_zone = handle.read().strip()
    except OSError:
        try:
            target = os.path.realpath("/etc/localtime")
            marker = "/usr/share/zoneinfo/"
            if marker in target:
                iana_zone = target.split(marker, 1)[1]
        except OSError:
            pass
    return locale_value, windows_timezone_for_iana(iana_zone), iana_zone


class WindowsOptionsDialog(Gtk.Dialog):
    """Explicit opt-in Windows Setup customizations."""

    def __init__(self, parent, previous=None):
        super().__init__(title="Windows installation options", transient_for=parent, modal=True)
        self.add_button("Cancel", Gtk.ResponseType.CANCEL)
        self.add_button("Continue", Gtk.ResponseType.OK)
        self.set_default_response(Gtk.ResponseType.OK)
        self.set_default_size(620, 560)
        previous = dict(previous or {})

        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_min_content_height(420)
        self.get_content_area().pack_start(scroll, True, True, 0)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_border_width(18)
        scroll.add(box)

        title = Gtk.Label()
        title.set_markup("<span size='large' weight='bold'>Customize Windows Setup</span>")
        title.set_xalign(0)
        box.pack_start(title, False, False, 0)

        intro = Gtk.Label(
            label=(
                "Every option below is optional. RufusArm64 creates an autounattend.xml file on the USB; "
                "the Windows ISO itself is not changed. Leave everything unchecked for standard Microsoft setup."
            )
        )
        intro.set_xalign(0)
        intro.set_line_wrap(True)
        box.pack_start(intro, False, False, 0)

        self.bypass_hardware = self.check(
            box,
            "Remove TPM 2.0, Secure Boot and minimum-RAM checks",
            "Useful for unsupported PCs. This normally is not needed on a Surface Pro 11 X1E.",
            previous.get("bypass_hardware", False),
        )
        self.bypass_online = self.check(
            box,
            "Remove the Microsoft online-account requirement",
            "Allows Windows setup to continue with a local account when supported by that Windows build.",
            previous.get("bypass_online_account", False),
        )

        self.local_account = Gtk.CheckButton(label="Create a local administrator account")
        self.local_account.set_active(bool(previous.get("local_user")))
        box.pack_start(self.local_account, False, False, 0)
        account_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        account_row.set_margin_start(28)
        account_label = Gtk.Label(label="Account name")
        account_label.set_xalign(0)
        self.local_user = Gtk.Entry()
        self.local_user.set_max_length(20)
        self.local_user.set_placeholder_text("geoca")
        self.local_user.set_text(previous.get("local_user", ""))
        account_row.pack_start(account_label, False, False, 0)
        account_row.pack_start(self.local_user, True, True, 0)
        box.pack_start(account_row, False, False, 0)
        self.local_account.connect("toggled", lambda button: self.local_user.set_sensitive(button.get_active()))
        self.local_user.set_sensitive(self.local_account.get_active())

        self.reduce_data = self.check(
            box,
            "Skip privacy prompts and reduce initial data collection/recommendations",
            "Sets Windows Setup privacy choices and disables advertising/consumer-content policies where supported.",
            previous.get("reduce_data_collection", False),
        )
        self.region_locale, self.region_timezone, self.region_iana = current_regional_settings()
        region_parts = []
        if self.region_locale:
            region_parts.append(f"locale {self.region_locale}")
        if self.region_timezone:
            region_parts.append(f"time zone {self.region_timezone}")
        region_detail = (
            "Applies " + " and ".join(region_parts) + " during Windows Setup."
            if region_parts
            else "Ubuntu's current locale or time zone could not be mapped safely to Windows."
        )
        self.use_region = self.check(
            box,
            "Use this Ubuntu user's regional settings",
            region_detail,
            previous.get("use_regional_settings", False) and bool(region_parts),
        )
        self.use_region.set_sensitive(bool(region_parts))
        self.disable_bitlocker = self.check(
            box,
            "Disable automatic BitLocker device-encryption provisioning",
            "Does not decrypt an existing installation. It prevents automatic encryption during this new setup where supported.",
            previous.get("disable_bitlocker", False),
        )

        warning = Gtk.InfoBar()
        warning.set_message_type(Gtk.MessageType.INFO)
        note = Gtk.Label(
            label=(
                "Microsoft can change unattended-setup behavior between Windows releases. RufusArm64 validates the answer file, "
                "but Windows may ignore an option that a future build no longer supports."
            )
        )
        note.set_xalign(0)
        note.set_line_wrap(True)
        warning.get_content_area().add(note)
        box.pack_start(warning, False, False, 0)
        self.show_all()

    @staticmethod
    def check(parent, title, detail, active):
        check = Gtk.CheckButton(label=title)
        check.set_active(bool(active))
        parent.pack_start(check, False, False, 0)
        label = Gtk.Label(label=detail)
        label.set_xalign(0)
        label.set_line_wrap(True)
        label.set_margin_start(28)
        label.get_style_context().add_class("dim-label")
        parent.pack_start(label, False, False, 0)
        return check

    def values(self):
        local_user = ""
        if self.local_account.get_active():
            local_user = validate_local_username(self.local_user.get_text())
            if not local_user:
                raise ValueError("Enter a local account name or turn off local-account creation.")
        return {
            "bypass_hardware": self.bypass_hardware.get_active(),
            "bypass_online_account": self.bypass_online.get_active(),
            "local_user": local_user,
            "reduce_data_collection": self.reduce_data.get_active(),
            "disable_bitlocker": self.disable_bitlocker.get_active(),
            "use_regional_settings": self.use_region.get_active(),
            "locale": self.region_locale if self.use_region.get_active() else "",
            "timezone": self.region_timezone if self.use_region.get_active() else "",
        }


class AcquisitionDialog(Gtk.Dialog):
    """Select and verify a local signed acquisition catalog."""

    def __init__(self, parent, settings):
        super().__init__(title="Download a verified image", transient_for=parent, modal=True)
        self.add_button("Cancel", Gtk.ResponseType.CANCEL)
        self.add_button("Download", Gtk.ResponseType.OK)
        self.set_default_response(Gtk.ResponseType.OK)
        self.set_default_size(720, 470)
        self.images = []
        self.get_widget_for_response(Gtk.ResponseType.OK).set_sensitive(False)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_border_width(18)
        self.get_content_area().pack_start(box, True, True, 0)

        intro = Gtk.Label(label=(
            "RufusArm64 accepts images only from a catalog whose detached Ed25519 signature verifies with the selected trusted public key. "
            "This first graphical workflow uses local catalog files; a built-in online catalog will be added after a reviewed key-rotation policy."
        ))
        intro.set_xalign(0)
        intro.set_line_wrap(True)
        box.pack_start(intro, False, False, 0)

        grid = Gtk.Grid(column_spacing=12, row_spacing=10)
        box.pack_start(grid, False, False, 0)
        self.catalog = self._chooser(grid, "Catalog", 0, Gtk.FileChooserAction.OPEN, settings.get("acquisition_catalog", ""))
        self.signature = self._chooser(grid, "Signature", 1, Gtk.FileChooserAction.OPEN, settings.get("acquisition_signature", ""))
        self.public_key = self._chooser(grid, "Public key", 2, Gtk.FileChooserAction.OPEN, settings.get("acquisition_public_key", ""))
        default_downloads = GLib.get_user_special_dir(GLib.UserDirectory.DIRECTORY_DOWNLOAD) or os.path.join(os.path.expanduser("~"), "Downloads")
        self.output = self._chooser(grid, "Download folder", 3, Gtk.FileChooserAction.SELECT_FOLDER, settings.get("acquisition_output", default_downloads))
        self.output.connect("file-set", self.image_selected)

        verify_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.verify_button = Gtk.Button(label="Verify catalog")
        self.verify_button.connect("clicked", self.verify_catalog)
        verify_row.pack_start(self.verify_button, False, False, 0)
        self.catalog_status = Gtk.Label(label="Choose all three trust files, then verify the catalog.")
        self.catalog_status.set_xalign(0)
        self.catalog_status.set_line_wrap(True)
        verify_row.pack_start(self.catalog_status, True, True, 0)
        box.pack_start(verify_row, False, False, 0)

        self.image_combo = Gtk.ComboBoxText()
        self.image_combo.set_hexpand(True)
        self.image_combo.connect("changed", self.image_selected)
        box.pack_start(self.image_combo, False, False, 0)
        self.image_detail = Gtk.Label(label="No verified image selected.")
        self.image_detail.set_xalign(0)
        self.image_detail.set_line_wrap(True)
        self.image_detail.get_style_context().add_class("dim-label")
        box.pack_start(self.image_detail, False, False, 0)
        self.show_all()

    @staticmethod
    def _chooser(grid, label_text, row, action, saved):
        label = Gtk.Label(label=label_text)
        label.set_xalign(0)
        chooser = Gtk.FileChooserButton(title=f"Choose {label_text.lower()}", action=action)
        chooser.set_hexpand(True)
        if saved and (os.path.isfile(saved) if action == Gtk.FileChooserAction.OPEN else os.path.isdir(saved)):
            chooser.set_filename(saved)
        grid.attach(label, 0, row, 1, 1)
        grid.attach(chooser, 1, row, 1, 1)
        return chooser

    def verify_catalog(self, *_):
        try:
            command = build_acquisition_list_command(
                helper_path(), self.catalog.get_filename(), self.signature.get_filename(), self.public_key.get_filename()
            )
            result = subprocess.run(command, check=False, text=True, capture_output=True, timeout=20)
            if result.returncode != 0:
                raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "Catalog verification failed")
            self.images = normalize_acquisition_images(json.loads(result.stdout))
        except Exception as exc:
            self.images = []
            self.image_combo.remove_all()
            self.catalog_status.set_text(f"Catalog rejected: {exc}")
            self.get_widget_for_response(Gtk.ResponseType.OK).set_sensitive(False)
            return
        self.image_combo.remove_all()
        for image in self.images:
            self.image_combo.append(image["id"], acquisition_image_label(image))
        self.image_combo.set_active(0)
        self.catalog_status.set_text(f"Signature valid. {len(self.images)} downloadable image(s) are available.")

    def image_selected(self, *_):
        image_id = self.image_combo.get_active_id()
        image = next((item for item in self.images if item["id"] == image_id), None)
        self.get_widget_for_response(Gtk.ResponseType.OK).set_sensitive(bool(image and self.output.get_filename()))
        if image:
            digest = f"\nSHA-256: {image['sha256']}" if image.get("sha256") else ""
            self.image_detail.set_text(f"File: {image['filename']}\nSize: {human_bytes(image['size'])}{digest}")

    def values(self):
        image_id = self.image_combo.get_active_id()
        image = next((item for item in self.images if item["id"] == image_id), None)
        if not image:
            raise ValueError("Verify the catalog and choose an image first.")
        return {
            "catalog": self.catalog.get_filename() or "",
            "signature": self.signature.get_filename() or "",
            "public_key": self.public_key.get_filename() or "",
            "output": self.output.get_filename() or "",
            "image": image,
        }


class PersistencePlanDialog(Gtk.Dialog):
    """Collect the read-only inputs required by the persistence planner."""

    def __init__(self, parent, settings):
        super().__init__(title="Analyze Linux persistence compatibility", transient_for=parent, modal=True)
        self.add_button("Cancel", Gtk.ResponseType.CANCEL)
        self.add_button("Analyze", Gtk.ResponseType.OK)
        self.set_default_response(Gtk.ResponseType.OK)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_border_width(18)
        self.get_content_area().pack_start(box, True, True, 0)
        intro = Gtk.Label(label=(
            "Choose the read-only mounted or extracted root of the selected Ubuntu or Debian image. "
            "Analysis does not modify the image or USB drive."
        ))
        intro.set_xalign(0)
        intro.set_line_wrap(True)
        box.pack_start(intro, False, False, 0)
        grid = Gtk.Grid(column_spacing=12, row_spacing=10)
        box.pack_start(grid, False, False, 0)
        label = Gtk.Label(label="Mounted media folder")
        label.set_xalign(0)
        self.media_root = Gtk.FileChooserButton(title="Choose mounted Linux media", action=Gtk.FileChooserAction.SELECT_FOLDER)
        saved = settings.get("persistence_media_root", "")
        if saved and os.path.isdir(saved):
            self.media_root.set_filename(saved)
        grid.attach(label, 0, 0, 1, 1)
        grid.attach(self.media_root, 1, 0, 1, 1)
        size_label = Gtk.Label(label="Persistence size")
        size_label.set_xalign(0)
        self.size = Gtk.SpinButton.new_with_range(0, 1024, 1)
        self.size.set_value(int(settings.get("persistence_size_gib", 16)))
        self.size.set_tooltip_text("GiB. Zero asks the planner to use all suitable remaining capacity.")
        size_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        size_box.pack_start(self.size, False, False, 0)
        size_box.pack_start(Gtk.Label(label="GiB (0 = remaining space)"), False, False, 0)
        grid.attach(size_label, 0, 1, 1, 1)
        grid.attach(size_box, 1, 1, 1, 1)
        note = Gtk.Label(label="Persistent USB creation remains experimental and command-line only; this screen only explains compatibility and sizing.")
        note.set_xalign(0)
        note.set_line_wrap(True)
        note.get_style_context().add_class("dim-label")
        box.pack_start(note, False, False, 0)
        self.show_all()

    def values(self):
        root = self.media_root.get_filename() or ""
        if not root:
            raise ValueError("Choose the mounted or extracted Linux media folder.")
        return root, int(self.size.get_value())


class RufusWindow(Gtk.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app)
        self.set_title(APP_NAME)
        self.set_size_request(600, 430)
        self.devices = []
        self.process = None
        self.busy = False
        self.cancel_requested = False
        self.cancel_path = None
        self.inspection = {}
        self.windows_options = {}
        self.last_status_key = None
        self.active_verify_requested = False
        self.active_mode = ""
        self.active_filesystem = "auto"
        self.active_job = ""
        self.operation_started_at = None
        self.download_result = {}
        self.settings = self.load_settings()
        width = max(600, int(self.settings.get("width", 820)))
        height = max(430, int(self.settings.get("height", 700)))
        self.set_default_size(width, height)
        if self.settings.get("maximized"):
            self.maximize()
        self.connect("delete-event", self.on_delete_event)
        self.connect("configure-event", self.on_configure)
        self.connect("window-state-event", self.on_window_state)

        header = Gtk.HeaderBar(title=APP_NAME, subtitle="Bootable USB creator for Linux ARM64")
        header.set_show_close_button(True)
        self.set_titlebar(header)
        about_button = Gtk.Button.new_from_icon_name("help-about-symbolic", Gtk.IconSize.BUTTON)
        about_button.set_tooltip_text("About RufusArm64")
        about_button.connect("clicked", self.show_about)
        header.pack_end(about_button)

        root_scroll = Gtk.ScrolledWindow()
        root_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        self.add(root_scroll)
        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        outer.set_border_width(18)
        root_scroll.add(outer)

        intro = Gtk.Label()
        intro.set_markup("<span size='large' weight='bold'>Create a bootable USB drive</span>")
        intro.set_xalign(0)
        outer.pack_start(intro, False, False, 0)

        description = Gtk.Label(
            label=(
                "Choose an image and a removable USB drive. Raw, ISOHybrid, compressed, and common virtual-disk images are supported. "
                "Windows installation ISOs can use GPT or MBR layouts, FAT32/NTFS selection, WIM splitting, and UEFI:NTFS."
            )
        )
        description.set_xalign(0)
        description.set_line_wrap(True)
        outer.pack_start(description, False, False, 0)

        grid = Gtk.Grid(column_spacing=12, row_spacing=12)
        grid.set_hexpand(True)
        outer.pack_start(grid, False, False, 0)
        self.attach_label(grid, "Boot image", 0)
        self.image_chooser = Gtk.FileChooserButton(title="Choose an ISO or disk image", action=Gtk.FileChooserAction.OPEN)
        self.image_chooser.set_hexpand(True)
        self.image_chooser.connect("file-set", self.image_changed)
        image_filter = Gtk.FileFilter()
        image_filter.set_name("ISO and disk images")
        for suffix in ("iso", "img", "raw", "bin", "zip", "gz", "bz2", "xz", "lzma", "zst", "vhd", "vhdx", "qcow", "qcow2", "vmdk", "ffu"):
            image_filter.add_pattern(f"*.{suffix}")
            image_filter.add_pattern(f"*.{suffix.upper()}")
        self.image_chooser.add_filter(image_filter)
        image_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        image_row.pack_start(self.image_chooser, True, True, 0)
        self.download_button = Gtk.Button(label="Download…")
        self.download_button.set_tooltip_text("Choose an image from a locally supplied, Ed25519-signed catalog")
        self.download_button.connect("clicked", self.open_acquisition)
        image_row.pack_start(self.download_button, False, False, 0)
        grid.attach(image_row, 1, 0, 2, 1)

        self.attach_label(grid, "USB drive", 1)
        self.target_combo = Gtk.ComboBoxText()
        self.target_combo.set_hexpand(True)
        grid.attach(self.target_combo, 1, 1, 1, 1)
        self.refresh_button = Gtk.Button.new_from_icon_name("view-refresh-symbolic", Gtk.IconSize.BUTTON)
        self.refresh_button.set_tooltip_text("Refresh connected USB drives")
        self.refresh_button.connect("clicked", lambda *_: self.refresh_devices())
        grid.attach(self.refresh_button, 2, 1, 1, 1)

        self.attach_label(grid, "Image option", 2)
        self.mode_value = self.value_label("Choose an image")
        grid.attach(self.mode_value, 1, 2, 2, 1)

        self.verify = Gtk.CheckButton(label="Verify copied data after writing")
        self.verify.set_active(bool(self.settings.get("verify", True)))
        self.verify.set_tooltip_text("Recommended. Verification takes additional time but detects faulty media or writes.")
        self.verify.connect("toggled", self.verify_changed)
        grid.attach(self.verify, 1, 3, 2, 1)
        self.verify_warning = Gtk.Label()
        self.verify_warning.set_xalign(0)
        self.verify_warning.set_line_wrap(True)
        self.verify_warning.set_margin_start(28)
        self.verify_warning.get_style_context().add_class("dim-label")
        grid.attach(self.verify_warning, 1, 4, 2, 1)

        advanced = Gtk.Expander(label="Advanced drive properties")
        advanced.set_expanded(bool(self.settings.get("advanced", False)))
        advanced.connect("notify::expanded", lambda widget, *_: self.remember_advanced(widget.get_expanded()))
        adv_grid = Gtk.Grid(column_spacing=12, row_spacing=10)
        adv_grid.set_margin_top(10)
        advanced.add(adv_grid)
        outer.pack_start(advanced, False, False, 0)

        persistence = Gtk.Expander(label="Linux persistence compatibility (experimental)")
        persistence_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        persistence_box.set_margin_top(8)
        persistence_intro = Gtk.Label(label=(
            "Analyze supported Ubuntu casper or Debian live-boot media before using the experimental command-line creator. "
            "This analysis is read-only."
        ))
        persistence_intro.set_xalign(0)
        persistence_intro.set_line_wrap(True)
        persistence_box.pack_start(persistence_intro, False, False, 0)
        self.persistence_button = Gtk.Button(label="Analyze selected image…")
        self.persistence_button.set_halign(Gtk.Align.START)
        self.persistence_button.connect("clicked", self.analyze_persistence)
        persistence_box.pack_start(self.persistence_button, False, False, 0)
        self.persistence_summary = Gtk.Label(label="Select a recognized Linux ISOHybrid image and USB drive.")
        self.persistence_summary.set_xalign(0)
        self.persistence_summary.set_line_wrap(True)
        self.persistence_summary.set_selectable(True)
        self.persistence_summary.get_style_context().add_class("dim-label")
        persistence_box.pack_start(self.persistence_summary, False, False, 0)
        persistence.add(persistence_box)
        outer.pack_start(persistence, False, False, 0)

        self.attach_label(adv_grid, "Partition scheme", 0)
        self.partition_combo = Gtk.ComboBoxText()
        self.partition_combo.append("gpt", "GPT")
        self.partition_combo.append("mbr", "MBR")
        self.partition_combo.append("from-image", "From image")
        saved_scheme = self.settings.get("partition_scheme", "gpt")
        self.windows_partition_scheme = saved_scheme if saved_scheme in {"gpt", "mbr"} else "gpt"
        self.partition_combo.set_active_id(self.windows_partition_scheme)
        self.partition_combo.connect("changed", self.partition_changed)
        adv_grid.attach(self.partition_combo, 1, 0, 1, 1)
        self.attach_label(adv_grid, "Target system", 1)
        self.target_system_combo = Gtk.ComboBoxText()
        self.target_system_combo.append("uefi", "UEFI (non-CSM)")
        self.target_system_combo.append("bios", "BIOS or UEFI-CSM")
        self.target_system_combo.append("from-image", "From image")
        saved_target = str(self.settings.get("target_system", "uefi"))
        self.windows_target_system = saved_target if saved_target in {"uefi", "bios"} else "uefi"
        self.target_system_combo.set_active_id(self.windows_target_system)
        self.target_system_combo.connect("changed", self.target_system_changed)
        adv_grid.attach(self.target_system_combo, 1, 1, 1, 1)
        self.attach_label(adv_grid, "File system", 2)
        self.filesystem_combo = Gtk.ComboBoxText()
        self.filesystem_combo.append("auto", "Automatic")
        self.filesystem_combo.append("fat32", "FAT32")
        self.filesystem_combo.append("ntfs", "NTFS")
        self.filesystem_combo.append("from-image", "From image")
        saved_filesystem = str(self.settings.get("filesystem", "auto"))
        self.windows_filesystem = saved_filesystem if saved_filesystem in {"auto", "fat32", "ntfs"} else "auto"
        self.filesystem_combo.set_active_id(self.windows_filesystem)
        self.filesystem_combo.connect("changed", self.filesystem_changed)
        adv_grid.attach(self.filesystem_combo, 1, 2, 1, 1)

        self.attach_label(adv_grid, "Cluster size", 3)
        self.cluster_combo = Gtk.ComboBoxText()
        for identifier, text in (("auto", "Automatic"), ("4096", "4 KiB"), ("8192", "8 KiB"), ("16384", "16 KiB"), ("32768", "32 KiB")):
            self.cluster_combo.append(identifier, text)
        self.cluster_combo.append("from-image", "From image")
        saved_cluster = str(self.settings.get("cluster_size", "auto"))
        self.windows_cluster_size = saved_cluster if saved_cluster in {"auto", "4096", "8192", "16384", "32768"} else "auto"
        self.cluster_combo.set_active_id(self.windows_cluster_size)
        adv_grid.attach(self.cluster_combo, 1, 3, 1, 1)

        self.attach_label(adv_grid, "Volume label", 4)
        self.volume_label = Gtk.Entry()
        self.volume_label.set_max_length(11)
        self.volume_label.set_text(self.settings.get("volume_label", "RUFUSARM64"))
        adv_grid.attach(self.volume_label, 1, 4, 1, 1)

        self.attach_label(adv_grid, "Windows drivers", 5)
        self.driver_chooser = Gtk.FileChooserButton(
            title="Choose an optional Windows driver folder",
            action=Gtk.FileChooserAction.SELECT_FOLDER,
        )
        saved_driver_folder = self.settings.get("driver_folder", "")
        if saved_driver_folder and os.path.isdir(saved_driver_folder):
            self.driver_chooser.set_filename(saved_driver_folder)
        self.driver_chooser.set_tooltip_text(
            "Optional. Copies signed .inf driver packages to USB\\drivers and auto-loads them in Windows PE; the Load driver button remains available as a fallback."
        )
        adv_grid.attach(self.driver_chooser, 1, 5, 1, 1)

        self.attach_label(adv_grid, "Secure Boot DBX", 6)
        dbx_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.dbx_chooser = Gtk.FileChooserButton(
            title="Choose a Microsoft DBXUpdate.bin file",
            action=Gtk.FileChooserAction.OPEN,
        )
        dbx_filter = Gtk.FileFilter()
        dbx_filter.set_name("UEFI DBX updates")
        dbx_filter.add_pattern("*.bin")
        self.dbx_chooser.add_filter(dbx_filter)
        saved_dbx = self.settings.get("dbx_file", "")
        if saved_dbx and os.path.isfile(saved_dbx):
            self.dbx_chooser.set_filename(saved_dbx)
        self.dbx_chooser.set_tooltip_text(
            "Optional. Rejects Windows EFI boot files whose direct Authenticode hash or embedded signing certificate appears in the selected DBX."
        )
        dbx_row.pack_start(self.dbx_chooser, True, True, 0)
        self.dbx_update_button = Gtk.Button(label="Update")
        self.dbx_update_button.set_tooltip_text("Download the current architecture-specific DBXUpdate.bin from Microsoft's secureboot_objects repository.")
        self.dbx_update_button.connect("clicked", self.update_dbx)
        dbx_row.pack_start(self.dbx_update_button, False, False, 0)
        adv_grid.attach(dbx_row, 1, 6, 1, 1)

        self.quick_format = Gtk.CheckButton(label="Quick format")
        self.quick_format.set_active(bool(self.settings.get("quick_format", True)))
        self.quick_format.set_tooltip_text("Disable to zero-write the entire new data partition before formatting. This can take a long time.")
        adv_grid.attach(self.quick_format, 1, 7, 1, 1)
        self.bad_block_check = Gtk.CheckButton(label="Check device for bad blocks (1 pass)")
        self.bad_block_check.set_active(bool(self.settings.get("bad_block_check", False)))
        self.bad_block_check.set_tooltip_text("Zero-writes and reads back the entire new data partition before formatting. This is slow and destructive.")
        self.bad_block_check.connect("toggled", self.bad_block_toggled)
        adv_grid.attach(self.bad_block_check, 1, 8, 1, 1)
        self.layout_note = Gtk.Label(label="Settings will be selected after the image is inspected.")
        self.layout_note.set_xalign(0)
        self.layout_note.set_line_wrap(True)
        self.layout_note.get_style_context().add_class("dim-label")
        adv_grid.attach(self.layout_note, 1, 9, 1, 1)

        wim_engine = "Bundled WIM engine" if os.access(BUNDLED_WIMLIB, os.X_OK) else (
            "System WIM engine (wimtools)" if shutil.which("wimlib-imagex") else "WIM engine not installed"
        )
        self.wim_status = Gtk.Label(label=wim_engine)
        self.wim_status.set_xalign(0)
        self.wim_status.get_style_context().add_class("dim-label")
        adv_grid.attach(self.wim_status, 1, 10, 1, 1)

        arm_note = Gtk.Label(
            label="For Surface Pro 11 X1E, use an official Windows ARM64 ISO with UEFI. BIOS/CSM media are only for x86/x86-64 PCs."
        )
        arm_note.set_xalign(0)
        arm_note.set_line_wrap(True)
        arm_note.get_style_context().add_class("dim-label")
        outer.pack_start(arm_note, False, False, 0)

        warning = Gtk.InfoBar()
        warning.set_message_type(Gtk.MessageType.WARNING)
        warning_label = Gtk.Label(label="Everything on the selected USB drive will be permanently erased.")
        warning_label.set_xalign(0)
        warning.get_content_area().add(warning_label)
        outer.pack_start(warning, False, False, 0)

        self.progress = Gtk.ProgressBar(show_text=True)
        self.progress.set_text("Ready")
        outer.pack_start(self.progress, False, False, 0)
        self.progress_detail = Gtk.Label(label="Select an image and a removable USB drive.")
        self.progress_detail.set_xalign(0)
        self.progress_detail.set_line_wrap(True)
        self.progress_detail.get_style_context().add_class("dim-label")
        outer.pack_start(self.progress_detail, False, False, 0)

        details = Gtk.Expander(label="Details and diagnostics")
        details.set_expanded(bool(self.settings.get("details", False)))
        details.connect("notify::expanded", lambda widget, *_: self.remember_details(widget.get_expanded()))
        details_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        details_box.set_margin_top(8)
        details_actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        details_actions.set_halign(Gtk.Align.END)
        self.copy_log_button = Gtk.Button(label="Copy")
        self.copy_log_button.connect("clicked", self.copy_log)
        details_actions.pack_start(self.copy_log_button, False, False, 0)
        self.save_log_button = Gtk.Button(label="Save…")
        self.save_log_button.connect("clicked", self.save_log)
        details_actions.pack_start(self.save_log_button, False, False, 0)
        self.clear_log_button = Gtk.Button(label="Clear")
        self.clear_log_button.connect("clicked", self.clear_log)
        details_actions.pack_start(self.clear_log_button, False, False, 0)
        details_box.pack_start(details_actions, False, False, 0)
        scroll = Gtk.ScrolledWindow()
        scroll.set_hexpand(True)
        scroll.set_vexpand(True)
        scroll.set_min_content_height(160)
        self.log = Gtk.TextView(editable=False, cursor_visible=False, monospace=True, wrap_mode=Gtk.WrapMode.WORD_CHAR)
        scroll.add(self.log)
        details_box.pack_start(scroll, True, True, 0)
        details.add(details_box)
        outer.pack_start(details, True, True, 0)

        buttons = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        buttons.set_halign(Gtk.Align.END)
        outer.pack_start(buttons, False, False, 0)
        self.cancel_button = Gtk.Button(label="Cancel")
        self.cancel_button.set_sensitive(False)
        self.cancel_button.connect("clicked", self.cancel)
        buttons.pack_start(self.cancel_button, False, False, 0)
        self.start_button = Gtk.Button(label="Create USB")
        self.start_button.get_style_context().add_class("suggested-action")
        self.start_button.connect("clicked", self.start)
        buttons.pack_start(self.start_button, False, False, 0)

        self.update_verify_warning()
        self.refresh_devices()

    @staticmethod
    def attach_label(grid, text, row):
        label = Gtk.Label(label=text)
        label.set_xalign(0)
        label.set_valign(Gtk.Align.CENTER)
        grid.attach(label, 0, row, 1, 1)

    @staticmethod
    def value_label(text):
        label = Gtk.Label(label=text)
        label.set_xalign(0)
        label.set_line_wrap(True)
        return label

    def load_settings(self):
        _, path = config_path()
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
                return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def save_settings(self):
        directory, path = config_path()
        self.settings["verify"] = self.verify.get_active()
        scheme = self.partition_combo.get_active_id()
        target_system = self.target_system_combo.get_active_id()
        filesystem = self.filesystem_combo.get_active_id()
        cluster = self.cluster_combo.get_active_id()
        if scheme in {"gpt", "mbr"}:
            self.windows_partition_scheme = scheme
        if target_system in {"uefi", "bios"}:
            self.windows_target_system = target_system
        if filesystem in {"auto", "fat32", "ntfs"}:
            self.windows_filesystem = filesystem
        if cluster in {"auto", "4096", "8192", "16384", "32768"}:
            self.windows_cluster_size = cluster
        self.settings["partition_scheme"] = self.windows_partition_scheme
        self.settings["target_system"] = self.windows_target_system
        self.settings["filesystem"] = self.windows_filesystem
        self.settings["cluster_size"] = self.windows_cluster_size
        self.settings["driver_folder"] = self.driver_chooser.get_filename() or ""
        self.settings["dbx_file"] = self.dbx_chooser.get_filename() or ""
        self.settings["quick_format"] = self.quick_format.get_active()
        self.settings["bad_block_check"] = self.bad_block_check.get_active()
        try:
            self.settings["volume_label"] = normalize_volume_label(
                self.volume_label.get_text(), self.windows_filesystem
            )
        except ValueError:
            pass
        try:
            os.makedirs(directory, mode=0o700, exist_ok=True)
            temporary = path + ".tmp"
            with open(temporary, "w", encoding="utf-8") as handle:
                json.dump(self.settings, handle, indent=2, sort_keys=True)
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
        except OSError:
            pass

    def on_configure(self, *_):
        if not self.is_maximized():
            width, height = self.get_size()
            self.settings["width"] = width
            self.settings["height"] = height
        return False

    def on_window_state(self, *_):
        self.settings["maximized"] = self.is_maximized()
        return False

    def remember_advanced(self, expanded):
        self.settings["advanced"] = bool(expanded)

    def remember_details(self, expanded):
        self.settings["details"] = bool(expanded)

    def log_text(self):
        buffer_ = self.log.get_buffer()
        return buffer_.get_text(buffer_.get_start_iter(), buffer_.get_end_iter(), True)

    def append_log(self, text):
        text = str(text).strip()
        if not text:
            return False
        timestamp = datetime.now().astimezone().strftime("%H:%M:%S")
        buffer_ = self.log.get_buffer()
        buffer_.insert(buffer_.get_end_iter(), f"[{timestamp}] {text}\n")
        mark = buffer_.create_mark(None, buffer_.get_end_iter(), False)
        self.log.scroll_to_mark(mark, 0.0, True, 0.0, 1.0)
        return False

    def diagnostic_report(self):
        image = self.image_chooser.get_filename() or "Not selected"
        target_index = self.target_combo.get_active()
        target = device_label(self.devices[target_index]) if 0 <= target_index < len(self.devices) else "Not selected"
        started = self.operation_started_at.isoformat() if self.operation_started_at else "Not started"
        inspection = json.dumps(self.inspection or {}, indent=2, sort_keys=True)
        return (
            f"{APP_NAME} {VERSION} diagnostic report\n"
            f"Generated: {datetime.now(timezone.utc).isoformat()}\n"
            f"Platform: {platform.platform()} ({platform.machine()})\n"
            f"Operation started: {started}\n"
            f"Image: {image}\n"
            f"Target: {target}\n\n"
            f"Inspection\n----------\n{inspection}\n\n"
            f"Log\n---\n{self.log_text()}"
        )

    def clear_log(self, *_):
        self.log.get_buffer().set_text("")

    def copy_log(self, *_):
        Gtk.Clipboard.get_default(self.get_display()).set_text(self.diagnostic_report(), -1)
        self.progress_detail.set_text("Diagnostic report copied to the clipboard.")

    def save_log(self, *_):
        dialog = Gtk.FileChooserDialog(title="Save diagnostic report", transient_for=self, action=Gtk.FileChooserAction.SAVE)
        dialog.add_buttons("Cancel", Gtk.ResponseType.CANCEL, "Save", Gtk.ResponseType.OK)
        dialog.set_do_overwrite_confirmation(True)
        dialog.set_current_name(f"rufusubuntuarm64-{datetime.now().strftime('%Y%m%d-%H%M%S')}.log")
        response = dialog.run()
        filename = dialog.get_filename() if response == Gtk.ResponseType.OK else None
        dialog.destroy()
        if not filename:
            return
        try:
            with open(filename, "w", encoding="utf-8") as handle:
                handle.write(self.diagnostic_report())
            os.chmod(filename, 0o600)
            self.progress_detail.set_text(f"Diagnostic report saved to {filename}")
        except OSError as exc:
            self.message(f"Could not save the diagnostic report: {exc}", Gtk.MessageType.ERROR)

    def set_busy(self, busy):
        self.busy = bool(busy)
        usable = not busy and bool(self.devices) and bool(self.inspection.get("recognized"))
        self.start_button.set_sensitive(usable)
        for widget in (self.image_chooser, self.download_button, self.target_combo, self.refresh_button, self.verify):
            widget.set_sensitive(not busy)
        self.persistence_button.set_sensitive(
            not busy
            and bool(self.devices)
            and bool(self.inspection.get("recognized"))
            and self.inspection.get("mode") == "raw"
        )
        windows_controls = not busy and self.inspection.get("mode") == "windows"
        for widget in (self.partition_combo, self.target_system_combo, self.filesystem_combo, self.cluster_combo, self.volume_label, self.driver_chooser, self.dbx_chooser, self.dbx_update_button, self.quick_format, self.bad_block_check):
            widget.set_sensitive(windows_controls)
        if not busy:
            self.bad_block_toggled()
        self.cancel_button.set_sensitive(busy and self.active_job in {"writer", "download", "persistence-plan"})

    def on_delete_event(self, *_):
        if self.busy:
            self.message(
                "An operation is still running. Click Cancel and wait for RufusArm64 to confirm it has stopped before closing the window.",
                Gtk.MessageType.WARNING,
            )
            return True
        self.save_settings()
        return False

    def image_changed(self, *_):
        path = self.image_chooser.get_filename()
        self.inspection = {}
        self.windows_options = {}
        if not path:
            self.update_layout({})
            return
        if not supported_image_name(path):
            self.update_layout({"description": "Unsupported filename", "recognized": False})
            return
        try:
            result = subprocess.run(
                [helper_path(), "inspect", "--image", path, "--json"],
                check=False,
                text=True,
                capture_output=True,
                timeout=20,
            )
            if result.stdout.strip():
                self.inspection = json.loads(result.stdout)
            if result.returncode != 0 and not self.inspection:
                raise RuntimeError(result.stderr.strip() or "Image inspection failed")
        except Exception as exc:
            self.inspection = {"recognized": False, "description": str(exc)}
        self.update_layout(self.inspection)

    def update_layout(self, info):
        description = info.get("description") or "Choose an image"
        self.mode_value.set_text(description)
        windows = info.get("mode") == "windows"
        for widget in (
            self.partition_combo,
            self.target_system_combo,
            self.filesystem_combo,
            self.cluster_combo,
            self.volume_label,
            self.driver_chooser,
            self.dbx_chooser,
            self.dbx_update_button,
            self.quick_format,
            self.bad_block_check,
        ):
            widget.set_sensitive(not self.busy and windows)
        self.bad_block_toggled()
        self.update_verify_warning()
        if windows:
            if self.partition_combo.get_active_id() in {"gpt", "mbr"}:
                self.windows_partition_scheme = self.partition_combo.get_active_id()
            if self.target_system_combo.get_active_id() in {"uefi", "bios"}:
                self.windows_target_system = self.target_system_combo.get_active_id()
            if self.filesystem_combo.get_active_id() in {"auto", "fat32", "ntfs"}:
                self.windows_filesystem = self.filesystem_combo.get_active_id()
            if self.cluster_combo.get_active_id() in {"auto", "4096", "8192", "16384", "32768"}:
                self.windows_cluster_size = self.cluster_combo.get_active_id()
            self.partition_combo.set_active_id(self.windows_partition_scheme)
            self.target_system_combo.set_active_id(self.windows_target_system)
            self.filesystem_combo.set_active_id(self.windows_filesystem)
            self.cluster_combo.set_active_id(self.windows_cluster_size)
            self.filesystem_changed()
        elif info.get("mode") == "raw":
            if self.partition_combo.get_active_id() in {"gpt", "mbr"}:
                self.windows_partition_scheme = self.partition_combo.get_active_id()
            if self.target_system_combo.get_active_id() in {"uefi", "bios"}:
                self.windows_target_system = self.target_system_combo.get_active_id()
            if self.filesystem_combo.get_active_id() in {"auto", "fat32", "ntfs"}:
                self.windows_filesystem = self.filesystem_combo.get_active_id()
            if self.cluster_combo.get_active_id() in {"auto", "4096", "8192", "16384", "32768"}:
                self.windows_cluster_size = self.cluster_combo.get_active_id()
            self.partition_combo.set_active_id("from-image")
            self.target_system_combo.set_active_id("from-image")
            self.filesystem_combo.set_active_id("from-image")
            self.cluster_combo.set_active_id("from-image")
            self.layout_note.set_text(
                "The partition table, boot modes, and file systems are embedded in the image and are preserved byte-for-byte."
            )
        else:
            self.layout_note.set_text(info.get("description") or "Settings will be selected after the image is inspected.")
        self.start_button.set_sensitive(not self.busy and bool(self.devices) and bool(info.get("recognized")))
        self.persistence_button.set_sensitive(not self.busy and bool(self.devices) and bool(info.get("recognized")) and info.get("mode") == "raw")
        if info.get("mode") != "raw":
            self.persistence_summary.set_text("Select a recognized Linux ISOHybrid image and USB drive.")
        self.update_verify_warning()

    def verify_changed(self, *_):
        self.update_verify_warning()

    def update_verify_warning(self):
        if getattr(self, "verify_warning", None) is None:
            return
        if self.inspection.get("mode") == "windows" and not self.verify.get_active():
            self.verify_warning.set_text(
                "Copied-file verification is off. RufusArm64 will still run a filesystem consistency check, "
                "but it will not compare every Windows setup file back from the USB."
            )
        else:
            self.verify_warning.set_text("")

    def bad_block_toggled(self, *_):
        if self.bad_block_check.get_active():
            self.quick_format.set_active(False)
            self.quick_format.set_sensitive(False)
        else:
            self.quick_format.set_sensitive(not self.busy and self.inspection.get("mode") == "windows")

    def filesystem_changed(self, *_):
        if self.inspection.get("mode") != "windows":
            return
        filesystem = self.filesystem_combo.get_active_id() or "auto"
        if filesystem in {"auto", "fat32", "ntfs"}:
            self.windows_filesystem = filesystem
        self.volume_label.set_max_length(32 if filesystem == "ntfs" else 11)
        self.partition_changed()

    def target_system_changed(self, *_):
        if self.inspection.get("mode") != "windows":
            return
        target_system = self.target_system_combo.get_active_id() or "uefi"
        if target_system not in {"uefi", "bios"}:
            return
        self.windows_target_system = target_system
        if target_system == "bios" and self.partition_combo.get_active_id() != "mbr":
            self.partition_combo.set_active_id("mbr")
            return
        self.partition_changed()

    def partition_changed(self, *_):
        if self.inspection.get("mode") != "windows":
            return
        scheme = self.partition_combo.get_active_id() or "gpt"
        target_system = self.target_system_combo.get_active_id() or "uefi"
        filesystem = self.filesystem_combo.get_active_id() or "auto"
        if scheme not in {"gpt", "mbr"} or target_system not in {"uefi", "bios"}:
            return
        if target_system == "bios" and scheme != "mbr":
            self.partition_combo.set_active_id("mbr")
            return
        self.windows_partition_scheme = scheme
        self.windows_target_system = target_system

        if target_system == "bios":
            scheme_note = (
                "BIOS/CSM mode writes an active MBR partition plus Windows BOOTMGR-compatible MBR and partition boot code. "
                "It is available only for x86/x86-64 Windows ISOs; Windows ARM64 and Surface devices are UEFI-only."
            )
            if filesystem == "ntfs":
                fs_note = "NTFS keeps install.wim intact and boots through the legacy Windows NTFS BOOTMGR path."
            elif filesystem == "fat32":
                fs_note = "FAT32 installs the Windows PE BOOTMGR boot record and splits install.wim when needed."
            else:
                fs_note = "Automatic prefers FAT32 and selects NTFS only when FAT32 cannot safely represent the ISO."
        else:
            if scheme == "mbr":
                scheme_note = "UEFI on MBR supports firmware that accepts MBR removable media; it is not legacy BIOS mode."
            else:
                scheme_note = "GPT/UEFI is recommended for modern Windows systems and required for Surface Pro 11 X1E."
            if filesystem == "ntfs":
                fs_note = (
                    "NTFS keeps install.wim intact and adds the pinned Rufus UEFI:NTFS boot partition. "
                    "Firmware compatibility is less universal than native FAT32."
                )
            elif filesystem == "fat32":
                fs_note = "FAT32 uses the firmware-native UEFI path and automatically splits install.wim when needed."
            else:
                fs_note = "Automatic prefers native FAT32 and switches to NTFS only when the ISO is not FAT32-safe."
        self.layout_note.set_text(scheme_note + " " + fs_note)

    def open_acquisition(self, *_):
        if self.busy:
            return
        dialog = AcquisitionDialog(self, self.settings)
        response = dialog.run()
        try:
            values = dialog.values() if response == Gtk.ResponseType.OK else None
        except ValueError as exc:
            values = None
            self.message(str(exc), Gtk.MessageType.ERROR)
        dialog.destroy()
        if not values:
            return
        for key in ("catalog", "signature", "public_key", "output"):
            self.settings[f"acquisition_{key}"] = values[key]
        self.save_settings()
        try:
            command = build_acquisition_download_command(
                helper_path(), values["catalog"], values["signature"], values["public_key"], values["image"]["id"], values["output"]
            )
        except ValueError as exc:
            self.message(str(exc), Gtk.MessageType.ERROR)
            return
        self.log.get_buffer().set_text("")
        self.operation_started_at = datetime.now(timezone.utc)
        self.active_job = "download"
        self.cancel_requested = False
        self.download_result = {}
        self.append_log("Verified catalog image: " + acquisition_image_label(values["image"]))
        self.set_busy(True)
        self.progress.set_fraction(0)
        self.progress.set_text("Starting verified download…")
        self.progress_detail.set_text("The final file will be installed only after its signed size and SHA-256 match.")
        threading.Thread(target=self.run_download, args=(command,), daemon=True).start()

    def run_download(self, command):
        result_payload = {}
        try:
            self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, start_new_session=True)
            assert self.process.stdout is not None
            for raw in self.process.stdout:
                line = raw.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    GLib.idle_add(self.append_log, line)
                    continue
                if isinstance(payload, dict) and payload.get("event"):
                    GLib.idle_add(self.handle_event, payload)
                elif isinstance(payload, dict) and payload.get("path"):
                    result_payload = payload
            return_code = self.process.wait()
            GLib.idle_add(self.finish_download, return_code, result_payload)
        except Exception as exc:
            GLib.idle_add(self.append_log, f"Verified download failed: {exc}")
            GLib.idle_add(self.finish_download, 1, {})
        finally:
            self.process = None

    def finish_download(self, return_code, payload):
        was_cancelled = self.cancel_requested
        self.set_busy(False)
        self.active_job = ""
        self.cancel_requested = False
        path = payload.get("path", "") if isinstance(payload, dict) else ""
        if return_code == 0 and path and os.path.isfile(path):
            self.progress.set_fraction(1.0)
            self.progress.set_text("Image downloaded and verified")
            self.progress_detail.set_text(f"Verified image saved to {path}")
            self.append_log(f"Verified image: {path}")
            if payload.get("sha256"):
                self.append_log(f"SHA-256: {payload['sha256']}")
            self.image_chooser.set_filename(path)
            self.image_changed()
            self.message("The image was downloaded, checksum-verified, and selected as the boot image.", Gtk.MessageType.INFO)
        elif was_cancelled:
            self.progress.set_text("Download cancelled")
            self.progress_detail.set_text("No unverified partial image was installed.")
        else:
            self.progress.set_text("Download failed — see Details")
            self.progress_detail.set_text("No unverified image was installed.")
            self.message("The image could not be downloaded or verified. No unverified file was installed.", Gtk.MessageType.ERROR)
        return False

    def analyze_persistence(self, *_):
        image = self.image_chooser.get_filename()
        index = self.target_combo.get_active()
        if not image or self.inspection.get("mode") != "raw" or not (0 <= index < len(self.devices)):
            self.message("Choose a recognized Linux ISOHybrid image and a USB drive first.", Gtk.MessageType.INFO)
            return
        dialog = PersistencePlanDialog(self, self.settings)
        response = dialog.run()
        try:
            values = dialog.values() if response == Gtk.ResponseType.OK else None
        except ValueError as exc:
            values = None
            self.message(str(exc), Gtk.MessageType.ERROR)
        dialog.destroy()
        if not values:
            return
        media_root, size_gib = values
        self.settings["persistence_media_root"] = media_root
        self.settings["persistence_size_gib"] = size_gib
        self.save_settings()
        try:
            command = build_persistence_plan_command(helper_path(), image, media_root, self.devices[index].get("size"), size_gib)
        except ValueError as exc:
            self.message(str(exc), Gtk.MessageType.ERROR)
            return
        self.active_job = "persistence-plan"
        self.cancel_requested = False
        self.operation_started_at = datetime.now(timezone.utc)
        self.set_busy(True)
        self.progress.set_fraction(0)
        self.progress.pulse()
        self.progress.set_text("Analyzing persistence compatibility…")
        self.progress_detail.set_text("Reading image metadata and approved boot configuration paths. Nothing is being modified.")
        threading.Thread(target=self.run_persistence_plan, args=(command,), daemon=True).start()

    def run_persistence_plan(self, command):
        try:
            self.process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
            stdout, stderr = self.process.communicate(timeout=90)
            return_code = self.process.returncode
            payload = json.loads(stdout) if return_code == 0 else {}
            error = stderr.strip() or stdout.strip() if return_code != 0 else ""
            GLib.idle_add(self.finish_persistence_plan, return_code, payload, error)
        except subprocess.TimeoutExpired:
            if self.process:
                self.process.kill()
            GLib.idle_add(self.finish_persistence_plan, 1, {}, "Persistence analysis timed out.")
        except Exception as exc:
            GLib.idle_add(self.finish_persistence_plan, 1, {}, str(exc))
        finally:
            self.process = None

    def finish_persistence_plan(self, return_code, payload, error):
        was_cancelled = self.cancel_requested
        self.set_busy(False)
        self.active_job = ""
        self.cancel_requested = False
        if return_code == 0:
            try:
                summary = persistence_plan_summary(payload)
            except ValueError as exc:
                error = str(exc)
            else:
                self.persistence_summary.set_text(summary)
                self.progress.set_text("Persistence compatibility confirmed")
                self.progress_detail.set_text("The result is read-only. Creation remains experimental and command-line only.")
                self.append_log(summary)
                return False
        if was_cancelled:
            self.progress.set_text("Persistence analysis cancelled")
            self.progress_detail.set_text("Nothing was modified.")
        else:
            self.persistence_summary.set_text("Not compatible with the current experimental persistence scope.\n" + (error or "Unknown planner error"))
            self.progress.set_text("Persistence analysis unavailable")
            self.progress_detail.set_text("The image and USB were not modified.")
        return False

    def update_dbx(self, *_):
        if self.busy:
            return
        machine = platform.machine().lower()
        architecture = {
            "aarch64": "arm64",
            "arm64": "arm64",
            "x86_64": "amd64",
            "amd64": "amd64",
            "i386": "x86",
            "i686": "x86",
        }.get(machine)
        if not architecture:
            self.message(f"No Microsoft DBX download mapping is available for {machine}.", Gtk.MessageType.ERROR)
            return
        self.dbx_update_button.set_sensitive(False)
        self.progress.set_text("Downloading Microsoft Secure Boot DBX…")

        def worker():
            try:
                result = subprocess.run(
                    [helper_path(), "dbx", "update", "--arch", architecture, "--json"],
                    check=False, text=True, capture_output=True, timeout=90,
                )
                if result.returncode != 0:
                    raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "DBX download failed")
                payload = json.loads(result.stdout)
                path = payload.get("path", "")
                if not path or not os.path.isfile(path):
                    raise RuntimeError("The DBX downloader did not produce a usable file.")
                GLib.idle_add(self.finish_dbx_update, path, payload.get("sha256", ""), None)
            except Exception as exc:
                GLib.idle_add(self.finish_dbx_update, "", "", str(exc))

        threading.Thread(target=worker, daemon=True).start()

    def finish_dbx_update(self, path, digest, error):
        self.dbx_update_button.set_sensitive(not self.busy and self.inspection.get("mode") == "windows")
        if error:
            self.progress.set_text("Secure Boot DBX update failed")
            self.message(f"Could not update the Secure Boot DBX: {error}", Gtk.MessageType.ERROR)
            return False
        self.dbx_chooser.set_filename(path)
        self.settings["dbx_file"] = path
        self.save_settings()
        self.progress.set_text("Secure Boot DBX updated")
        suffix = f"\nSHA-256: {digest}" if digest else ""
        self.message(f"Microsoft Secure Boot DBX saved to:\n{path}{suffix}", Gtk.MessageType.INFO)
        return False

    def refresh_devices(self):
        self.target_combo.remove_all()
        self.devices = []
        try:
            result = subprocess.run([helper_path(), "list", "--json"], check=True, text=True, capture_output=True, timeout=15)
            self.devices = json.loads(result.stdout)
            for device in self.devices:
                self.target_combo.append_text(device_label(device))
            if self.devices:
                self.target_combo.set_active(0)
                self.progress.set_text("Ready")
            else:
                self.progress.set_text("No removable USB drive found")
        except Exception as exc:
            self.append_log(f"Could not list USB drives: {exc}")
            self.progress.set_text("Drive detection failed")
        self.start_button.set_sensitive(not self.busy and bool(self.devices) and bool(self.inspection.get("recognized")))
        self.persistence_button.set_sensitive(not self.busy and bool(self.devices) and self.inspection.get("mode") == "raw" and bool(self.inspection.get("recognized")))

    def choose_windows_options(self):
        dialog = WindowsOptionsDialog(self, self.windows_options)
        while True:
            response = dialog.run()
            if response != Gtk.ResponseType.OK:
                dialog.destroy()
                return None
            try:
                values = dialog.values()
            except ValueError as exc:
                self.message(str(exc), Gtk.MessageType.ERROR)
                continue
            dialog.destroy()
            self.windows_options = values
            return values

    def start(self, *_):
        image = self.image_chooser.get_filename()
        index = self.target_combo.get_active()
        if not image or not supported_image_name(image):
            self.message("Choose a supported ISO, raw, compressed, or virtual-disk image first.", Gtk.MessageType.INFO)
            return
        if not self.inspection.get("recognized"):
            self.message(self.inspection.get("description") or "The selected image is not recognized.", Gtk.MessageType.ERROR)
            return
        if index < 0 or index >= len(self.devices):
            self.message("Connect and select a USB drive first.", Gtk.MessageType.INFO)
            return

        options = {}
        if self.inspection.get("windows_options"):
            options = self.choose_windows_options()
            if options is None:
                return
        if self.inspection.get("mode") == "windows":
            try:
                partition_scheme = normalize_partition_scheme(self.partition_combo.get_active_id() or "gpt")
                target_system = normalize_target_system(self.target_system_combo.get_active_id() or "uefi")
                if target_system == "bios" and partition_scheme != "mbr":
                    raise ValueError("BIOS/CSM requires the MBR partition scheme.")
                filesystem = normalize_filesystem(self.filesystem_combo.get_active_id() or "auto")
                cluster_size = normalize_cluster_size(self.cluster_combo.get_active_id() or "auto")
                label = normalize_volume_label(self.volume_label.get_text(), filesystem)
            except ValueError as exc:
                self.message(str(exc), Gtk.MessageType.ERROR)
                return
            driver_folder = self.driver_chooser.get_filename() or ""
            dbx_file = self.dbx_chooser.get_filename() or ""
            quick_format = self.quick_format.get_active()
            bad_block_check = self.bad_block_check.get_active()
        else:
            partition_scheme = "gpt"
            target_system = "uefi"
            filesystem = "auto"
            cluster_size = "auto"
            driver_folder = ""
            dbx_file = ""
            label = "RUFUSARM64"
            quick_format = True
            bad_block_check = False

        device = self.devices[index]
        path = device.get("path")
        identity = device.get("identity")
        if not identity:
            self.message("The selected drive has no safety identity. Refresh the drive list and try again.", Gtk.MessageType.ERROR)
            return
        model = " ".join(value for value in (device.get("vendor", ""), device.get("model", "")) if value).strip() or "USB drive"
        summary = self.inspection.get("description", "Bootable media")
        selected_options = [
            name
            for enabled, name in (
                (options.get("bypass_hardware"), "hardware-check bypass"),
                (options.get("bypass_online_account"), "offline-account setup"),
                (bool(options.get("local_user")), f"local account {options.get('local_user', '')}"),
                (options.get("reduce_data_collection"), "reduced setup data collection"),
                (options.get("disable_bitlocker"), "automatic encryption disabled"),
                (options.get("use_regional_settings"), "Ubuntu regional settings"),
            )
            if enabled
        ]
        if selected_options:
            summary += "\nWindows options: " + ", ".join(selected_options)
        verify_requested = self.verify.get_active()
        if self.inspection.get("mode") == "windows" and dbx_file:
            summary += "\nSecure Boot: EFI boot files will be checked against " + os.path.basename(dbx_file)
        if self.inspection.get("mode") == "windows" and not verify_requested:
            summary += "\nVerification: copied-file comparison skipped; a filesystem consistency check will still run."

        dialog = Gtk.MessageDialog(
            transient_for=self,
            modal=True,
            message_type=Gtk.MessageType.WARNING,
            buttons=Gtk.ButtonsType.CANCEL,
            text="Erase the selected USB drive?",
        )
        dialog.format_secondary_text(
            f"All data on {path} ({model}, {human_bytes(device.get('size'))}) will be permanently erased.\n\n{summary}\n\nCheck the device carefully before continuing."
        )
        dialog.add_button("Erase and create USB", Gtk.ResponseType.OK)
        # A stray Enter keypress must never confirm a destructive erase.
        dialog.set_default_response(Gtk.ResponseType.CANCEL)
        response = dialog.run()
        dialog.destroy()
        if response != Gtk.ResponseType.OK:
            return

        self.log.get_buffer().set_text("")
        self.operation_started_at = datetime.now(timezone.utc)
        self.active_job = "writer"
        self.cancel_requested = False
        self.last_status_key = None
        self.active_verify_requested = verify_requested
        self.active_mode = self.inspection.get("mode", "")
        self.active_filesystem = filesystem
        self.append_log(f"Image: {image}")
        self.append_log(f"Target: {path} — {model} — {human_bytes(device.get('size'))}")
        if self.inspection.get("mode") == "windows":
            layout_summary = f"{partition_scheme.upper()} / {self.target_system_combo.get_active_text()} / {filesystem.upper()} / {self.cluster_combo.get_active_text()} clusters"
        else:
            layout_summary = "From image / From image / From image"
        self.append_log(f"Layout: {layout_summary}")
        self.set_busy(True)
        self.progress.set_fraction(0)
        self.progress.set_text("Requesting administrator permission…")
        self.progress_detail.set_text("Waiting for Ubuntu administrator authentication.")

        runtime_dir = f"/run/user/{os.getuid()}"
        try:
            fd, self.cancel_path = tempfile.mkstemp(prefix="rufusarm64-", suffix=".cancel", dir=runtime_dir)
            os.close(fd)
            os.unlink(self.cancel_path)
        except OSError as exc:
            self.active_job = ""
            self.set_busy(False)
            self.message(f"Could not create a safe cancellation channel: {exc}", Gtk.MessageType.ERROR)
            return

        if not os.path.isfile(PKEXEC) or not os.access(PKEXEC, os.X_OK):
            self.cancel_path = None
            self.active_job = ""
            self.set_busy(False)
            self.message("Ubuntu administrator authentication (pkexec) is not installed.", Gtk.MessageType.ERROR)
            return
        try:
            command = build_writer_command(
                PKEXEC,
                helper_path(),
                image,
                path,
                identity,
                verify_requested,
                self.cancel_path,
                label,
                options,
                partition_scheme,
                target_system,
                filesystem,
                cluster_size,
                driver_folder,
                dbx_file,
                quick_format,
                bad_block_check,
            )
        except ValueError as exc:
            self.active_job = ""
            self.set_busy(False)
            self.message(str(exc), Gtk.MessageType.ERROR)
            return
        self.save_settings()
        threading.Thread(target=self.run_writer, args=(command,), daemon=True).start()

    def run_writer(self, command):
        try:
            self.process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                start_new_session=True,
            )
            assert self.process.stdout is not None
            if self.cancel_requested and self.process.poll() is None:
                try:
                    os.killpg(self.process.pid, signal.SIGTERM)
                except (ProcessLookupError, PermissionError):
                    pass
            for raw in self.process.stdout:
                line = raw.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    GLib.idle_add(self.append_log, line)
                    continue
                GLib.idle_add(self.handle_event, event)
            return_code = self.process.wait()
            GLib.idle_add(self.finish, return_code)
        except Exception as exc:
            GLib.idle_add(self.append_log, f"Failed to start the writer: {exc}")
            GLib.idle_add(self.finish, 1)
        finally:
            self.process = None

    def handle_event(self, event):
        message = event.get("message", "")
        event_type = event.get("event")
        total = int(event.get("total") or 0)
        done = int(event.get("done") or 0)
        rate = float(event.get("rate") or 0)
        stage_key = event.get("stage") or "working"
        stage = stage_key.replace("_", " ").title()

        # Status/progress updates are not appended repeatedly. Technical log
        # messages and a change of stage remain visible in Details.
        status_key = (stage_key, message)
        if event_type == "log":
            if message:
                self.append_log(message)
        elif message and status_key != self.last_status_key:
            self.append_log(message)
            self.last_status_key = status_key

        if total > 0:
            fraction = min(1.0, done / total)
            self.progress.set_fraction(fraction)
            self.progress.set_text(f"{stage}: {fraction * 100:.1f}%")
            self.progress_detail.set_text(progress_status(stage_key, done, total, rate))
        elif event_type in ("stage", "preflight"):
            self.progress.pulse()
            if message:
                self.progress.set_text(message)
                self.progress_detail.set_text(message)
        elif event_type == "complete":
            self.progress.set_fraction(1.0)
            self.progress.set_text(message or "Complete")
            self.progress_detail.set_text(message or "Complete")
        return False

    def finish(self, return_code):
        was_cancelled = self.cancel_requested
        self.set_busy(False)
        self.active_job = ""
        self.cancel_requested = False
        if self.cancel_path:
            try:
                os.unlink(self.cancel_path)
            except FileNotFoundError:
                pass
            self.cancel_path = None
        if return_code == 0:
            self.progress.set_fraction(1.0)
            self.progress.set_text("USB created successfully")
            self.progress_detail.set_text("The operation completed successfully. A diagnostic report can be saved from Details.")
            self.message(success_message(self.active_mode, self.active_verify_requested, self.active_filesystem), Gtk.MessageType.INFO)
        elif was_cancelled:
            self.progress.set_text("Cancelled safely")
            self.progress_detail.set_text("Writing has stopped. The incomplete USB should be recreated before use.")
            self.message("The operation stopped. The USB is incomplete and should be recreated before use.", Gtk.MessageType.WARNING)
        else:
            self.progress.set_text("Failed — see Details")
            self.progress_detail.set_text("Nothing is being written now. Save the diagnostic report from Details when requesting help.")
            self.message("The USB could not be created. Nothing is being written now. Open Details for the exact error.", Gtk.MessageType.ERROR)
        self.refresh_devices()
        return False

    def cancel(self, *_):
        if not self.busy:
            return
        self.cancel_requested = True
        self.cancel_button.set_sensitive(False)
        if self.active_job == "writer":
            self.append_log("Cancellation requested. Do not remove the USB until RufusArm64 confirms that writing has stopped.")
            self.progress.set_text("Cancelling safely…")
            self.progress_detail.set_text("Waiting for the privileged writer to reach a safe cancellation point. Do not unplug the USB.")
        else:
            self.append_log("Cancellation requested.")
            self.progress.set_text("Cancelling…")
            self.progress_detail.set_text("Stopping the read-only operation. No unverified download will be installed.")
        if self.cancel_path:
            try:
                fd = os.open(self.cancel_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                os.close(fd)
            except FileExistsError:
                pass
            except OSError as exc:
                self.append_log(f"Could not create cancellation marker: {exc}")
        process = self.process
        if process and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass

    def message(self, text, kind):
        dialog = Gtk.MessageDialog(transient_for=self, modal=True, message_type=kind, buttons=Gtk.ButtonsType.OK, text=text)
        dialog.run()
        dialog.destroy()

    def show_about(self, *_):
        dialog = Gtk.AboutDialog(transient_for=self, modal=True)
        dialog.set_program_name(APP_NAME)
        dialog.set_version(VERSION)
        dialog.set_comments("An unofficial Ubuntu ARM64 bootable-USB creator for Linux images and modern Windows UEFI installation media.")
        dialog.set_website("https://github.com/geocausa/RufusUbuntuArm64")
        dialog.set_license_type(Gtk.License.GPL_3_0)
        dialog.run()
        dialog.destroy()


class RufusApp(Gtk.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID)

    def do_activate(self):
        window = self.props.active_window or RufusWindow(self)
        window.show_all()
        window.present()


if __name__ == "__main__":
    raise SystemExit(RufusApp().run(None))
