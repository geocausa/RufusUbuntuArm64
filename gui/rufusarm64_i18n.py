"""Bounded GNU gettext integration for the RufusArm64 GTK interface."""

import gettext as _gettext
import sys

from gi.repository import GLib, Gtk


DOMAIN = "rufusarm64"
DEFAULT_LOCALE_DIR = "/usr/share/locale"
SECONDARY_DIALOG_CLASSES = (
    ("rufusarm64_checksums", "ChecksumDialog"),
    ("rufusarm64_device_qualify_dialog", "DeviceQualificationDialog"),
    ("rufusarm64_device_qualify_dialog", "DriveImageBackupDialog"),
    ("rufusarm64_ffu_dialog", "FFUReviewDialog"),
    ("rufusarm64_nonbootable_dialog", "NonBootableFormatDialog"),
    ("rufusarm64_freedos_dialog", "FreeDOSFormatDialog"),
    ("rufusarm64", "WindowsOptionsDialog"),
    ("rufusarm64", "AcquisitionDialog"),
    ("rufusarm64_persistence", "Window"),
)


def N_(message):
    """Mark one source string for deterministic catalog extraction."""
    return message


CATALOG_MESSAGES = (
    N_("About RufusArm64"),
    N_("Advanced drive properties"),
    N_("Advanced options"),
    N_("Advanced recovery: local signed catalog"),
    N_("After a successful unmounted-target review, type the displayed phrase exactly. Administrator authentication then reruns every source, policy, trust-generation, target and geometry check before any write."),
    N_("After writing, read copied data back from the USB and compare it with authenticated source content."),
    N_("Appearance"),
    N_("Apply"),
    N_("Apply Rufus Quality of Life changes"),
    N_("Authenticated trust store"),
    N_("Built-in verified catalog"),
    N_("Authenticate a supported FFU and review the exact removable target before experimental restoration."),
    N_("Authenticate and review"),
    N_("Automatic"),
    N_("Automatic (image-derived)"),
    N_("BIOS or UEFI-CSM"),
    N_("Boot image"),
    N_("Bootable USB creator for Linux ARM64"),
    N_("C_ancel"),
    N_("C_hecksums…"),
    N_("Calculate"),
    N_("Catalog"),
    N_("Calculate MD5, SHA-1, SHA-256, and SHA-512 for the selected image in one read-only pass. The image is not mounted or modified, no USB device is opened, and administrator authentication is not used."),
    N_("Calculate image checksums"),
    N_("Calculate comparison hashes. Shortcut Ctrl+K."),
    N_("Calculate MD5, SHA-1, SHA-256, and SHA-512 for the selected image without modifying it."),
    N_("Calculating a read-only plan…"),
    N_("Cancel"),
    N_("Cancel active operation"),
    N_("Continue"),
    N_("Cancel backup"),
    N_("Cancel creation"),
    N_("Cancel formatting"),
    N_("Cancel restore"),
    N_("Cancel test"),
    N_("Calculating the exact data-only plan without administrator access…"),
    N_("Calculating the exact FreeDOS plan without administrator access…"),
    N_("Calculating the unprivileged formatting plan…"),
    N_("Calculating the unprivileged FreeDOS plan…"),
    N_("Change appearance"),
    N_("Check USB capacity and blocks"),
    N_("Check USB drive"),
    N_("Check USB…"),
    N_("Check compatibility"),
    N_("Check ISO and USB"),
    N_("Check device for bad blocks (1 pass)"),
    N_("Checking identity, capacity, sector size, layout, filesystem tools, and safety warnings…"),
    N_("Checking target identity, capacity, 512-byte sectors, FAT32 geometry, pinned payload, and platform warnings…"),
    N_("Choose System, Light, or Dark appearance for RufusArm64 and its dialogs."),
    N_("Choose a destination file."),
    N_("Choose all three explicit trust inputs."),
    N_("Choose all three local trust files, then verify."),
    N_("Choose catalog"),
    N_("Choose download folder"),
    N_("Choose public key"),
    N_("Choose signature"),
    N_("Choose a new .img path"),
    N_("Choose a new Dynamic VHD (.vhd) file"),
    N_("Choose a new Dynamic VHDX (.vhdx) file"),
    N_("Choose a new Filesystem ISO/UDF (.iso) file"),
    N_("Choose a new Raw image (.img) file"),
    N_("Choose a new destination path to calculate the read-only plan."),
    N_("Choose a plain Linux ISOHybrid image"),
    N_("Choose an ISO and USB drive, then check compatibility."),
    N_("Choose an image and a removable USB drive. Raw, ISOHybrid, compressed, and common virtual-disk images are supported. Windows installation ISOs can use GPT or MBR layouts, FAT32/NTFS selection, WIM splitting, and UEFI:NTFS."),
    N_("Choose persistence capacity in GiB; zero requests the recommended available capacity."),
    N_("Choose the allocation-unit size for a newly created Windows FAT32 or NTFS filesystem."),
    N_("Choose the exact removable whole drive that will be erased only after review and confirmation."),
    N_("Choose an ISO or disk image that RufusArm64 will inspect before writing."),
    N_("Choose the ISO or disk image that RufusArm64 will inspect before writing."),
    N_("Choose the ISO, disk image, compressed image, virtual disk, or FFU source to inspect before any write."),
    N_("Choose the removable whole drive that will be erased only after confirmation."),
    N_("Choose…"),
    N_("Choose Automatic, FAT32, or NTFS for supported Windows installation media."),
    N_("Choose Automatic, GPT, or MBR for supported Windows media; incompatible combinations are refused."),
    N_("Choose Automatic, UEFI, or x86-family BIOS/CSM for supported Windows installation media."),
    N_("Clear"),
    N_("Clear only the visible diagnostic log."),
    N_("Close"),
    N_("Cluster size"),
    N_("Copy"),
    N_("Copy report"),
    N_("Copy the complete diagnostic report to the clipboard."),
    N_("Create a bootable USB drive"),
    N_("Create deterministic FreeDOS 1.4 media for x86 BIOS or Legacy/CSM systems."),
    N_("Create FreeDOS media"),
    N_("Create non-bootable media"),
    N_("Create USB"),
    N_("Create a local administrator account"),
    N_("Create a persistent live Linux USB"),
    N_("Create persistent USB"),
    N_("Customize Windows Setup"),
    N_("Dark"),
    N_("Details and diagnostics"),
    N_("Development validation"),
    N_("Disable automatic BitLocker device-encryption provisioning"),
    N_("Does not decrypt an existing installation. It prevents automatic encryption during this new setup where supported."),
    N_("Download"),
    N_("Download a verified image"),
    N_("Download folder"),
    N_("Download the current architecture-specific Microsoft DBX update for local inspection."),
    N_("Download unavailable"),
    N_("Download verified image"),
    N_("Dynamic VHD (.vhd)"),
    N_("Dynamic VHDX (.vhdx)"),
    N_("Erase the selected drive and create one verified data-only filesystem without claiming bootability."),
    N_("Every option below is optional. RufusArm64 creates an autounattend.xml file on the USB; the Windows ISO itself is not changed. Leave everything unchecked for standard Microsoft setup."),
    N_("Everything on the selected drive will be permanently erased. Cancelling after erasure may leave intentionally incomplete media that must be formatted again before use."),
    N_("Everything on the selected drive will be permanently erased. The resulting media runs only on x86-compatible computers using BIOS or UEFI Legacy/CSM. It will not boot ARM64 or UEFI-only systems. Software verification cannot prove that a physical PC will boot it."),
    N_("FAT32"),
    N_("Filesystem ISO/UDF (.iso)"),
    N_("File system"),
    N_("Follow the desktop appearance observed when RufusArm64 started."),
    N_("For supported Ubuntu or Debian live media, create separate saved-change storage that can survive reboot."),
    N_("Format data-only media"),
    N_("FreeDOS 1.4 — x86 BIOS/Legacy media"),
    N_("FreeDOS…"),
    N_("_FreeDOS…"),
    N_("_Boot image"),
    N_("_Create USB"),
    N_("_Download…"),
    N_("_USB drive"),
    N_("_Validate UEFI Media…"),
    N_("GiB (0 = recommended available space)"),
    N_("GiB — leave at 0 to use the recommended available space"),
    N_("Image checksums"),
    N_("Linux ISO"),
    N_("Linux ISO images"),
    N_("Account name"),
    N_("Image format"),
    N_("Image compatibility and write path"),
    N_("Image option"),
    N_("Keep files and settings across reboots"),
    N_("Keep quick formatting enabled, or disable it to zero-write the complete new data partition first."),
    N_("Keyboard: {shortcut}"),
    N_("Light"),
    N_("MD5 and SHA-1 are included only for comparison with legacy published values. They are not used by RufusArm64 for trust, signatures, downloads, or write assurance."),
    N_("Microsoft can change unattended-setup behavior between Windows releases. RufusArm64 validates the answer file, but Windows may ignore an option that a future build no longer supports."),
    N_("No backup report is available yet."),
    N_("No checksums have been calculated."),
    N_("No formatting report is available yet."),
    N_("No qualification report is available yet."),
    N_("No review has been performed. The ordinary Create USB action remains disabled for FFU images."),
    N_("No verified image selected."),
    N_("No FreeDOS report is available yet."),
    N_("Non bootable — data-only media"),
    N_("Not started"),
    N_("New image file"),
    N_("NTFS"),
    N_("Open read-only UEFI media validation. Shortcut Ctrl+U."),
    N_("Remove TPM 2.0, Secure Boot and minimum-RAM checks"),
    N_("Remove the Microsoft online-account requirement"),
    N_("Removes bundled OneDrive setup, Outlook and Teams, and disables Copilot, web search, consumer-content suggestions and related Microsoft promotions."),
    N_("Open read-only validation of a mounted or extracted UEFI media directory."),
    N_("Open signed image acquisition. Shortcut Ctrl+D."),
    N_("Open the final erase confirmation for the selected image and drive."),
    N_("Open the separate destructive USB capacity, bad-block, and fake-capacity qualification workflow."),
    N_("Open verified signed-catalog image acquisition when the installed channel is available."),
    N_("Operation progress"),
    N_("Operation status details"),
    N_("Post-operation actions"),
    N_("Optional"),
    N_("Optionally select a Microsoft DBX update used to reject revoked Windows EFI boot files."),
    N_("Optionally stage validated Windows PE driver packages from this folder onto the USB."),
    N_("Partition scheme"),
    N_("Persistent storage"),
    N_("Prefer the dark variant of the active GTK theme for RufusArm64."),
    N_("Prefer the light variant of the active GTK theme for RufusArm64."),
    N_("Preparing a read-only plan…"),
    N_("Preparing…"),
    N_("Public key"),
    N_("Publisher policy"),
    N_("Quick format"),
    N_("Raw image (.img)"),
    N_("Ready"),
    N_("RufusArm64 Persistent Live USB"),
    N_("Raw is byte-for-byte. VHD and VHDX are dynamic sparse containers verified against the held source."),
    N_("Refresh catalog"),
    N_("Refresh USB drives"),
    N_("Request safe cancellation and wait for cleanup to finish."),
    N_("Request safe cancellation of the active operation and wait for its final state and cleanup."),
    N_("Rescan connected removable whole drives without changing any device."),
    N_("Rescan removable whole drives. Shortcut Ctrl+R."),
    N_("Restore / format…"),
    N_("Restore / for_mat…"),
    N_("Restore authenticated FFU"),
    N_("Restore or format drive for storage"),
    N_("Review FFU…"),
    N_("Review Full Flash Update"),
    N_("Review the final destructive warning for the selected image and exact USB drive."),
    N_("Running the test will erase data in every selected test region. A full test is intended for an empty USB drive."),
    N_("RufusArm64 appearance"),
    N_("Run a read-only validation of a mounted or extracted UEFI media folder"),
    N_("Run USB check"),
    N_("Run read-only validation of a mounted or extracted UEFI media directory."),
    N_("Run the mandatory read-only persistence compatibility and capacity analysis."),
    N_("Save a byte-for-byte image of the selected removable drive. The source is opened read-only, but its mounted filesystems may be unmounted briefly to obtain a coherent image. Create USB and Check USB are separate workflows."),
    N_("Sets Windows Setup privacy choices and disables advertising/consumer-content policies where supported."),
    N_("Skip privacy prompts and reduce initial data collection/recommendations"),
    N_("Save a verified raw, dynamic VHD/VHDX, or one-filesystem ISO/UDF image of the selected drive."),
    N_("Save drive image"),
    N_("Save drive image…"),
    N_("Save report…"),
    N_("Save the complete diagnostic report to an owner-private file."),
    N_("Save…"),
    N_("Saved-change space"),
    N_("Space for saved changes"),
    N_("Secure Boot DBX"),
    N_("Select Calculate to hash the exact image file."),
    N_("Signature"),
    N_("Set the validated volume label used for the newly created Windows installation filesystem."),
    N_("Set Windows installation filesystem options without changing the source image."),
    N_("Show application and licence information. Shortcut F1."),
    N_("Shows the detected image type, selected write path, and bounded compatibility or boot limitations."),
    N_("System"),
    N_("The short name shown for the writable boot partition."),
    N_("The USB cannot be erased until the compatibility check succeeds."),
    N_("Use this Ubuntu user's regional settings"),
    N_("System keeps the desktop preference observed when this application started. Light and Dark affect only RufusArm64 and its dialogs."),
    N_("The built-in channel verifies threshold-signed root and catalog metadata, rejects version rollback, and checksum-verifies every image. No unsigned bypass is offered."),
    N_("Target system"),
    N_("Test profile"),
    N_("Technical diagnostic log"),
    N_("USB target drive"),
    N_("The exact confirmation phrase appears after planning."),
    N_("The exact FORMAT phrase appears after the read-only plan is validated."),
    N_("The exact WRITE FREEDOS phrase appears after the read-only plan is validated."),
    N_("The final image path is created only after every planned byte has been copied, synchronized, SHA-256 hashed, and revalidated. Existing files and symbolic links are never replaced."),
    N_("This is a separate destructive USB qualification test. It overwrites every tested region and does not preserve files or partitions. The normal Create USB workflow is not changed."),
    N_("This separate workflow erases the complete selected removable drive and constructs one deterministic FAT32 FreeDOS volume from checksum-pinned package payloads."),
    N_("This check reads the ISO without changing the USB. It confirms that the selected image supports persistence and that the USB has enough space."),
    N_("This feature supports recognized Ubuntu 20.04 or newer and Debian live images. Some images or computers may not be compatible; RufusArm64 checks the ISO before writing anything to the USB."),
    N_("This separate workflow erases the complete selected removable drive, creates one data partition, checks the new filesystem, and explicitly does not claim the result is bootable."),
    N_("Trust-metadata policy"),
    N_("Type the exact SAVE phrase"),
    N_("Type the exact FORMAT phrase"),
    N_("Type the exact WRITE FREEDOS phrase"),
    N_("UEFI (non-CSM)"),
    N_("Ubuntu casper and Debian live-boot"),
    N_("Unsigned development loader — Secure Boot compatibility is not established. Development testing only."),
    N_("USB name"),
    N_("USB drive"),
    N_("USB target drive"),
    N_("Validate UEFI Media…"),
    N_("Validate UEFI media"),
    N_("Verify copied data after writing"),
    N_("Validate media at UEFI boot (development only)"),
    N_("Validate UEFI media"),
    N_("Verify copied data after writing"),
    N_("Verify local catalog"),
    N_("Volume label"),
    N_("Windows drivers"),
    N_("Choose a supported Ubuntu or Debian ISO, select a removable USB drive, and choose how much space to keep for files and settings. RufusArm64 checks compatibility before it allows the USB to be erased."),
    N_("Windows installation options"),
    N_("Checking the package-owned trust channel…"),
    N_("Use this only with catalog, detached-signature, and public-key files obtained through a separately trusted path."),
    N_("Allows Windows setup to continue with a local account when supported by that Windows build."),
    N_("Useful for unsupported PCs. This normally is not needed on a Surface Pro 11 X1E."),
    N_("Zero-write and read back the complete new data partition before formatting; this is slow and destructive."),
    N_("_Boot image"),
    N_("_Create USB"),
    N_("_Download…"),
    N_("_FreeDOS…"),
    N_("_USB drive"),
    N_("_Validate UEFI Media…"),
)
CATALOG_MESSAGE_SET = frozenset(CATALOG_MESSAGES)
MARKUP_TEMPLATES = {
    "Create a bootable USB drive": "<span size='large' weight='bold'>{}</span>",
    "FreeDOS 1.4 — x86 BIOS/Legacy media": "<span size='large' weight='bold'>{}</span>",
    "Non bootable — data-only media": "<span size='large' weight='bold'>{}</span>",
    "Customize Windows Setup": "<span size='large' weight='bold'>{}</span>",
    "Create a persistent live Linux USB": "<span size='large' weight='bold'>{}</span>",
}


def load_translation(localedir=DEFAULT_LOCALE_DIR, languages=None):
    """Load standard GNU catalogs without reusing gettext's process cache."""
    try:
        filenames = _gettext.find(
            DOMAIN,
            localedir=localedir,
            languages=languages,
            all=True,
        )
        translation = None
        for filename in filenames:
            with open(filename, "rb") as handle:
                catalog = _gettext.GNUTranslations(handle)
            if translation is None:
                translation = catalog
            else:
                translation.add_fallback(catalog)
        return translation or _gettext.NullTranslations()
    except (EOFError, OSError, TypeError, UnicodeError, ValueError):
        return _gettext.NullTranslations()


_translation = load_translation()


def configure_translation(localedir=DEFAULT_LOCALE_DIR, languages=None):
    """Replace the process translation object; primarily useful for deterministic tests."""
    global _translation
    _translation = load_translation(localedir=localedir, languages=languages)
    return _translation


def gettext(message):
    """Translate one reviewed source message with non-empty source fallback."""
    return _translated(str(message), _translation)


def _translated(message, translation):
    if message not in CATALOG_MESSAGE_SET:
        return message
    value = translation.gettext(message)
    if not isinstance(value, str) or not value:
        return message
    return value


def _translated_tooltip(message, translation):
    if message is None or message == "":
        return message
    translated = []
    for line in str(message).split("\n"):
        if line.startswith("Keyboard: "):
            shortcut = line.removeprefix("Keyboard: ")
            template = _translated("Keyboard: {shortcut}", translation)
            try:
                translated.append(template.format(shortcut=shortcut))
            except (IndexError, KeyError, ValueError):
                translated.append(line)
        else:
            translated.append(_translated(line, translation))
    return "\n".join(translated)


def _walk_widgets(widget):
    yield widget
    if isinstance(widget, Gtk.Container):
        for child in widget.get_children():
            yield from _walk_widgets(child)


def _translate_accessible(widget, translation):
    accessible = widget.get_accessible() if hasattr(widget, "get_accessible") else None
    if accessible is None:
        return 0
    changed = 0
    for getter_name, setter_name in (("get_name", "set_name"), ("get_description", "set_description")):
        getter = getattr(accessible, getter_name, None)
        setter = getattr(accessible, setter_name, None)
        if not callable(getter) or not callable(setter):
            continue
        source = getter()
        if not source:
            continue
        translated = _translated(str(source), translation)
        if translated != source:
            setter(translated)
            changed += 1
    return changed


def _translate_widget(widget, translation):
    changed = 0
    if isinstance(widget, Gtk.Window):
        source = widget.get_title()
        if source:
            translated = _translated(str(source), translation)
            if translated != source:
                widget.set_title(translated)
                changed += 1
    elif isinstance(widget, Gtk.HeaderBar):
        for getter_name, setter_name in (("get_title", "set_title"), ("get_subtitle", "set_subtitle")):
            source = getattr(widget, getter_name)()
            if not source:
                continue
            translated = _translated(str(source), translation)
            if translated != source:
                getattr(widget, setter_name)(translated)
                changed += 1
    elif isinstance(widget, Gtk.Frame):
        source = widget.get_label()
        if source:
            translated = _translated(str(source), translation)
            if translated != source:
                widget.set_label(translated)
                changed += 1
    elif isinstance(widget, Gtk.FileChooserButton):
        source = widget.get_title()
        if source:
            translated = _translated(str(source), translation)
            if translated != source:
                widget.set_title(translated)
                changed += 1
        list_filters = getattr(widget, "list_filters", None)
        if callable(list_filters):
            for file_filter in list_filters():
                source = file_filter.get_name() if hasattr(file_filter, "get_name") else None
                if not source or not hasattr(file_filter, "set_name"):
                    continue
                translated = _translated(str(source), translation)
                if translated != source:
                    file_filter.set_name(translated)
                    changed += 1
    elif isinstance(widget, Gtk.Label):
        source = widget.get_text()
        translated = _translated(str(source or ""), translation)
        if translated != source:
            template = MARKUP_TEMPLATES.get(source) if widget.get_use_markup() else None
            if template:
                widget.set_markup(template.format(GLib.markup_escape_text(translated)))
            else:
                widget.set_text(translated)
            changed += 1
    elif isinstance(widget, (Gtk.Button, Gtk.CheckButton, Gtk.Expander)):
        source = widget.get_label()
        if source:
            translated = _translated(str(source), translation)
            if translated != source:
                widget.set_label(translated)
                changed += 1
    elif isinstance(widget, Gtk.Entry):
        source = widget.get_placeholder_text()
        if source:
            translated = _translated(str(source), translation)
            if translated != source:
                widget.set_placeholder_text(translated)
                changed += 1
    elif isinstance(widget, Gtk.ProgressBar):
        source = widget.get_text()
        if source:
            translated = _translated(str(source), translation)
            if translated != source:
                widget.set_text(translated)
                changed += 1
    elif isinstance(widget, Gtk.TextView):
        buffer = widget.get_buffer()
        start, end = buffer.get_bounds()
        source = buffer.get_text(start, end, True)
        if source:
            translated = _translated(str(source), translation)
            if translated != source:
                buffer.set_text(translated)
                changed += 1

    if hasattr(widget, "get_tooltip_text") and hasattr(widget, "set_tooltip_text"):
        source = widget.get_tooltip_text()
        translated = _translated_tooltip(source, translation)
        if translated != source:
            widget.set_tooltip_text(translated)
            changed += 1
    return changed + _translate_accessible(widget, translation)


def translate_widget_tree(widget, translation=None):
    """Translate one exact reviewed GTK widget tree and return from an idle callback."""
    selected = translation or _translation
    changed = 0
    for child in _walk_widgets(widget):
        changed += _translate_widget(child, selected)
    widget._rufusarm64_translation = selected
    widget._rufusarm64_translated_fields = changed
    return False


def apply_primary_ui_translation(window, translation=None):
    """Translate exact reviewed static strings after the composed window exists."""
    return translate_widget_tree(window, translation)


def install_secondary_dialog_localization():
    """Wrap already-imported guarded dialogs without changing their operation paths."""
    for module_name, class_name in SECONDARY_DIALOG_CLASSES:
        module = sys.modules.get(module_name)
        dialog_class = getattr(module, class_name, None) if module is not None else None
        if dialog_class is None or getattr(dialog_class, "_localization_installed", False):
            continue
        original_init = dialog_class.__init__

        def localized_init(dialog, *args, _original_init=original_init, **kwargs):
            _original_init(dialog, *args, **kwargs)
            GLib.idle_add(translate_widget_tree, dialog)

        dialog_class.__init__ = localized_init
        dialog_class._localization_installed = True


def install_localization(window_class):
    """Defer translation until appearance, tooltips, and composed controls exist."""
    install_secondary_dialog_localization()
    if getattr(window_class, "_localization_installed", False):
        return
    original_init = window_class.__init__

    def integrated_init(window, app):
        original_init(window, app)
        GLib.idle_add(apply_primary_ui_translation, window)

    window_class.__init__ = integrated_init
    window_class._localization_installed = True
