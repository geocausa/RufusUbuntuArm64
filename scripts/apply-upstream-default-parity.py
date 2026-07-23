#!/usr/bin/env python3
from pathlib import Path


def replace_once(path, old, new):
    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one replacement, found {count}")
    file_path.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_once(
    "cmd/rufus-linux/main.go",
    'const defaultAcquisitionChannelConfig = "/usr/share/rufusarm64/acquisition/channel.json"\n',
    '''const defaultAcquisitionChannelConfig = "/usr/share/rufusarm64/acquisition/channel.json"

const (
\tdefaultWriteVerify            = false
\tdefaultWindowsPartitionScheme = "auto"
\tdefaultWindowsTargetSystem    = "auto"
\tdefaultWindowsFilesystem      = "auto"
\tdefaultWindowsClusterSize     = "auto"
\tdefaultWindowsFullFormat      = false
\tdefaultWindowsBadBlockCheck   = false
)
''',
)
replace_once(
    "cmd/rufus-linux/main.go",
    'result.PartitionScheme = "GPT"\n\t\t\t\tresult.TargetSystem = "UEFI"',
    'result.PartitionScheme = "Automatic (image-derived)"\n\t\t\t\tresult.TargetSystem = "Automatic (image-derived)"',
)
replace_once(
    "cmd/rufus-linux/main.go",
    'result.PartitionScheme = "GPT"\n\t\t\tresult.TargetSystem = "UEFI"',
    'result.PartitionScheme = "Automatic (image-derived)"\n\t\t\tresult.TargetSystem = "Automatic (image-derived)"',
)
replace_once(
    "cmd/rufus-linux/main.go",
    '\tverify := fs.Bool("verify", false, "verify data after writing")\n',
    '\tverify := fs.Bool("verify", defaultWriteVerify, "verify data after writing")\n',
)
replace_once(
    "cmd/rufus-linux/main.go",
    '''\tpartitionScheme := fs.String("partition-scheme", "gpt", "Windows media partition scheme: gpt or mbr")
\ttargetSystem := fs.String("target-system", "uefi", "Windows target system: uefi or bios")
\tfilesystem := fs.String("filesystem", "auto", "Windows media filesystem: auto, fat32, or ntfs")
\tclusterSizeText := fs.String("cluster-size", "auto", "cluster size: auto, 4096, 8192, 16384, or 32768")
''',
    '''\tpartitionScheme := fs.String("partition-scheme", defaultWindowsPartitionScheme, "Windows media partition scheme: auto, gpt, or mbr")
\ttargetSystem := fs.String("target-system", defaultWindowsTargetSystem, "Windows target system: auto, uefi, or bios")
\tfilesystem := fs.String("filesystem", defaultWindowsFilesystem, "Windows media filesystem: auto, fat32, or ntfs")
\tclusterSizeText := fs.String("cluster-size", defaultWindowsClusterSize, "cluster size: auto, 4096, 8192, 16384, or 32768")
''',
)
replace_once(
    "cmd/rufus-linux/main.go",
    '''\tfullFormat := fs.Bool("full-format", false, "zero the Windows partition before formatting")
\tbadBlockCheck := fs.Bool("bad-block-check", false, "zero and read back the Windows partition before formatting")
''',
    '''\tfullFormat := fs.Bool("full-format", defaultWindowsFullFormat, "zero the Windows partition before formatting")
\tbadBlockCheck := fs.Bool("bad-block-check", defaultWindowsBadBlockCheck, "zero and read back the Windows partition before formatting")
''',
)
replace_once(
    "cmd/rufus-linux/main.go",
    '''\tscheme := strings.ToLower(strings.TrimSpace(*partitionScheme))
\tif scheme != "gpt" && scheme != "mbr" {
\t\treturn errors.New("--partition-scheme must be gpt or mbr")
\t}
\ttargetSystemChoice := strings.ToLower(strings.TrimSpace(*targetSystem))
\tswitch targetSystemChoice {
\tcase "", "auto", "uefi":
\t\ttargetSystemChoice = "uefi"
\tcase "bios", "legacy", "legacy-bios", "bios-csm":
\t\ttargetSystemChoice = "bios"
\tdefault:
\t\treturn errors.New("--target-system must be uefi or bios")
\t}
\tif targetSystemChoice == "bios" && scheme != "mbr" {
\t\treturn errors.New("--target-system bios requires --partition-scheme mbr")
\t}
''',
    '''\tscheme := strings.ToLower(strings.TrimSpace(*partitionScheme))
\tswitch scheme {
\tcase "", "auto":
\t\tscheme = "auto"
\tcase "gpt", "mbr":
\tdefault:
\t\treturn errors.New("--partition-scheme must be auto, gpt, or mbr")
\t}
\ttargetSystemChoice := strings.ToLower(strings.TrimSpace(*targetSystem))
\tswitch targetSystemChoice {
\tcase "", "auto":
\t\ttargetSystemChoice = "auto"
\tcase "uefi":
\t\ttargetSystemChoice = "uefi"
\tcase "bios", "legacy", "legacy-bios", "bios-csm":
\t\ttargetSystemChoice = "bios"
\tdefault:
\t\treturn errors.New("--target-system must be auto, uefi, or bios")
\t}
\tif targetSystemChoice == "bios" && scheme == "gpt" {
\t\treturn errors.New("--target-system bios cannot be combined with --partition-scheme gpt")
\t}
''',
)
replace_once(
    "cmd/rufus-linux/main.go",
    '\tif selectedMode != "windows" && (winOptions.Enabled() || scheme != "gpt" || targetSystemChoice != "uefi" || filesystemChoice != "auto" || clusterSize != 0 || *driverFolder != "" || *dbxFile != "" || *fullFormat || *badBlockCheck) {\n',
    '\tif selectedMode != "windows" && (winOptions.Enabled() || scheme != "auto" || targetSystemChoice != "auto" || filesystemChoice != "auto" || clusterSize != 0 || *driverFolder != "" || *dbxFile != "" || *fullFormat || *badBlockCheck) {\n',
)
replace_once(
    "cmd/rufus-linux/main.go",
    '''\t\tif scheme != "gpt" || targetSystemChoice != "uefi" || filesystemChoice != "auto" || clusterSize != 0 {
\t\t\treturn errors.New("experimental Linux persistence currently requires GPT, UEFI, and automatic filesystem settings")
\t\t}
''',
    '''\t\tif (scheme != "auto" && scheme != "gpt") || (targetSystemChoice != "auto" && targetSystemChoice != "uefi") || filesystemChoice != "auto" || clusterSize != 0 {
\t\t\treturn errors.New("experimental Linux persistence currently requires automatic/GPT, automatic/UEFI, and automatic filesystem settings")
\t\t}
''',
)

replace_once(
    "internal/windowsmedia/windowsmedia.go",
    '''\ttargetSystem, err := normalizeTargetSystem(opts.TargetSystem)
\tif err != nil {
\t\treturn err
\t}
\tif targetSystem == "bios" {
''',
    '''\tscheme, targetSystem, err := resolveWindowsLayout(plan, opts.PartitionScheme, opts.TargetSystem)
\tif err != nil {
\t\treturn err
\t}
\tif strings.EqualFold(strings.TrimSpace(opts.PartitionScheme), "auto") || strings.TrimSpace(opts.PartitionScheme) == "" ||
\t\tstrings.EqualFold(strings.TrimSpace(opts.TargetSystem), "auto") || strings.TrimSpace(opts.TargetSystem) == "" {
\t\tsend(emit, Event{Stage: "inspect", Message: fmt.Sprintf("Automatic Windows layout resolved to %s/%s from the selected image capabilities.", strings.ToUpper(scheme), strings.ToUpper(targetSystem))})
\t}
\tif targetSystem == "bios" {
''',
)
replace_once(
    "internal/windowsmedia/windowsmedia.go",
    '''\tscheme, err := normalizePartitionScheme(opts.PartitionScheme)
\tif err != nil {
\t\treturn err
\t}
\tif targetSystem == "bios" && scheme != "mbr" {
\t\treturn errors.New("legacy BIOS/CSM Windows media requires the MBR partition scheme")
\t}
''',
    '',
)

replace_once(
    "gui/rufusarm64_logic.py",
    'RFC3339_UTC_PATTERN = re.compile(r"^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$")\n',
    '''RFC3339_UTC_PATTERN = re.compile(r"^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$")

DEFAULT_VERIFY_AFTER_WRITE = False
DEFAULT_WINDOWS_PARTITION_SCHEME = "auto"
DEFAULT_WINDOWS_TARGET_SYSTEM = "auto"
DEFAULT_WINDOWS_FILESYSTEM = "auto"
DEFAULT_WINDOWS_CLUSTER_SIZE = "auto"
DEFAULT_QUICK_FORMAT = True
DEFAULT_BAD_BLOCK_CHECK = False
DEFAULT_PERSISTENCE_ENABLED = False
''',
)
replace_once(
    "gui/rufusarm64_logic.py",
    '''def normalize_partition_scheme(value):
    value = (value or "gpt").strip().lower()
    if value not in {"gpt", "mbr"}:
        raise ValueError("Partition scheme must be GPT or MBR.")
    return value
''',
    '''def normalize_partition_scheme(value):
    value = (value or DEFAULT_WINDOWS_PARTITION_SCHEME).strip().lower()
    if value not in {"auto", "gpt", "mbr"}:
        raise ValueError("Partition scheme must be Automatic, GPT, or MBR.")
    return value
''',
)
replace_once(
    "gui/rufusarm64_logic.py",
    '''def normalize_target_system(value):
    value = (value or "uefi").strip().lower()
    aliases = {"legacy": "bios", "legacy-bios": "bios", "bios-csm": "bios"}
    value = aliases.get(value, value)
    if value not in {"uefi", "bios"}:
        raise ValueError("Target system must be UEFI or BIOS/CSM.")
    return value
''',
    '''def normalize_target_system(value):
    value = (value or DEFAULT_WINDOWS_TARGET_SYSTEM).strip().lower()
    aliases = {"legacy": "bios", "legacy-bios": "bios", "bios-csm": "bios"}
    value = aliases.get(value, value)
    if value not in {"auto", "uefi", "bios"}:
        raise ValueError("Target system must be Automatic, UEFI, or BIOS/CSM.")
    return value
''',
)
replace_once(
    "gui/rufusarm64_logic.py",
    '''    partition_scheme="gpt",
    target_system="uefi",
    filesystem="auto",
    cluster_size="auto",
''',
    '''    partition_scheme=DEFAULT_WINDOWS_PARTITION_SCHEME,
    target_system=DEFAULT_WINDOWS_TARGET_SYSTEM,
    filesystem=DEFAULT_WINDOWS_FILESYSTEM,
    cluster_size=DEFAULT_WINDOWS_CLUSTER_SIZE,
''',
)
replace_once(
    "gui/rufusarm64_logic.py",
    '''    quick_format=True,
    bad_block_check=False,
''',
    '''    quick_format=DEFAULT_QUICK_FORMAT,
    bad_block_check=DEFAULT_BAD_BLOCK_CHECK,
''',
)
replace_once(
    "gui/rufusarm64_logic.py",
    '''    if target_system == "bios" and partition_scheme != "mbr":
        raise ValueError("BIOS/CSM requires the MBR partition scheme.")
''',
    '''    if target_system == "bios" and partition_scheme == "gpt":
        raise ValueError("BIOS/CSM cannot be combined with the GPT partition scheme.")
''',
)

replace_once(
    "gui/rufusarm64.py",
    '''    acquisition_image_label,
    atomic_write_json,
''',
    '''    acquisition_image_label,
    atomic_write_json,
    DEFAULT_BAD_BLOCK_CHECK,
    DEFAULT_PERSISTENCE_ENABLED,
    DEFAULT_QUICK_FORMAT,
    DEFAULT_VERIFY_AFTER_WRITE,
    DEFAULT_WINDOWS_CLUSTER_SIZE,
    DEFAULT_WINDOWS_FILESYSTEM,
    DEFAULT_WINDOWS_PARTITION_SCHEME,
    DEFAULT_WINDOWS_TARGET_SYSTEM,
''',
)
replace_once("gui/rufusarm64.py", '        self.verify.set_active(bool(self.settings.get("verify", True)))\n', '        self.verify.set_active(bool(self.settings.get("verify", DEFAULT_VERIFY_AFTER_WRITE)))\n')
replace_once("gui/rufusarm64.py", '        self.persistence_enabled.set_active(False)\n', '        self.persistence_enabled.set_active(DEFAULT_PERSISTENCE_ENABLED)\n')
replace_once(
    "gui/rufusarm64.py",
    '''        self.partition_combo = Gtk.ComboBoxText()
        self.partition_combo.append("gpt", "GPT")
        self.partition_combo.append("mbr", "MBR")
        self.partition_combo.append("from-image", "From image")
        saved_scheme = self.settings.get("partition_scheme", "gpt")
        self.windows_partition_scheme = saved_scheme if saved_scheme in {"gpt", "mbr"} else "gpt"
''',
    '''        self.partition_combo = Gtk.ComboBoxText()
        self.partition_combo.append("auto", "Automatic (image-derived)")
        self.partition_combo.append("gpt", "GPT")
        self.partition_combo.append("mbr", "MBR")
        self.partition_combo.append("from-image", "From image")
        saved_scheme = self.settings.get("partition_scheme", DEFAULT_WINDOWS_PARTITION_SCHEME)
        self.windows_partition_scheme = saved_scheme if saved_scheme in {"auto", "gpt", "mbr"} else DEFAULT_WINDOWS_PARTITION_SCHEME
''',
)
replace_once(
    "gui/rufusarm64.py",
    '''        self.target_system_combo = Gtk.ComboBoxText()
        self.target_system_combo.append("uefi", "UEFI (non-CSM)")
        self.target_system_combo.append("bios", "BIOS or UEFI-CSM")
        self.target_system_combo.append("from-image", "From image")
        saved_target = str(self.settings.get("target_system", "uefi"))
        self.windows_target_system = saved_target if saved_target in {"uefi", "bios"} else "uefi"
''',
    '''        self.target_system_combo = Gtk.ComboBoxText()
        self.target_system_combo.append("auto", "Automatic (image-derived)")
        self.target_system_combo.append("uefi", "UEFI (non-CSM)")
        self.target_system_combo.append("bios", "BIOS or UEFI-CSM")
        self.target_system_combo.append("from-image", "From image")
        saved_target = str(self.settings.get("target_system", DEFAULT_WINDOWS_TARGET_SYSTEM))
        self.windows_target_system = saved_target if saved_target in {"auto", "uefi", "bios"} else DEFAULT_WINDOWS_TARGET_SYSTEM
''',
)
replace_once("gui/rufusarm64.py", '        saved_filesystem = str(self.settings.get("filesystem", "auto"))\n        self.windows_filesystem = saved_filesystem if saved_filesystem in {"auto", "fat32", "ntfs"} else "auto"\n', '        saved_filesystem = str(self.settings.get("filesystem", DEFAULT_WINDOWS_FILESYSTEM))\n        self.windows_filesystem = saved_filesystem if saved_filesystem in {"auto", "fat32", "ntfs"} else DEFAULT_WINDOWS_FILESYSTEM\n')
replace_once("gui/rufusarm64.py", '        saved_cluster = str(self.settings.get("cluster_size", "auto"))\n        self.windows_cluster_size = saved_cluster if saved_cluster in {"auto", "4096", "8192", "16384", "32768"} else "auto"\n', '        saved_cluster = str(self.settings.get("cluster_size", DEFAULT_WINDOWS_CLUSTER_SIZE))\n        self.windows_cluster_size = saved_cluster if saved_cluster in {"auto", "4096", "8192", "16384", "32768"} else DEFAULT_WINDOWS_CLUSTER_SIZE\n')
replace_once("gui/rufusarm64.py", '        self.quick_format.set_active(bool(self.settings.get("quick_format", True)))\n', '        self.quick_format.set_active(bool(self.settings.get("quick_format", DEFAULT_QUICK_FORMAT)))\n')
replace_once("gui/rufusarm64.py", '        self.bad_block_check.set_active(bool(self.settings.get("bad_block_check", False)))\n', '        self.bad_block_check.set_active(bool(self.settings.get("bad_block_check", DEFAULT_BAD_BLOCK_CHECK)))\n')
replace_once(
    "gui/rufusarm64.py",
    '''        if scheme in {"gpt", "mbr"}:
            self.windows_partition_scheme = scheme
        if target_system in {"uefi", "bios"}:
            self.windows_target_system = target_system
''',
    '''        if scheme in {"auto", "gpt", "mbr"}:
            self.windows_partition_scheme = scheme
        if target_system in {"auto", "uefi", "bios"}:
            self.windows_target_system = target_system
''',
)
for _ in range(2):
    replace_once(
        "gui/rufusarm64.py",
        '''            if self.partition_combo.get_active_id() in {"gpt", "mbr"}:
                self.windows_partition_scheme = self.partition_combo.get_active_id()
            if self.target_system_combo.get_active_id() in {"uefi", "bios"}:
                self.windows_target_system = self.target_system_combo.get_active_id()
''',
        '''            if self.partition_combo.get_active_id() in {"auto", "gpt", "mbr"}:
                self.windows_partition_scheme = self.partition_combo.get_active_id()
            if self.target_system_combo.get_active_id() in {"auto", "uefi", "bios"}:
                self.windows_target_system = self.target_system_combo.get_active_id()
''',
    )
replace_once(
    "gui/rufusarm64.py",
    '''    def target_system_changed(self, *_):
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
''',
    '''    def target_system_changed(self, *_):
        if self.inspection.get("mode") != "windows":
            return
        target_system = self.target_system_combo.get_active_id() or DEFAULT_WINDOWS_TARGET_SYSTEM
        if target_system not in {"auto", "uefi", "bios"}:
            return
        self.windows_target_system = target_system
        if target_system == "bios" and self.partition_combo.get_active_id() == "gpt":
            self.partition_combo.set_active_id("mbr")
            return
        self.partition_changed()

    def partition_changed(self, *_):
        if self.inspection.get("mode") != "windows":
            return
        scheme = self.partition_combo.get_active_id() or DEFAULT_WINDOWS_PARTITION_SCHEME
        target_system = self.target_system_combo.get_active_id() or DEFAULT_WINDOWS_TARGET_SYSTEM
        filesystem = self.filesystem_combo.get_active_id() or DEFAULT_WINDOWS_FILESYSTEM
        if scheme not in {"auto", "gpt", "mbr"} or target_system not in {"auto", "uefi", "bios"}:
            return
        if target_system == "bios" and scheme == "gpt":
            self.partition_combo.set_active_id("mbr")
            return
        self.windows_partition_scheme = scheme
        self.windows_target_system = target_system

        if scheme == "auto" or target_system == "auto":
            if filesystem == "ntfs":
                fs_note = "NTFS keeps install.wim intact and uses UEFI:NTFS when the resolved target is UEFI."
            elif filesystem == "fat32":
                fs_note = "FAT32 uses the native firmware path and splits install.wim when required."
            else:
                fs_note = "Automatic filesystem selection prefers FAT32 and uses NTFS only when FAT32 cannot safely represent the ISO."
            self.layout_note.set_text(
                "Automatic layout follows the selected Windows image: supported UEFI-capable media defaults to GPT/UEFI; "
                "an explicit BIOS choice resolves Automatic partition scheme to MBR. " + fs_note
            )
            return

        if target_system == "bios":
''',
)

replace_once(
    "gui/test_logic.py",
    '''        self.assertEqual(normalize_partition_scheme("MBR"), "mbr")
        self.assertEqual(normalize_target_system("legacy-bios"), "bios")
''',
    '''        self.assertEqual(normalize_partition_scheme(None), "auto")
        self.assertEqual(normalize_partition_scheme("MBR"), "mbr")
        self.assertEqual(normalize_target_system(None), "auto")
        self.assertEqual(normalize_target_system("legacy-bios"), "bios")
''',
)
replace_once(
    "gui/test_logic.py",
    '''    def test_regional_normalization(self):
''',
    '''    def test_writer_defaults_are_image_derived_and_verification_is_opt_in(self):
        command = build_writer_command(
            "pkexec", "/helper", "/image.iso", "/dev/sda", "abc", False, "/tmp/cancel"
        )
        self.assertEqual(command[command.index("--partition-scheme") + 1], "auto")
        self.assertEqual(command[command.index("--target-system") + 1], "auto")
        self.assertEqual(command[command.index("--filesystem") + 1], "auto")
        self.assertEqual(command[command.index("--cluster-size") + 1], "auto")
        for flag in ("--verify", "--full-format", "--bad-block-check"):
            self.assertNotIn(flag, command)
        bios_auto = build_writer_command(
            "pkexec", "/helper", "/image.iso", "/dev/sda", "abc", False, "/tmp/cancel",
            partition_scheme="auto", target_system="bios",
        )
        self.assertEqual(bios_auto[bios_auto.index("--partition-scheme") + 1], "auto")
        self.assertEqual(bios_auto[bios_auto.index("--target-system") + 1], "bios")

    def test_regional_normalization(self):
''',
)

replace_once(
    "CHANGELOG.md",
    '- Held plain raw/ISOHybrid sources under the identity-bound Linux read lease through destructive writing, while retaining the complete pre-write and write-time digest comparison and the conservative fallback for unsupported or already-writable sources.\n',
    '- Held plain raw/ISOHybrid sources under the identity-bound Linux read lease through destructive writing, while retaining the complete pre-write and write-time digest comparison and the conservative fallback for unsupported or already-writable sources.\n- Aligned fresh-profile defaults with pinned upstream Rufus: post-write verification is opt-in, quick format remains on, bad-block testing and persistence remain off, and Windows partition/target choices now default to image-derived Automatic rather than preselecting GPT/UEFI.\n',
)
