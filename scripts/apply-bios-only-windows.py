#!/usr/bin/env python3
from pathlib import Path


def replace_once(path, old, new):
    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one replacement for {old.splitlines()[0]!r}, found {count}")
    file_path.write_text(text.replace(old, new, 1), encoding="utf-8")


replace_once(
    "internal/windowsmedia/windowsmedia.go",
    '''\tArchitecture       string
\tHasARM64           bool
\tHasX64             bool
\tHasX86             bool
\tHasBootmgr         bool
''',
    '''\tArchitecture       string
\tBootWIMPath        string
\tHasARM64           bool
\tHasX64             bool
\tHasX86             bool
\tHasBIOS            bool
\tBIOSArchitecture   string
\tHasBootmgr         bool
''',
)

replace_once(
    "internal/windowsmedia/windowsmedia.go",
    '''\tplan, err := inspectMountedISO(isoMount)
\tif err != nil {
\t\treturn err
\t}
\tif opts.RequireARM64 && !plan.HasARM64 {
\t\treturn errors.New("this ISO contains only x86/x86-64 Windows boot files and will not boot this ARM64 computer; choose an official Windows ARM64 ISO")
\t}
\tscheme, targetSystem, err := resolveWindowsLayout(plan, opts.PartitionScheme, opts.TargetSystem)
\tif err != nil {
\t\treturn err
\t}
''',
    '''\tplan, err := inspectMountedISO(isoMount)
\tif err != nil {
\t\treturn err
\t}
\tif err := bindBootCapabilities(ctx, &plan); err != nil {
\t\treturn err
\t}
\tscheme, targetSystem, err := resolveWindowsLayout(plan, opts.PartitionScheme, opts.TargetSystem)
\tif err != nil {
\t\treturn err
\t}
\tif opts.RequireARM64 && targetSystem == "uefi" && !plan.HasARM64 {
\t\treturn errors.New("this ISO contains only x86/x86-64 Windows UEFI boot files and will not boot this ARM64 computer; choose an official Windows ARM64 ISO or deliberately select a proven legacy-BIOS layout")
\t}
''',
)
replace_once(
    "internal/windowsmedia/windowsmedia.go",
    '''\tif targetSystem == "bios" {
\t\tif !plan.HasX64 && !plan.HasX86 {
\t\t\treturn errors.New("legacy BIOS/CSM Windows media requires an x86 or x86-64 ISO; Windows ARM64 boots through UEFI only")
\t\t}
\t\tif !plan.HasBootmgr {
\t\t\treturn errors.New("this Windows ISO has no root bootmgr file and cannot be made legacy-BIOS bootable")
\t\t}
\t}
''',
    '''\tif targetSystem == "bios" && !plan.HasBIOS {
\t\treturn errors.New("legacy BIOS/CSM Windows media requires a root bootmgr file and x86 or x86-64 boot metadata; Windows ARM64 boots through UEFI only")
\t}
''',
)

replace_once(
    "internal/windowsmedia/windowsmedia.go",
    '''func inspectMountedISO(root string) (mediaPlan, error) {
\tif _, ok := findRelativeCaseInsensitive(root, "sources/boot.wim"); !ok {
\t\treturn mediaPlan{}, errors.New("this is not a supported Windows installation ISO: sources/boot.wim was not found")
\t}

\t_, arm64 := findRelativeCaseInsensitive(root, "efi/boot/bootaa64.efi")
''',
    '''func inspectMountedISO(root string) (mediaPlan, error) {
\tbootWIMPath, ok := findRelativeCaseInsensitive(root, "sources/boot.wim")
\tif !ok {
\t\treturn mediaPlan{}, errors.New("this is not a supported Windows installation ISO: sources/boot.wim was not found")
\t}

\t_, arm64 := findRelativeCaseInsensitive(root, "efi/boot/bootaa64.efi")
''',
)
replace_once(
    "internal/windowsmedia/windowsmedia.go",
    '''\tarchitecture := "UEFI"
\tswitch {
\tcase arm64 && x64:
\t\tarchitecture = "ARM64/x86-64 UEFI"
\tcase arm64:
\t\tarchitecture = "ARM64 UEFI"
\tcase x64:
\t\tarchitecture = "x86-64 UEFI"
\tcase x86:
\t\tarchitecture = "x86 UEFI"
\tdefault:
\t\treturn mediaPlan{}, errors.New("the ISO has no standard ARM64 or x86-64 UEFI boot file")
\t}
''',
    '''\tarchitecture := ""
\tswitch {
\tcase arm64 && x64:
\t\tarchitecture = "ARM64/x86-64 UEFI"
\tcase arm64:
\t\tarchitecture = "ARM64 UEFI"
\tcase x64:
\t\tarchitecture = "x86-64 UEFI"
\tcase x86:
\t\tarchitecture = "x86 UEFI"
\tcase bootmgr:
\t\tarchitecture = "legacy BIOS (architecture pending WIM inspection)"
\tdefault:
\t\treturn mediaPlan{}, errors.New("the ISO has no standard UEFI fallback loader and no root bootmgr file")
\t}
''',
)
replace_once(
    "internal/windowsmedia/windowsmedia.go",
    '''\tplan := mediaPlan{
\t\tInstallPath:        installPath,
\t\tExistingSplitFiles: existingSplitFiles,
\t\tArchitecture:       architecture,
\t\tHasARM64:           arm64,
\t\tHasX64:             x64,
\t\tHasX86:             x86,
\t\tHasBootmgr:         bootmgr,
\t}
''',
    '''\tplan := mediaPlan{
\t\tInstallPath:        installPath,
\t\tExistingSplitFiles: existingSplitFiles,
\t\tArchitecture:       architecture,
\t\tBootWIMPath:        bootWIMPath,
\t\tHasARM64:           arm64,
\t\tHasX64:             x64,
\t\tHasX86:             x86,
\t\tHasBootmgr:         bootmgr,
\t}
\tif bootmgr && x64 {
\t\tplan.HasBIOS = true
\t\tplan.BIOSArchitecture = "amd64"
\t} else if bootmgr && x86 {
\t\tplan.HasBIOS = true
\t\tplan.BIOSArchitecture = "x86"
\t}
''',
)
replace_once(
    "internal/windowsmedia/windowsmedia.go",
    '''// validateFATCompatibility performs the checks that matter only when the main
''',
    '''func bindBootCapabilities(ctx context.Context, plan *mediaPlan) error {
\tif plan == nil {
\t\treturn errors.New("Windows media plan is nil")
\t}
\tif plan.HasARM64 || plan.HasX64 || plan.HasX86 {
\t\treturn nil
\t}
\tif !plan.HasBootmgr {
\t\treturn errors.New("the Windows ISO has neither a supported UEFI fallback loader nor root bootmgr")
\t}
\tif strings.TrimSpace(plan.BootWIMPath) == "" {
\t\treturn errors.New("the Windows ISO has no identity-bound boot.wim path for legacy-BIOS architecture inspection")
\t}
\tmetadata, err := InspectWIMMetadata(ctx, plan.BootWIMPath)
\tif err != nil {
\t\treturn fmt.Errorf("inspect boot.wim before accepting legacy-BIOS media: %w", err)
\t}
\treturn bindBIOSMetadata(plan, metadata)
}

func bindBIOSMetadata(plan *mediaPlan, metadata windowsconfig.MediaMetadata) error {
\tif plan == nil {
\t\treturn errors.New("Windows media plan is nil")
\t}
\tif !plan.HasBootmgr {
\t\treturn errors.New("legacy-BIOS capability requires a root bootmgr file")
\t}
\tswitch normalizeWIMArchitecture(metadata.Architecture) {
\tcase "amd64":
\t\tplan.HasBIOS = true
\t\tplan.BIOSArchitecture = "amd64"
\t\tplan.Architecture = "x86-64 legacy BIOS"
\tcase "x86":
\t\tplan.HasBIOS = true
\t\tplan.BIOSArchitecture = "x86"
\t\tplan.Architecture = "x86 legacy BIOS"
\tcase "arm64":
\t\treturn errors.New("Windows ARM64 boot.wim cannot be used as legacy-BIOS media; ARM64 boots through UEFI only")
\tdefault:
\t\treturn fmt.Errorf("boot.wim architecture %q is unsupported or ambiguous for legacy-BIOS media", metadata.Architecture)
\t}
\treturn nil
}

// validateFATCompatibility performs the checks that matter only when the main
''',
)

replace_once(
    "cmd/rufus-linux/main.go",
    '''\tfmt.Printf("Windows %s %s (%s)\\n", result.Capabilities.Generation, result.Capabilities.Family, result.Capabilities.Architecture)
''',
    '''\tfmt.Printf("Windows %s %s (%s)\\n", result.Capabilities.Generation, result.Capabilities.Family, result.Capabilities.Architecture)
\tfmt.Printf("  Boot capability: %s\\n", result.BootArchitecture)
\tfmt.Printf("  Automatic layout: %s / %s\\n", strings.ToUpper(result.DefaultPartitionScheme), strings.ToUpper(result.DefaultTargetSystem))
''',
)

replace_once(
    "gui/rufusarm64.py",
    '''    normalized = dict(payload)
    normalized["metadata"] = metadata
    normalized["capabilities"] = capabilities
    return normalized
''',
    '''    default_scheme = str(payload.get("default_partition_scheme") or "").strip().lower()
    default_target = str(payload.get("default_target_system") or "").strip().lower()
    if default_scheme not in {"gpt", "mbr"} or default_target not in {"uefi", "bios"}:
        raise ValueError("Windows capability analysis is missing a resolved automatic layout.")
    normalized = dict(payload)
    normalized["metadata"] = metadata
    normalized["capabilities"] = capabilities
    normalized["default_partition_scheme"] = default_scheme
    normalized["default_target_system"] = default_target
    return normalized
''',
)
replace_once(
    "gui/rufusarm64.py",
    '''        return {
        "metadata": {},
        "capabilities": {
''',
    '''        return {
        "metadata": {},
        "default_partition_scheme": "",
        "default_target_system": "",
        "capabilities": {
''',
)
replace_once(
    "gui/rufusarm64.py",
    '''            return f"Detected Windows {generation} {family} media ({architecture}). Unsupported options are disabled below."
''',
    '''            scheme = str(self.capability_analysis.get("default_partition_scheme") or "").upper()
            target = str(self.capability_analysis.get("default_target_system") or "").upper()
            layout = f" Automatic layout: {scheme}/{target}." if scheme and target else ""
            return f"Detected Windows {generation} {family} media ({architecture}).{layout} Unsupported options are disabled below."
''',
)
replace_once(
    "gui/rufusarm64.py",
    '''        elif self.inspection.get("mode") == "windows":
            layout_summary = f"{partition_scheme.upper()} / {self.target_system_combo.get_active_text()} / {filesystem.upper()} / {self.cluster_combo.get_active_text()} clusters"
''',
    '''        elif self.inspection.get("mode") == "windows":
            display_scheme = partition_scheme
            display_target = target_system
            if partition_scheme == "auto":
                display_scheme = str(self.windows_capability_analysis.get("default_partition_scheme") or "auto")
            if target_system == "auto":
                display_target = str(self.windows_capability_analysis.get("default_target_system") or "auto")
            layout_summary = f"{display_scheme.upper()} / {display_target.upper()} / {filesystem.upper()} / {self.cluster_combo.get_active_text()} clusters"
''',
)

replace_once(
    "CHANGELOG.md",
    '''- Aligned fresh-profile defaults with pinned upstream Rufus: post-write verification is opt-in, quick format remains on, bad-block testing and persistence remain off, and Windows partition/target choices now default to image-derived Automatic rather than preselecting GPT/UEFI.
''',
    '''- Aligned fresh-profile defaults with pinned upstream Rufus: post-write verification is opt-in, quick format remains on, bad-block testing and persistence remain off, and Windows partition/target choices now default to image-derived Automatic rather than preselecting GPT/UEFI.
- Recognized proven BIOS-only Windows setup ISOs by binding root `bootmgr` to bounded `boot.wim` x86/x64 metadata, allowing Automatic to choose MBR/BIOS without weakening ARM64 UEFI checks.
''',
)
