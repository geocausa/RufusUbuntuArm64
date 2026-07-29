#!/usr/bin/env python3
from pathlib import Path


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    if new in text:
        return
    if old not in text:
        raise SystemExit(f"missing {label} anchor in {path}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


ca = Path("internal/windowsmedia/ca2023.go")
replace_once(
    ca,
    '''\tif !capability.Available {
\t\treason := strings.TrimSpace(capability.Reason)
\t\tif reason == "" {
\t\t\treason = "a complete boot.wim _EX replacement set was not proven"
\t\t}
\t\treturn fmt.Errorf("Windows UEFI CA 2023 bootloaders are unavailable: %s", reason)
\t}
\tif strings.ToLower(strings.TrimSpace(targetSystem)) != "uefi" {
''',
    '''\tif !capability.Available {
\t\treason := strings.TrimSpace(capability.Reason)
\t\tif reason == "" {
\t\t\treason = "a complete boot.wim _EX replacement set was not proven"
\t\t}
\t\treturn fmt.Errorf("Windows UEFI CA 2023 bootloaders are unavailable: %s", reason)
\t}
\tinstallArchitecture := normalizeWIMArchitecture(metadata.Architecture)
\tif installArchitecture == "" || capability.Architecture == "" {
\t\treturn errors.New("Windows UEFI CA 2023 architecture evidence is missing or unsupported")
\t}
\tif installArchitecture != capability.Architecture {
\t\treturn fmt.Errorf("Windows installation payload architecture %s does not match boot.wim CA 2023 architecture %s", installArchitecture, capability.Architecture)
\t}
\tif strings.ToLower(strings.TrimSpace(targetSystem)) != "uefi" {
''',
    "selection architecture binding",
)

marker = "func summarizeWindowsCA2023Capability(capability WindowsCA2023Capability, plan *WindowsCA2023Plan) WindowsCA2023Capability {\n"
helper = '''func validateWindowsCA2023Architecture(metadata windowsconfig.MediaMetadata, plan *WindowsCA2023Plan) error {
\tif plan == nil {
\t\treturn errors.New("Windows UEFI CA 2023 replacement plan is missing")
\t}
\tinstallArchitecture := normalizeWIMArchitecture(metadata.Architecture)
\tif installArchitecture == "" {
\t\treturn errors.New("Windows installation payload architecture is missing or unsupported")
\t}
\tif installArchitecture != plan.Architecture {
\t\treturn fmt.Errorf("Windows installation payload architecture %s does not match staged boot.wim CA 2023 architecture %s", installArchitecture, plan.Architecture)
\t}
\treturn nil
}

'''
text = ca.read_text(encoding="utf-8")
if helper.strip() not in text:
    if marker not in text:
        raise SystemExit("missing architecture helper insertion anchor")
    ca.write_text(text.replace(marker, helper + marker, 1), encoding="utf-8")

replace_once(
    ca,
    '''\tmetadata, err := inspectWindowsCA2023Metadata(ctx, bootWIMPath)
\tif err != nil {
\t\treturn WindowsCA2023Capability{}, fmt.Errorf("inspect boot.wim metadata: %w", err)
\t}
\tindexes := make([]int, 0, 2)
''',
    '''\tmetadata, err := inspectWindowsCA2023Metadata(ctx, bootWIMPath)
\tif err != nil {
\t\treturn WindowsCA2023Capability{}, fmt.Errorf("inspect boot.wim metadata: %w", err)
\t}
\tbootArchitecture := normalizeWIMArchitecture(metadata.Architecture)
\tif bootArchitecture == "" {
\t\treturn WindowsCA2023Capability{Reason: "boot.wim architecture is missing or unsupported"}, nil
\t}
\tindexes := make([]int, 0, 2)
''',
    "boot.wim architecture extraction",
)
replace_once(
    ca,
    '''\t\tif complete {
\t\t\treturn WindowsCA2023Capability{Available: true, ImageIndex: index}, nil
\t\t}
''',
    '''\t\tif complete {
\t\t\treturn WindowsCA2023Capability{Available: true, ImageIndex: index, Architecture: bootArchitecture}, nil
\t\t}
''',
    "capability architecture evidence",
)
replace_once(
    ca,
    '''\tarchitecture, fallback, err := ca2023Architecture(bootmgfwEvidence.Machine)
\tif err != nil {
\t\treturn nil, err
\t}
\tif _, ok := findRelativeCaseInsensitive(isoRoot, fallback); !ok {
''',
    '''\tarchitecture, fallback, err := ca2023Architecture(bootmgfwEvidence.Machine)
\tif err != nil {
\t\treturn nil, err
\t}
\tif capability.Architecture == "" || capability.Architecture != architecture {
\t\treturn nil, fmt.Errorf("boot.wim metadata architecture %s does not match staged CA 2023 PE architecture %s", capability.Architecture, architecture)
\t}
\tif _, ok := findRelativeCaseInsensitive(isoRoot, fallback); !ok {
''',
    "staged PE architecture binding",
)

analysis = Path("internal/windowsmedia/analysis.go")
replace_once(
    analysis,
    '''\t\tif stageErr != nil {
\t\t\tca2023 = WindowsCA2023Capability{Reason: fmt.Sprintf("Windows UEFI CA 2023 bootloader validation failed: %v", stageErr)}
\t\t} else {
\t\t\tca2023 = summarizeWindowsCA2023Capability(ca2023, staged)
\t\t}
''',
    '''\t\tif stageErr != nil {
\t\t\tca2023 = WindowsCA2023Capability{Reason: fmt.Sprintf("Windows UEFI CA 2023 bootloader validation failed: %v", stageErr)}
\t\t} else if architectureErr := validateWindowsCA2023Architecture(metadata, staged); architectureErr != nil {
\t\t\tca2023 = WindowsCA2023Capability{Reason: architectureErr.Error()}
\t\t} else {
\t\t\tca2023 = summarizeWindowsCA2023Capability(ca2023, staged)
\t\t}
''',
    "analysis architecture refusal",
)
