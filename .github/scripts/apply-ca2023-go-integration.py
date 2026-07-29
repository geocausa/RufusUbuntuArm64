#!/usr/bin/env python3
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if new in text:
        return text
    if old not in text:
        raise SystemExit(f"missing anchor: {label}")
    return text.replace(old, new, 1)


def write(path: str, text: str) -> None:
    Path(path).write_text(text, encoding="utf-8")


# Capability schema and policy.
path = Path("internal/windowsconfig/capabilities.go")
text = path.read_text(encoding="utf-8")
text = replace_once(
    text,
    '''\tSkuSiPolicyAvailable      bool     `json:"sku_si_policy_available"`\n\tSkuSiPolicyUnavailableWhy string   `json:"sku_si_policy_unavailable_reason,omitempty"`\n''',
    '''\tSkuSiPolicyAvailable             bool     `json:"sku_si_policy_available"`\n\tSkuSiPolicyUnavailableWhy        string   `json:"sku_si_policy_unavailable_reason,omitempty"`\n\tWindowsCA2023Available           bool     `json:"windows_ca_2023_available"`\n\tWindowsCA2023UnavailableWhy      string   `json:"windows_ca_2023_unavailable_reason,omitempty"`\n\tWindowsCA2023ImageIndex          int      `json:"windows_ca_2023_image_index,omitempty"`\n''',
    "Windows metadata CA 2023 fields",
)
text = replace_once(
    text,
    '''\tQualityOfLife        OptionCapability `json:"quality_of_life"`\n\tApplySkuSiPolicy     OptionCapability `json:"apply_sku_si_policy"`\n\tLocale               OptionCapability `json:"locale"`\n''',
    '''\tQualityOfLife                  OptionCapability `json:"quality_of_life"`\n\tApplySkuSiPolicy               OptionCapability `json:"apply_sku_si_policy"`\n\tUseWindowsCA2023Bootloaders    OptionCapability `json:"use_windows_ca_2023_bootloaders"`\n\tLocale                         OptionCapability `json:"locale"`\n''',
    "Windows capability profile CA 2023 field",
)
text = replace_once(
    text,
    '''\t\tif metadata.SkuSiPolicyAvailable {\n\t\t\tprofile.ApplySkuSiPolicy = generic\n\t\t} else {\n\t\t\treason := strings.TrimSpace(metadata.SkuSiPolicyUnavailableWhy)\n\t\t\tif reason == "" {\n\t\t\t\treason = "SkuSiPolicy.p7b was not found in every Windows installation image"\n\t\t\t}\n\t\t\tprofile.ApplySkuSiPolicy = OptionCapability{Reason: reason}\n\t\t}\n\t} else {\n\t\treason := "Available only for positively identified Windows 11 client media"\n\t\tprofile.BypassHardwareChecks = OptionCapability{Reason: reason}\n\t\tprofile.BypassOnlineAccount = OptionCapability{Reason: reason}\n\t\tprofile.ApplySkuSiPolicy = OptionCapability{Reason: reason}\n\t}\n''',
    '''\t\tif metadata.SkuSiPolicyAvailable {\n\t\t\tprofile.ApplySkuSiPolicy = generic\n\t\t} else {\n\t\t\treason := strings.TrimSpace(metadata.SkuSiPolicyUnavailableWhy)\n\t\t\tif reason == "" {\n\t\t\t\treason = "SkuSiPolicy.p7b was not found in every Windows installation image"\n\t\t\t}\n\t\t\tprofile.ApplySkuSiPolicy = OptionCapability{Reason: reason}\n\t\t}\n\t\tif metadata.WindowsCA2023Available {\n\t\t\tprofile.UseWindowsCA2023Bootloaders = generic\n\t\t} else {\n\t\t\treason := strings.TrimSpace(metadata.WindowsCA2023UnavailableWhy)\n\t\t\tif reason == "" {\n\t\t\t\treason = "A complete, architecture-matched Windows UEFI CA 2023 bootloader set was not proven in boot.wim"\n\t\t\t}\n\t\t\tprofile.UseWindowsCA2023Bootloaders = OptionCapability{Reason: reason}\n\t\t}\n\t} else {\n\t\treason := "Available only for positively identified Windows 11 client media"\n\t\tprofile.BypassHardwareChecks = OptionCapability{Reason: reason}\n\t\tprofile.BypassOnlineAccount = OptionCapability{Reason: reason}\n\t\tprofile.ApplySkuSiPolicy = OptionCapability{Reason: reason}\n\t\tprofile.UseWindowsCA2023Bootloaders = OptionCapability{Reason: reason}\n\t}\n''',
    "Windows 11 CA 2023 capability policy",
)
text = replace_once(
    text,
    '''\tprofile.QualityOfLife = disabled\n\tprofile.ApplySkuSiPolicy = disabled\n\tprofile.Locale = disabled\n''',
    '''\tprofile.QualityOfLife = disabled\n\tprofile.ApplySkuSiPolicy = disabled\n\tprofile.UseWindowsCA2023Bootloaders = disabled\n\tprofile.Locale = disabled\n''',
    "disabled CA 2023 capability",
)
write(str(path), text)


# CA 2023 core evidence and selection guards.
path = Path("internal/windowsmedia/ca2023.go")
text = path.read_text(encoding="utf-8")
text = replace_once(
    text,
    '''\t"github.com/geocausa/RufusArm64/internal/secureboot"\n''',
    '''\t"github.com/geocausa/RufusArm64/internal/secureboot"\n\t"github.com/geocausa/RufusArm64/internal/windowsconfig"\n''',
    "CA 2023 windowsconfig import",
)
text = replace_once(
    text,
    '''type WindowsCA2023Capability struct {\n\tAvailable  bool   `json:"available"`\n\tImageIndex int    `json:"image_index,omitempty"`\n\tReason     string `json:"reason,omitempty"`\n}\n''',
    '''type WindowsCA2023Capability struct {\n\tAvailable        bool   `json:"available"`\n\tImageIndex       int    `json:"image_index,omitempty"`\n\tArchitecture     string `json:"architecture,omitempty"`\n\tAssetCount       int    `json:"asset_count,omitempty"`\n\tReplacementBytes uint64 `json:"replacement_bytes,omitempty"`\n\tOriginalBytes    uint64 `json:"original_bytes,omitempty"`\n\tManifestSHA256   string `json:"manifest_sha256,omitempty"`\n\tReason           string `json:"reason,omitempty"`\n}\n''',
    "CA 2023 capability evidence fields",
)
selection_helper = '''\nfunc validateWindowsCA2023Selection(metadata windowsconfig.MediaMetadata, capability WindowsCA2023Capability, targetSystem, filesystem string) error {\n\tprofile := windowsconfig.Capabilities(metadata)\n\tif !profile.Recognized || profile.Generation != "11" || profile.Family != "client" {\n\t\treason := strings.TrimSpace(profile.Reason)\n\t\tif reason == "" {\n\t\t\treason = "available only for positively identified Windows 11 client media"\n\t\t}\n\t\treturn fmt.Errorf("Windows UEFI CA 2023 bootloaders are unavailable: %s", reason)\n\t}\n\tif !capability.Available {\n\t\treason := strings.TrimSpace(capability.Reason)\n\t\tif reason == "" {\n\t\t\treason = "a complete boot.wim _EX replacement set was not proven"\n\t\t}\n\t\treturn fmt.Errorf("Windows UEFI CA 2023 bootloaders are unavailable: %s", reason)\n\t}\n\tif strings.ToLower(strings.TrimSpace(targetSystem)) != "uefi" {\n\t\treturn errors.New("Windows UEFI CA 2023 bootloader replacement requires a resolved UEFI target")\n\t}\n\tif strings.ToLower(strings.TrimSpace(filesystem)) != "fat32" {\n\t\treturn errors.New("Windows UEFI CA 2023 bootloader replacement currently requires FAT32; the pinned UEFI:NTFS first-stage image is signed through Microsoft UEFI CA 2011 and cannot be represented as CA 2023-only media")\n\t}\n\treturn nil\n}\n\nfunc summarizeWindowsCA2023Capability(capability WindowsCA2023Capability, plan *WindowsCA2023Plan) WindowsCA2023Capability {\n\tif plan == nil {\n\t\treturn capability\n\t}\n\tcapability.Available = true\n\tcapability.ImageIndex = plan.ImageIndex\n\tcapability.Architecture = plan.Architecture\n\tcapability.AssetCount = len(plan.Assets)\n\tcapability.ReplacementBytes = plan.ReplacementBytes\n\tcapability.OriginalBytes = plan.OriginalBytes\n\tcapability.ManifestSHA256 = plan.ManifestSHA256\n\tcapability.Reason = ""\n\treturn capability\n}\n\n'''
marker = "// InspectWindowsCA2023Capability checks only the two boot.wim indexes used by\n"
if selection_helper.strip() not in text:
    if marker not in text:
        raise SystemExit("missing anchor: CA 2023 selection helper insertion")
    text = text.replace(marker, selection_helper + marker, 1)
text = replace_once(
    text,
    '''\tfor _, asset := range plan.Assets {\n\t\tif err := ctx.Err(); err != nil {\n\t\t\treturn err\n\t\t}\n\t\tdestination, err := prepareCA2023Destination(root, asset.Destination)\n''',
    '''\tfor _, asset := range plan.Assets {\n\t\tif err := ctx.Err(); err != nil {\n\t\t\treturn err\n\t\t}\n\t\tif err := verifyStagedWindowsCA2023Asset(asset); err != nil {\n\t\t\treturn err\n\t\t}\n\t\tdestination, err := prepareCA2023Destination(root, asset.Destination)\n''',
    "CA 2023 staged-source revalidation",
)
staged_helper = '''\nfunc verifyStagedWindowsCA2023Asset(asset WindowsCA2023Asset) error {\n\tinfo, err := os.Lstat(asset.sourcePath)\n\tif err != nil {\n\t\treturn fmt.Errorf("restat staged CA 2023 asset %s: %w", asset.Destination, err)\n\t}\n\tif !info.Mode().IsRegular() || uint64(info.Size()) != asset.Size {\n\t\treturn fmt.Errorf("staged CA 2023 asset %s changed type or size after pre-erasure validation", asset.Destination)\n\t}\n\tdigest, err := fileSHA256(asset.sourcePath)\n\tif err != nil {\n\t\treturn fmt.Errorf("rehash staged CA 2023 asset %s: %w", asset.Destination, err)\n\t}\n\tif hex.EncodeToString(digest[:]) != asset.SHA256 {\n\t\treturn fmt.Errorf("staged CA 2023 asset %s changed after pre-erasure validation", asset.Destination)\n\t}\n\treturn nil\n}\n\n'''
marker = "func applyWindowsCA2023(ctx context.Context, root string, plan *WindowsCA2023Plan, progress func(uint64)) error {\n"
if staged_helper.strip() not in text:
    if marker not in text:
        raise SystemExit("missing anchor: staged CA 2023 verifier insertion")
    text = text.replace(marker, staged_helper + marker, 1)
write(str(path), text)


# Read-only capability analysis, including the actual automatic filesystem result.
path = Path("internal/windowsmedia/analysis.go")
text = path.read_text(encoding="utf-8")
text = replace_once(
    text,
    '''\tDefaultPartitionScheme string                          `json:"default_partition_scheme"`\n\tDefaultTargetSystem    string                          `json:"default_target_system"`\n\tPayloadKind            string                          `json:"payload_kind"`\n''',
    '''\tDefaultPartitionScheme string                          `json:"default_partition_scheme"`\n\tDefaultTargetSystem    string                          `json:"default_target_system"`\n\tDefaultFilesystem      string                          `json:"default_filesystem"`\n\tWindowsCA2023          WindowsCA2023Capability         `json:"windows_ca_2023"`\n\tPayloadKind            string                          `json:"payload_kind"`\n''',
    "capability analysis filesystem and CA 2023 evidence",
)
text = replace_once(
    text,
    '''\tdefaultScheme, defaultTarget, err := resolveWindowsLayout(plan, "auto", "auto")\n\tif err != nil {\n\t\treturn CapabilityAnalysis{}, err\n\t}\n\tpayloadKind, payloadParts, err := capabilityPayloadFacts(plan)\n''',
    '''\tdefaultScheme, defaultTarget, err := resolveWindowsLayout(plan, "auto", "auto")\n\tif err != nil {\n\t\treturn CapabilityAnalysis{}, err\n\t}\n\tdefaultFilesystem, err := resolveFilesystem("auto", validateFATCompatibility(mountPath, plan))\n\tif err != nil {\n\t\treturn CapabilityAnalysis{}, err\n\t}\n\tpayloadKind, payloadParts, err := capabilityPayloadFacts(plan)\n''',
    "automatic filesystem analysis",
)
text = replace_once(
    text,
    '''\tmetadata, err := InspectWIMSetupMetadata(ctx, payloadPath)\n\tif err != nil {\n\t\treturn CapabilityAnalysis{}, fmt.Errorf("inspect Windows setup capabilities: %w", err)\n\t}\n\treturn CapabilityAnalysis{\n\t\tMetadata:               metadata,\n\t\tCapabilities:           windowsconfig.Capabilities(metadata),\n\t\tBootArchitecture:       plan.Architecture,\n\t\tUEFICapable:            plan.HasARM64 || plan.HasX64 || plan.HasX86,\n\t\tBIOSCapable:            plan.HasBIOS,\n\t\tDefaultPartitionScheme: defaultScheme,\n\t\tDefaultTargetSystem:    defaultTarget,\n\t\tPayloadKind:            payloadKind,\n\t\tPayloadParts:           payloadParts,\n\t}, nil\n''',
    '''\tmetadata, err := InspectWIMSetupMetadata(ctx, payloadPath)\n\tif err != nil {\n\t\treturn CapabilityAnalysis{}, fmt.Errorf("inspect Windows setup capabilities: %w", err)\n\t}\n\tca2023, caErr := InspectWindowsCA2023Capability(ctx, plan.BootWIMPath)\n\tif caErr != nil {\n\t\tca2023 = WindowsCA2023Capability{Reason: fmt.Sprintf("Windows UEFI CA 2023 bootloader inspection failed: %v", caErr)}\n\t} else if ca2023.Available {\n\t\tstaged, stageErr := StageWindowsCA2023(ctx, plan.BootWIMPath, mountPath, workDir, ca2023)\n\t\tif stageErr != nil {\n\t\t\tca2023 = WindowsCA2023Capability{Reason: fmt.Sprintf("Windows UEFI CA 2023 bootloader validation failed: %v", stageErr)}\n\t\t} else {\n\t\t\tca2023 = summarizeWindowsCA2023Capability(ca2023, staged)\n\t\t}\n\t}\n\tmetadata.WindowsCA2023Available = ca2023.Available\n\tmetadata.WindowsCA2023UnavailableWhy = ca2023.Reason\n\tmetadata.WindowsCA2023ImageIndex = ca2023.ImageIndex\n\treturn CapabilityAnalysis{\n\t\tMetadata:               metadata,\n\t\tCapabilities:           windowsconfig.Capabilities(metadata),\n\t\tBootArchitecture:       plan.Architecture,\n\t\tUEFICapable:            plan.HasARM64 || plan.HasX64 || plan.HasX86,\n\t\tBIOSCapable:            plan.HasBIOS,\n\t\tDefaultPartitionScheme: defaultScheme,\n\t\tDefaultTargetSystem:    defaultTarget,\n\t\tDefaultFilesystem:      defaultFilesystem,\n\t\tWindowsCA2023:          ca2023,\n\t\tPayloadKind:            payloadKind,\n\t\tPayloadParts:           payloadParts,\n\t}, nil\n''',
    "full CA 2023 capability analysis",
)
write(str(path), text)


# Production writer integration.
path = Path("internal/windowsmedia/windowsmedia.go")
text = path.read_text(encoding="utf-8")
text = replace_once(
    text,
    '''\tBadBlockCheck     bool\n\tCustomizations    windowsconfig.Options\n''',
    '''\tBadBlockCheck                 bool\n\tUseWindowsCA2023Bootloaders    bool\n\tCustomizations                windowsconfig.Options\n''',
    "writer option CA 2023",
)
text = replace_once(
    text,
    '''\tDriverFolder       string\n\tDriverBytes        uint64\n}\n''',
    '''\tDriverFolder       string\n\tDriverBytes        uint64\n\tCA2023             *WindowsCA2023Plan\n}\n''',
    "media plan CA 2023 field",
)
text = replace_once(
    text,
    '''type Event struct {\n\tStage   string\n\tMessage string\n\tDone    uint64\n\tTotal   uint64\n}\n''',
    '''type Event struct {\n\tStage   string\n\tMessage string\n\tDone    uint64\n\tTotal   uint64\n\tHash    string\n}\n''',
    "event hash evidence",
)
text = replace_once(
    text,
    '''\tif strings.TrimSpace(opts.DBXPath) != "" {\n''',
    '''\tvar selectedDBX *secureboot.Database\n\tif strings.TrimSpace(opts.DBXPath) != "" {\n''',
    "selected DBX declaration",
)
text = replace_once(
    text,
    '''\t\tdatabase, err := secureboot.ParseFile(dbxPath)\n\t\tif err != nil {\n''',
    '''\t\tdatabase, err := secureboot.ParseFile(dbxPath)\n\t\tif err != nil {\n''',
    "DBX parse anchor",
)
text = replace_once(
    text,
    '''\t\tif err != nil {\n\t\t\treturn fmt.Errorf("read Secure Boot DBX: %w", err)\n\t\t}\n\t\tsend(emit, Event{Stage: "secure_boot", Message: "Checking Windows EFI boot files against the Secure Boot revocation database…"})\n''',
    '''\t\tif err != nil {\n\t\t\treturn fmt.Errorf("read Secure Boot DBX: %w", err)\n\t\t}\n\t\tselectedDBX = database\n\t\tsend(emit, Event{Stage: "secure_boot", Message: "Checking Windows EFI boot files against the Secure Boot revocation database…"})\n''',
    "retain selected DBX",
)
ca_writer_block = '''\tif opts.UseWindowsCA2023Bootloaders {\n\t\tpayloadPath, payloadErr := customizationImagePath(plan)\n\t\tif payloadErr != nil {\n\t\t\treturn payloadErr\n\t\t}\n\t\tmetadata, metadataErr := InspectWIMSetupMetadata(ctx, payloadPath)\n\t\tif metadataErr != nil {\n\t\t\treturn fmt.Errorf("inspect Windows identity for CA 2023 bootloaders: %w", metadataErr)\n\t\t}\n\t\tcapability, capabilityErr := InspectWindowsCA2023Capability(ctx, plan.BootWIMPath)\n\t\tif capabilityErr != nil {\n\t\t\treturn fmt.Errorf("inspect Windows UEFI CA 2023 bootloader capability: %w", capabilityErr)\n\t\t}\n\t\tif err := validateWindowsCA2023Selection(metadata, capability, targetSystem, filesystem); err != nil {\n\t\t\treturn err\n\t\t}\n\t\tstaged, stageErr := StageWindowsCA2023(ctx, plan.BootWIMPath, isoMount, workDir, capability)\n\t\tif stageErr != nil {\n\t\t\treturn fmt.Errorf("stage Windows UEFI CA 2023 bootloaders before erasing the USB: %w", stageErr)\n\t\t}\n\t\tif selectedDBX != nil {\n\t\t\tfor _, asset := range staged.Assets {\n\t\t\t\tif !strings.EqualFold(filepath.Ext(asset.Destination), ".efi") {\n\t\t\t\t\tcontinue\n\t\t\t\t}\n\t\t\t\tchecked := secureboot.CheckPEFile(asset.sourcePath, selectedDBX)\n\t\t\t\tif checked.Error != "" {\n\t\t\t\t\treturn fmt.Errorf("check staged CA 2023 bootloader %s against DBX: %s", asset.Destination, checked.Error)\n\t\t\t\t}\n\t\t\t\tif checked.DirectHashRevoked || checked.X509CertificateRevoked {\n\t\t\t\t\treturn fmt.Errorf("staged CA 2023 bootloader %s is revoked by the selected Secure Boot DBX; nothing was erased", asset.Destination)\n\t\t\t\t}\n\t\t\t}\n\t\t}\n\t\tplan.CA2023 = staged\n\t\tsend(emit, Event{\n\t\t\tStage: "windows_ca_2023",\n\t\t\tMessage: fmt.Sprintf("Qualified %d Windows UEFI CA 2023 replacement files from boot.wim index %d for %s; firmware must trust Windows UEFI CA 2023.", len(staged.Assets), staged.ImageIndex, strings.ToUpper(staged.Architecture)),\n\t\t\tHash: staged.ManifestSHA256,\n\t\t})\n\t}\n'''
anchor = '''\tif strings.TrimSpace(opts.DriverFolder) != "" {\n'''
if ca_writer_block.strip() not in text:
    if anchor not in text:
        raise SystemExit("missing anchor: CA 2023 writer staging")
    text = text.replace(anchor, ca_writer_block + anchor, 1)
text = replace_once(
    text,
    '''\t\tif err := copyTree(copyCtx, isoMount, usbMount, plan.InstallPath, answerToExclude, report); err != nil {\n''',
    '''\t\tif err := copyTreeWithWindowsCA2023(copyCtx, isoMount, usbMount, plan.InstallPath, answerToExclude, plan.CA2023, report); err != nil {\n''',
    "copy tree CA 2023 exclusions",
)
text = replace_once(
    text,
    '''\t\tif plan.DriverFolder != "" {\n\t\t\tdestination := filepath.Join(usbMount, "drivers")\n\t\t\tif err := os.MkdirAll(destination, 0o755); err != nil {\n\t\t\t\treturn err\n\t\t\t}\n\t\t\tif err := copyTreeWithOptions(copyCtx, plan.DriverFolder, destination, "", "", true, report); err != nil {\n\t\t\t\treturn fmt.Errorf("copy Windows drivers: %w", err)\n\t\t\t}\n\t\t\tif err := os.WriteFile(filepath.Join(usbMount, rufusDriverMarkerName), rufusDriverMarker, 0o644); err != nil {\n\t\t\t\treturn fmt.Errorf("write Windows driver marker: %w", err)\n\t\t\t}\n\t\t\treport(uint64(len(rufusDriverMarker)))\n\t\t}\n\t\treturn nil\n''',
    '''\t\tif plan.DriverFolder != "" {\n\t\t\tdestination := filepath.Join(usbMount, "drivers")\n\t\t\tif err := os.MkdirAll(destination, 0o755); err != nil {\n\t\t\t\treturn err\n\t\t\t}\n\t\t\tif err := copyTreeWithOptions(copyCtx, plan.DriverFolder, destination, "", "", true, report); err != nil {\n\t\t\t\treturn fmt.Errorf("copy Windows drivers: %w", err)\n\t\t\t}\n\t\t\tif err := os.WriteFile(filepath.Join(usbMount, rufusDriverMarkerName), rufusDriverMarker, 0o644); err != nil {\n\t\t\t\treturn fmt.Errorf("write Windows driver marker: %w", err)\n\t\t\t}\n\t\t\treport(uint64(len(rufusDriverMarker)))\n\t\t}\n\t\tif plan.CA2023 != nil {\n\t\t\tsend(emit, Event{Stage: "windows_ca_2023", Message: "Replacing the reviewed removable-media boot files with the staged Windows UEFI CA 2023 set…", Total: plan.CA2023.ReplacementBytes, Hash: plan.CA2023.ManifestSHA256})\n\t\t\tif err := applyWindowsCA2023(copyCtx, usbMount, plan.CA2023, report); err != nil {\n\t\t\t\treturn err\n\t\t\t}\n\t\t}\n\t\treturn nil\n''',
    "apply CA 2023 replacements",
)
text = replace_once(
    text,
    '''\tif opts.Verify {\n\t\tif err := checkTarget(); err != nil {\n\t\t\treturn err\n\t\t}\n\t\tsend(emit, Event{Stage: "verify", Message: "Verifying copied setup files from the USB…"})\n\t\tif err := run(ctx, emit, "mount", "-o", "ro,nosuid,nodev,noexec", "--", partition, usbMount); err != nil {\n\t\t\treturn err\n\t\t}\n\t\tmountedUSB = true\n\t\tif err := withExclusiveMount(ctx, partition, usbMount, func(verifyCtx context.Context) error {\n\t\t\tif err := verifyTree(verifyCtx, isoMount, usbMount, plan, emit); err != nil {\n\t\t\t\treturn err\n\t\t\t}\n\t\t\tif plan.DriverFolder != "" {\n\t\t\t\treturn verifyDirectory(verifyCtx, plan.DriverFolder, filepath.Join(usbMount, "drivers"), emit, &plan)\n\t\t\t}\n\t\t\treturn nil\n\t\t}); err != nil {\n\t\t\treturn err\n\t\t}\n\t\tif err := run(ctx, emit, "umount", "--", usbMount); err != nil {\n\t\t\treturn err\n\t\t}\n\t\tmountedUSB = false\n\t}\n''',
    '''\tif opts.Verify || plan.CA2023 != nil {\n\t\tif err := checkTarget(); err != nil {\n\t\t\treturn err\n\t\t}\n\t\tif err := run(ctx, emit, "mount", "-o", "ro,nosuid,nodev,noexec", "--", partition, usbMount); err != nil {\n\t\t\treturn err\n\t\t}\n\t\tmountedUSB = true\n\t\tif err := withExclusiveMount(ctx, partition, usbMount, func(verifyCtx context.Context) error {\n\t\t\tif opts.Verify {\n\t\t\t\tsend(emit, Event{Stage: "verify", Message: "Verifying copied setup files from the USB…"})\n\t\t\t\tif err := verifyTree(verifyCtx, isoMount, usbMount, plan, emit); err != nil {\n\t\t\t\t\treturn err\n\t\t\t\t}\n\t\t\t\tif plan.DriverFolder != "" {\n\t\t\t\t\tif err := verifyDirectory(verifyCtx, plan.DriverFolder, filepath.Join(usbMount, "drivers"), emit, &plan); err != nil {\n\t\t\t\t\t\treturn err\n\t\t\t\t\t}\n\t\t\t\t}\n\t\t\t}\n\t\t\tif plan.CA2023 != nil {\n\t\t\t\tsend(emit, Event{Stage: "verify_ca_2023", Message: "Reading back every Windows UEFI CA 2023 replacement from the USB…", Total: plan.CA2023.ReplacementBytes, Hash: plan.CA2023.ManifestSHA256})\n\t\t\t\tif err := verifyWindowsCA2023(usbMount, plan.CA2023); err != nil {\n\t\t\t\t\treturn err\n\t\t\t\t}\n\t\t\t\tsend(emit, Event{Stage: "verify_ca_2023", Message: "Windows UEFI CA 2023 replacement readback passed.", Done: plan.CA2023.ReplacementBytes, Total: plan.CA2023.ReplacementBytes, Hash: plan.CA2023.ManifestSHA256})\n\t\t\t}\n\t\t\treturn nil\n\t\t}); err != nil {\n\t\t\treturn err\n\t\t}\n\t\tif err := run(ctx, emit, "umount", "--", usbMount); err != nil {\n\t\t\treturn err\n\t\t}\n\t\tmountedUSB = false\n\t}\n''',
    "mandatory CA 2023 readback",
)
text = replace_once(
    text,
    '''func copyTree(ctx context.Context, sourceRoot, destinationRoot, excludedPath, excludedAnswerPath string, progress func(uint64)) error {\n\treturn copyTreeWithOptions(ctx, sourceRoot, destinationRoot, excludedPath, excludedAnswerPath, false, progress)\n}\n''',
    '''func copyTree(ctx context.Context, sourceRoot, destinationRoot, excludedPath, excludedAnswerPath string, progress func(uint64)) error {\n\treturn copyTreeWithPlan(ctx, sourceRoot, destinationRoot, excludedPath, excludedAnswerPath, false, nil, progress)\n}\n\nfunc copyTreeWithWindowsCA2023(ctx context.Context, sourceRoot, destinationRoot, excludedPath, excludedAnswerPath string, plan *WindowsCA2023Plan, progress func(uint64)) error {\n\treturn copyTreeWithPlan(ctx, sourceRoot, destinationRoot, excludedPath, excludedAnswerPath, false, plan, progress)\n}\n''',
    "copy tree CA 2023 wrapper",
)
text = replace_once(
    text,
    '''func copyTreeWithOptions(ctx context.Context, sourceRoot, destinationRoot, excludedPath, excludedAnswerPath string, untrustedSource bool, progress func(uint64)) error {\n\tvar rootHandle *os.File\n''',
    '''func copyTreeWithOptions(ctx context.Context, sourceRoot, destinationRoot, excludedPath, excludedAnswerPath string, untrustedSource bool, progress func(uint64)) error {\n\treturn copyTreeWithPlan(ctx, sourceRoot, destinationRoot, excludedPath, excludedAnswerPath, untrustedSource, nil, progress)\n}\n\nfunc copyTreeWithPlan(ctx context.Context, sourceRoot, destinationRoot, excludedPath, excludedAnswerPath string, untrustedSource bool, ca2023 *WindowsCA2023Plan, progress func(uint64)) error {\n\tvar rootHandle *os.File\n''',
    "copy tree plan-aware implementation",
)
text = replace_once(
    text,
    '''\t\tif relative == "." {\n\t\t\treturn nil\n\t\t}\n\t\tdestination := filepath.Join(destinationRoot, relative)\n''',
    '''\t\tif relative == "." {\n\t\t\treturn nil\n\t\t}\n\t\tif ca2023 != nil && ca2023.Replaces(relative) {\n\t\t\treturn nil\n\t\t}\n\t\tdestination := filepath.Join(destinationRoot, relative)\n''',
    "copy tree exact CA 2023 skip",
)
text = replace_once(
    text,
    '''func verifyTree(ctx context.Context, sourceRoot, destinationRoot string, plan mediaPlan, emit EventFunc) error {\n\ttotal := plan.CopyBytes - plan.DriverBytes\n''',
    '''func verifyTree(ctx context.Context, sourceRoot, destinationRoot string, plan mediaPlan, emit EventFunc) error {\n\ttotal := plan.CopyBytes - plan.DriverBytes\n\tif plan.CA2023 != nil {\n\t\ttotal -= plan.CA2023.ReplacementBytes\n\t}\n''',
    "base verification total",
)
text = replace_once(
    text,
    '''\t\trelative, err := filepath.Rel(sourceRoot, path)\n\t\tif err != nil {\n\t\t\treturn err\n\t\t}\n\t\tdestination := filepath.Join(destinationRoot, relative)\n''',
    '''\t\trelative, err := filepath.Rel(sourceRoot, path)\n\t\tif err != nil {\n\t\t\treturn err\n\t\t}\n\t\tif plan.CA2023 != nil && plan.CA2023.Replaces(relative) {\n\t\t\treturn nil\n\t\t}\n\t\tdestination := filepath.Join(destinationRoot, relative)\n''',
    "base verification exact CA 2023 skip",
)
text = replace_once(
    text,
    '''\tif len(plan.AnswerFile) > 0 {\n\t\tif plan.ExistingAnswerSize > otherBytes {\n''',
    '''\tif plan.CA2023 != nil {\n\t\tif plan.CA2023.OriginalBytes > otherBytes {\n\t\t\treturn errors.New("Windows CA 2023 original replacement total exceeds the inspected media total")\n\t\t}\n\t\totherBytes -= plan.CA2023.OriginalBytes\n\t\tvar err error\n\t\totherBytes, err = checkedAdd("Windows CA 2023 replacement total", otherBytes, plan.CA2023.ReplacementBytes)\n\t\tif err != nil {\n\t\t\treturn err\n\t\t}\n\t}\n\tif len(plan.AnswerFile) > 0 {\n\t\tif plan.ExistingAnswerSize > otherBytes {\n''',
    "CA 2023 capacity accounting",
)
write(str(path), text)


# CLI/helper binding and evidence propagation.
path = Path("cmd/rufus-linux/main.go")
text = path.read_text(encoding="utf-8")
text = replace_once(
    text,
    '''\twinApplySkuSiPolicy := fs.Bool("win-apply-sku-si-policy", false, "apply the installed Windows SkuSiPolicy to its EFI System Partition on first logon")\n\twinDisableBitLocker := fs.Bool("win-disable-bitlocker", false, "disable automatic Windows device encryption provisioning")\n''',
    '''\twinApplySkuSiPolicy := fs.Bool("win-apply-sku-si-policy", false, "apply the installed Windows SkuSiPolicy to its EFI System Partition on first logon")\n\twinUseCA2023Bootloaders := fs.Bool("win-use-ca-2023-bootloaders", false, "replace qualified FAT32 removable-media boot files with the Windows UEFI CA 2023-signed set from boot.wim")\n\twinDisableBitLocker := fs.Bool("win-disable-bitlocker", false, "disable automatic Windows device encryption provisioning")\n''',
    "CLI CA 2023 flag",
)
text = replace_once(
    text,
    '''\tif selectedMode != "windows" && (winOptions.Enabled() || scheme != "auto" || targetSystemChoice != "auto" || filesystemChoice != "auto" || clusterSize != 0 || *driverFolder != "" || *dbxFile != "" || *fullFormat || *badBlockCheck) {\n''',
    '''\tif selectedMode != "windows" && (winOptions.Enabled() || *winUseCA2023Bootloaders || scheme != "auto" || targetSystemChoice != "auto" || filesystemChoice != "auto" || clusterSize != 0 || *driverFolder != "" || *dbxFile != "" || *fullFormat || *badBlockCheck) {\n''',
    "non-Windows CA 2023 refusal",
)
text = replace_once(
    text,
    '''\tout.event(jsonEvent{Event: "preflight", Stage: "preflight", Message: fmt.Sprintf("Image: %s%s; target: %s (%s)", filepath.Base(originalImagePath), containerNote, resolved, humanBytes(dev.Size))})\n\tmounts := device.MountedDescendants(dev)\n''',
    '''\tout.event(jsonEvent{Event: "preflight", Stage: "preflight", Message: fmt.Sprintf("Image: %s%s; target: %s (%s)", filepath.Base(originalImagePath), containerNote, resolved, humanBytes(dev.Size))})\n\tif *winUseCA2023Bootloaders {\n\t\tout.event(jsonEvent{Event: "preflight", Stage: "windows_ca_2023", Message: "Windows UEFI CA 2023 bootloader replacement was requested. The privileged writer will accept only Windows 11 client, UEFI, FAT32 media with a complete CA 2023-signed _EX set, and the completed USB will require firmware that trusts Windows UEFI CA 2023."})\n\t}\n\tmounts := device.MountedDescendants(dev)\n''',
    "CA 2023 confirmation warning",
)
text = replace_once(
    text,
    '''\t\t\tBadBlockCheck:     *badBlockCheck,\n\t\t\tCustomizations:    winOptions,\n''',
    '''\t\t\tBadBlockCheck:                 *badBlockCheck,\n\t\t\tUseWindowsCA2023Bootloaders:    *winUseCA2023Bootloaders,\n\t\t\tCustomizations:                winOptions,\n''',
    "writer CA 2023 option binding",
)
text = replace_once(
    text,
    '''\t\t\tout.event(jsonEvent{Event: eventName, Stage: ev.Stage, Message: ev.Message, Done: ev.Done, Total: ev.Total})\n''',
    '''\t\t\tout.event(jsonEvent{Event: eventName, Stage: ev.Stage, Message: ev.Message, Done: ev.Done, Total: ev.Total, Hash: ev.Hash})\n''',
    "writer event hash propagation",
)
write(str(path), text)


# Focused policy/copy/capacity regression tests.
write("internal/windowsconfig/ca2023_capabilities_test.go", r'''package windowsconfig

import "testing"

func TestWindowsCA2023CapabilityRequiresQualifiedWindows11ClientAssets(t *testing.T) {
	metadata := MediaMetadata{
		ProductName:          "Windows 11 Pro",
		Version:              "10.0.26100",
		Architecture:         "arm64",
		InstallationType:     "Client",
		WindowsCA2023Available: true,
		WindowsCA2023ImageIndex: 2,
	}
	profile := Capabilities(metadata)
	if !profile.UseWindowsCA2023Bootloaders.Enabled {
		t.Fatalf("expected CA 2023 capability, got reason %q", profile.UseWindowsCA2023Bootloaders.Reason)
	}

	metadata.WindowsCA2023Available = false
	metadata.WindowsCA2023UnavailableWhy = "boot.wim _EX set is incomplete"
	profile = Capabilities(metadata)
	if profile.UseWindowsCA2023Bootloaders.Enabled || profile.UseWindowsCA2023Bootloaders.Reason != metadata.WindowsCA2023UnavailableWhy {
		t.Fatalf("expected media-specific refusal, got %+v", profile.UseWindowsCA2023Bootloaders)
	}

	metadata.ProductName = "Windows Server 2025"
	metadata.InstallationType = "Server"
	metadata.WindowsCA2023Available = true
	profile = Capabilities(metadata)
	if profile.UseWindowsCA2023Bootloaders.Enabled {
		t.Fatal("server media must not expose the Windows 11 client CA 2023 option")
	}
}
''')

write("internal/windowsmedia/ca2023_integration_test.go", r'''//go:build linux

package windowsmedia

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geocausa/RufusArm64/internal/windowsconfig"
)

func qualifiedCA2023Metadata() windowsconfig.MediaMetadata {
	return windowsconfig.MediaMetadata{
		ProductName:      "Windows 11 Pro",
		Version:          "10.0.26100",
		Architecture:     "arm64",
		InstallationType: "Client",
	}
}

func TestValidateWindowsCA2023Selection(t *testing.T) {
	capability := WindowsCA2023Capability{Available: true, ImageIndex: 2}
	if err := validateWindowsCA2023Selection(qualifiedCA2023Metadata(), capability, "uefi", "fat32"); err != nil {
		t.Fatalf("qualified selection rejected: %v", err)
	}
	if err := validateWindowsCA2023Selection(qualifiedCA2023Metadata(), capability, "bios", "fat32"); err == nil || !strings.Contains(err.Error(), "UEFI") {
		t.Fatalf("expected BIOS refusal, got %v", err)
	}
	if err := validateWindowsCA2023Selection(qualifiedCA2023Metadata(), capability, "uefi", "ntfs"); err == nil || !strings.Contains(err.Error(), "UEFI:NTFS") {
		t.Fatalf("expected NTFS trust-chain refusal, got %v", err)
	}
	server := qualifiedCA2023Metadata()
	server.ProductName = "Windows Server 2025"
	server.InstallationType = "Server"
	if err := validateWindowsCA2023Selection(server, capability, "uefi", "fat32"); err == nil {
		t.Fatal("server media unexpectedly accepted")
	}
}

func TestFinalizePlanAccountsForCA2023ReplacementDelta(t *testing.T) {
	plan := mediaPlan{
		OtherBytes:  1000,
		InstallSize: 2000,
		Filesystem:  "fat32",
		CA2023: &WindowsCA2023Plan{
			OriginalBytes:    100,
			ReplacementBytes: 160,
		},
	}
	if err := finalizePlan(&plan); err != nil {
		t.Fatal(err)
	}
	if plan.CopyBytes != 3060 {
		t.Fatalf("copy bytes=%d, want 3060", plan.CopyBytes)
	}
}

func TestCopyTreeSkipsOnlyExactCA2023Destinations(t *testing.T) {
	source := t.TempDir()
	destination := t.TempDir()
	fallback := filepath.Join(source, "EFI", "BOOT", "BOOTAA64.EFI")
	normal := filepath.Join(source, "EFI", "Microsoft", "Boot", "BCD")
	for path, data := range map[string][]byte{fallback: []byte("old"), normal: []byte("keep")} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	plan := &WindowsCA2023Plan{replacements: map[string]struct{}{
		strings.ToLower(filepath.ToSlash(filepath.Join("EFI", "BOOT", "BOOTAA64.EFI"))): {},
	}}
	if err := copyTreeWithWindowsCA2023(context.Background(), source, destination, "", "", plan, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(destination, "EFI", "BOOT", "BOOTAA64.EFI")); !os.IsNotExist(err) {
		t.Fatalf("replaced fallback should be excluded, stat err=%v", err)
	}
	if data, err := os.ReadFile(filepath.Join(destination, "EFI", "Microsoft", "Boot", "BCD")); err != nil || string(data) != "keep" {
		t.Fatalf("ordinary file was not copied: data=%q err=%v", data, err)
	}
}

func TestApplyWindowsCA2023RejectsChangedStaging(t *testing.T) {
	root := t.TempDir()
	staged := filepath.Join(t.TempDir(), "bootmgfw_EX.efi")
	if err := os.WriteFile(staged, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest, err := fileSHA256(staged)
	if err != nil {
		t.Fatal(err)
	}
	plan := &WindowsCA2023Plan{Assets: []WindowsCA2023Asset{{
		Destination: filepath.ToSlash(filepath.Join("EFI", "BOOT", "BOOTAA64.EFI")),
		Size:        5,
		SHA256:      fmtDigest(digest),
		sourcePath:  staged,
	}}}
	if err := os.WriteFile(staged, []byte("later"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := applyWindowsCA2023(context.Background(), root, plan, nil); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("expected changed staging refusal, got %v", err)
	}
}

func fmtDigest(value [32]byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 64)
	for i, b := range value {
		out[i*2] = digits[b>>4]
		out[i*2+1] = digits[b&15]
	}
	return string(out)
}
''')
