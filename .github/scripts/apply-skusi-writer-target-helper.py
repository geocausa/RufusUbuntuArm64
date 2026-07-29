#!/usr/bin/env python3
from pathlib import Path

path = Path("internal/windowsmedia/windowsmedia.go")
text = path.read_text(encoding="utf-8")
old = '''\tcustomizations := opts.Customizations
\tif customizations.ApplySkuSiPolicy && targetSystem != "uefi" {
\t\treturn errors.New("SkuSiPolicy deployment requires a resolved UEFI Windows target; BIOS/CSM media has no EFI System Partition")
\t}
\tcustomizations.LoadDrivers = plan.DriverFolder != ""
'''
new = '''\tcustomizations := opts.Customizations
\tif err := validateCustomizationTargetSystem(customizations, targetSystem); err != nil {
\t\treturn err
\t}
\tcustomizations.LoadDrivers = plan.DriverFolder != ""
'''
if old in text:
    text = text.replace(old, new, 1)
elif new not in text:
    raise SystemExit("SkuSiPolicy writer target block not found")
path.write_text(text, encoding="utf-8")
