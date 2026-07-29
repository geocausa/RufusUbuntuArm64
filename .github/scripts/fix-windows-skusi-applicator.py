#!/usr/bin/env python3
from pathlib import Path

path = Path('.github/scripts/apply-windows-skusi-policy.py')
text = path.read_text(encoding='utf-8')
replacements = {
    'flags.Bool("win-quality-of-life", false, "apply Rufus 4.15 Quality of Life Windows policy")':
        'fs.Bool("win-quality-of-life", false, "remove bundled OneDrive setup, Outlook and Teams and apply Rufus Quality of Life policies")',
    'flags.Bool("win-apply-sku-si-policy", false, "apply the installed Windows SkuSiPolicy to its EFI System Partition on first logon")':
        'fs.Bool("win-apply-sku-si-policy", false, "apply the installed Windows SkuSiPolicy to its EFI System Partition on first logon")',
    'flags.Bool("win-disable-bitlocker", false, "disable automatic Windows device encryption")':
        'fs.Bool("win-disable-bitlocker", false, "disable automatic Windows device encryption provisioning")',
}
for old, new in replacements.items():
    if old not in text:
        raise SystemExit(f'applicator expression not found: {old}')
    text = text.replace(old, new)
path.write_text(text, encoding='utf-8')
