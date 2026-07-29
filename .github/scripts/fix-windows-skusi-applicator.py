#!/usr/bin/env python3
from pathlib import Path

path = Path('.github/scripts/apply-windows-skusi-policy.py')
text = path.read_text(encoding='utf-8')
old = '''\twinQualityOfLife := flags.Bool("win-quality-of-life", false, "apply Rufus 4.15 Quality of Life Windows policy")
\twinDisableBitLocker := flags.Bool("win-disable-bitlocker", false, "disable automatic Windows device encryption")
'''
new = '''\twinQualityOfLife := fs.Bool("win-quality-of-life", false, "remove bundled OneDrive setup, Outlook and Teams and apply Rufus Quality of Life policies")
\twinDisableBitLocker := fs.Bool("win-disable-bitlocker", false, "disable automatic Windows device encryption provisioning")
'''
replacement = '''\twinQualityOfLife := fs.Bool("win-quality-of-life", false, "remove bundled OneDrive setup, Outlook and Teams and apply Rufus Quality of Life policies")
\twinApplySkuSiPolicy := fs.Bool("win-apply-sku-si-policy", false, "apply the installed Windows SkuSiPolicy to its EFI System Partition on first logon")
\twinDisableBitLocker := fs.Bool("win-disable-bitlocker", false, "disable automatic Windows device encryption provisioning")
'''
if old not in text:
    raise SystemExit('old applicator CLI block not found')
text = text.replace(old, new, 1)
# Replace the applicator's intended replacement block as well.
old_replacement = '''\twinQualityOfLife := flags.Bool("win-quality-of-life", false, "apply Rufus 4.15 Quality of Life Windows policy")
\twinApplySkuSiPolicy := flags.Bool("win-apply-sku-si-policy", false, "apply the installed Windows SkuSiPolicy to its EFI System Partition on first logon")
\twinDisableBitLocker := flags.Bool("win-disable-bitlocker", false, "disable automatic Windows device encryption")
'''
if old_replacement not in text:
    raise SystemExit('old applicator CLI replacement block not found')
text = text.replace(old_replacement, replacement, 1)
path.write_text(text, encoding='utf-8')
