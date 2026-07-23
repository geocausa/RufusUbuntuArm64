#!/usr/bin/env python3
from pathlib import Path

path = Path("internal/imaging/imaging.go")
text = path.read_text(encoding="utf-8")

def replace_once(old: str, new: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected one replacement, found {count}: {old[:80]!r}")
    text = text.replace(old, new, 1)

replace_once(
'''\tif opts.ClearStaleSignatures {
\t\ttargetChanged = true
\t\tif opts.TargetSize == 0 {
\t\t\treturn writeResult, errors.New("target size is required when clearing stale signatures")
\t\t}
\t\tif err := clearTargetEdges(ctx, dst, opts.TargetSize); err != nil {
\t\t\treturn writeResult, fmt.Errorf("clear stale target signatures: %w", err)
\t\t}
\t}
''',
'''\tif opts.ClearStaleSignatures {
\t\tif opts.TargetSize == 0 {
\t\t\treturn writeResult, errors.New("target size is required when clearing stale signatures")
\t\t}
\t\tif err := clearTargetEdges(ctx, dst, opts.TargetSize, func() { targetChanged = true }); err != nil {
\t\t\treturn writeResult, fmt.Errorf("clear stale target signatures: %w", err)
\t\t}
\t}
''')
replace_once(
'''func clearTargetEdges(ctx context.Context, target *os.File, targetSize uint64) error {''',
'''func clearTargetEdges(ctx context.Context, target *os.File, targetSize uint64, onMutation func()) error {''')
replace_once(
'''\t\tif err := writeZerosAt(ctx, target, 0, targetSize); err != nil {''',
'''\t\tif err := writeZerosAt(ctx, target, 0, targetSize, onMutation); err != nil {''')
replace_once(
'''\tif err := writeZerosAt(ctx, target, 0, clearSize); err != nil {''',
'''\tif err := writeZerosAt(ctx, target, 0, clearSize, onMutation); err != nil {''')
replace_once(
'''\tif err := writeZerosAt(ctx, target, targetSize-clearSize, clearSize); err != nil {''',
'''\tif err := writeZerosAt(ctx, target, targetSize-clearSize, clearSize, onMutation); err != nil {''')
replace_once(
'''func writeZerosAt(ctx context.Context, target *os.File, offset, length uint64) error {''',
'''func writeZerosAt(ctx context.Context, target *os.File, offset, length uint64, onMutation func()) error {''')
replace_once(
'''\t\tn, err := target.WriteAt(zeroes[:int(chunk)], int64(offset+written))
\t\twritten += uint64(n)
\t\tif err != nil {''',
'''\t\tn, err := target.WriteAt(zeroes[:int(chunk)], int64(offset+written))
\t\tif n > 0 && onMutation != nil {
\t\t\tonMutation()
\t\t}
\t\twritten += uint64(n)
\t\tif err != nil {''')

path.write_text(text, encoding="utf-8")
