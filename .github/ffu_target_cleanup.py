from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if old not in text:
        raise SystemExit(f"{label} not found")
    return text.replace(old, new, 1)


test_path = Path("internal/ffu/restore_target_plan_linux_test.go")
test = test_path.read_text()
test = replace_once(test, '"errors"\n\t"strings"', '"errors"\n\t"strconv"\n\t"strings"', "test imports")
test = replace_once(
    test,
    '"RESTORE AUTHENTICATED FFU TO /dev/test-ffu SIZE "+uint64Text(request.TargetSizeBytes)+" BYTES"',
    '"RESTORE AUTHENTICATED FFU TO /dev/test-ffu SIZE "+strconv.FormatUint(request.TargetSizeBytes, 10)+" BYTES"',
    "confirmation phrase assertion",
)
marker = "\nfunc uint64Text("
if marker in test:
    test = test.split(marker, 1)[0] + "\n"
test_path.write_text(test)

source_path = Path("internal/ffu/restore_target_plan_linux.go")
source = source_path.read_text()
source = replace_once(
    source,
    '''\t\tLimitations: []string{
\t\t\t"the plan is bound to caller-discovered target facts but opens no device",
\t\t\t"a privileged provider must independently rediscover and revalidate identity, size, sector geometry, source evidence, and the complete plan",
\t\t\t"target-side validation descriptor semantics, cancellation, write ordering, flush, readback, and changed-media reporting remain unresolved",
\t\t\t"software planning and verification cannot prove physical bootability or whole-device health",
\t\t},''',
    '''\t\tLimitations:                     restoreTargetLimitations(),''',
    "target-plan limitations block",
)
source = replace_once(
    source,
    '''\tfor _, write := range descriptor.WriteDescriptors {
\t\tif write.BlockCount == 0 || write.PayloadLength == 0 || write.PayloadLength != uint64(write.BlockCount)*descriptor.BlockSizeBytes {
\t\t\treturn nil, 0, fmt.Errorf("FFU write descriptor %d has inconsistent payload geometry", write.Index)
\t\t}''',
    '''\tfor _, write := range descriptor.WriteDescriptors {
\t\texpectedPayloadLength, err := checkedMul(uint64(write.BlockCount), descriptor.BlockSizeBytes)
\t\tif err != nil || write.BlockCount == 0 || write.PayloadLength == 0 || write.PayloadLength != expectedPayloadLength {
\t\t\treturn nil, 0, fmt.Errorf("FFU write descriptor %d has inconsistent payload geometry", write.Index)
\t\t}''',
    "write payload geometry block",
)
source = replace_once(
    source,
    '''\t\tif extent.Anchor != "begin" && extent.Anchor != "end" || extent.TargetStartBlock >= extent.TargetEndBlock || extent.TargetEndBlock > plan.TargetBlockCount || extent.TargetOffset != extent.TargetStartBlock*plan.StoreBlockSizeBytes || extent.TargetLength != (extent.TargetEndBlock-extent.TargetStartBlock)*plan.StoreBlockSizeBytes || extent.PayloadLength != extent.TargetLength {
\t\t\treturn fmt.Errorf("FFU restore target-plan extent %d is inconsistent", index)
\t\t}
\t\tif index != 0 && extent.TargetStartBlock < plan.ResolvedWriteExtents[index-1].TargetEndBlock {
\t\t\treturn errors.New("FFU restore target-plan contains overlapping extents")
\t\t}
\t\tvar err error
\t\tmutationBytes, err = checkedAdd(mutationBytes, extent.TargetLength)''',
    '''\t\texpectedOffset, offsetErr := checkedMul(extent.TargetStartBlock, plan.StoreBlockSizeBytes)
\t\texpectedLength, lengthErr := checkedMul(extent.TargetEndBlock-extent.TargetStartBlock, plan.StoreBlockSizeBytes)
\t\tpayloadEnd, payloadErr := checkedAdd(extent.PayloadOffset, extent.PayloadLength)
\t\tif (extent.Anchor != "begin" && extent.Anchor != "end") || extent.TargetStartBlock >= extent.TargetEndBlock || extent.TargetEndBlock > plan.TargetBlockCount || offsetErr != nil || lengthErr != nil || payloadErr != nil || extent.TargetOffset != expectedOffset || extent.TargetLength != expectedLength || extent.PayloadLength != extent.TargetLength || payloadEnd > plan.SourceFileSize {
\t\t\treturn fmt.Errorf("FFU restore target-plan extent %d is inconsistent", index)
\t\t}
\t\tif index != 0 && extent.TargetStartBlock < plan.ResolvedWriteExtents[index-1].TargetEndBlock {
\t\t\treturn errors.New("FFU restore target-plan contains overlapping extents")
\t\t}
\t\tvar err error
\t\tmutationBytes, err = checkedAdd(mutationBytes, extent.TargetLength)''',
    "extent validation block",
)
source = replace_once(
    source,
    '''\tif mutationBytes != plan.MutationBytes || plan.PlanSHA256 != restoreTargetPlanDigest(plan) || !equalRestoreStrings(plan.Warnings, restoreTargetWarnings()) {
\t\treturn errors.New("FFU restore target-plan evidence or warnings were altered")
\t}''',
    '''\tif mutationBytes != plan.MutationBytes || mutationBytes > plan.TargetSizeBytes || plan.PlanSHA256 != restoreTargetPlanDigest(plan) || !equalRestoreStrings(plan.Warnings, restoreTargetWarnings()) || !equalRestoreStrings(plan.Limitations, restoreTargetLimitations()) {
\t\treturn errors.New("FFU restore target-plan evidence, warnings, or limitations were altered")
\t}''',
    "plan evidence validation block",
)
warning_helper = '''func restoreTargetWarnings() []string {
\treturn []string{
\t\t"Restoring an FFU is destructive and can overwrite partition tables and data on the complete selected target.",
\t\t"The exact target identity, capacity, and sector geometry must be rediscovered and match immediately before any future write.",
\t\t"FFU validation descriptors are not yet resolved or executed, so this plan cannot authorize restoration.",
\t\t"Software authentication and restoration cannot prove that the resulting device will boot or that the complete device is healthy.",
\t}
}
'''
source = replace_once(
    source,
    warning_helper,
    warning_helper
    + '''
func restoreTargetLimitations() []string {
\treturn []string{
\t\t"the plan is bound to caller-discovered target facts but opens no device",
\t\t"a privileged provider must independently rediscover and revalidate identity, size, sector geometry, source evidence, and the complete plan",
\t\t"target-side validation descriptor semantics, cancellation, write ordering, flush, readback, and changed-media reporting remain unresolved",
\t\t"software planning and verification cannot prove physical bootability or whole-device health",
\t}
}
''',
    "warning helper",
)
source_path.write_text(source)
