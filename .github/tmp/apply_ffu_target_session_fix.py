from pathlib import Path

# The closed-source test must provide a complete injected operations table so
# the code reaches the source-capability check rather than correctly rejecting
# an incomplete test harness first.
test_path = Path("internal/ffu/restore_target_session_linux_test.go")
test = test_path.read_text()
old = '''\tif session, err := acquireExclusiveFullFlashTargetWithOps(context.Background(), sourceLease, fixture.preflight, fullFlashTargetOpenOps{}); err == nil || !strings.Contains(err.Error(), "closed") {
\t\tif session != nil {
\t\t\tsession.Close()
\t\t}
\t\tt.Fatalf("closed source error=%v", err)
\t}
\tvar nilContext context.Context
\tif session, err := acquireExclusiveFullFlashTargetWithOps(nilContext, sourceLease, fixture.preflight, fullFlashTargetOpenOps{}); err == nil || !strings.Contains(err.Error(), "context is nil") {
\t\tif session != nil {
\t\t\tsession.Close()
\t\t}
\t\tt.Fatalf("nil context error=%v", err)
\t}
\tctx, cancel := context.WithCancel(context.Background())
\tcancel()
\tif session, err := acquireExclusiveFullFlashTargetWithOps(ctx, sourceLease, fixture.preflight, fullFlashTargetOpenOps{}); !errors.Is(err, context.Canceled) {'''
new = '''\tops := completeTargetSessionTestOps()
\tif session, err := acquireExclusiveFullFlashTargetWithOps(context.Background(), sourceLease, fixture.preflight, ops); err == nil || !strings.Contains(err.Error(), "closed") {
\t\tif session != nil {
\t\t\tsession.Close()
\t\t}
\t\tt.Fatalf("closed source error=%v", err)
\t}
\tvar nilContext context.Context
\tif session, err := acquireExclusiveFullFlashTargetWithOps(nilContext, sourceLease, fixture.preflight, ops); err == nil || !strings.Contains(err.Error(), "context is nil") {
\t\tif session != nil {
\t\t\tsession.Close()
\t\t}
\t\tt.Fatalf("nil context error=%v", err)
\t}
\tctx, cancel := context.WithCancel(context.Background())
\tcancel()
\tif session, err := acquireExclusiveFullFlashTargetWithOps(ctx, sourceLease, fixture.preflight, ops); !errors.Is(err, context.Canceled) {'''
if old not in test:
    raise SystemExit("closed-source test block not found")
test = test.replace(old, new)
marker = '''func exclusiveTargetSessionTestDevice(preflight FullFlashTargetPreflightPlan) device.BlockDevice {'''
helper = '''func completeTargetSessionTestOps() fullFlashTargetOpenOps {
\treturn fullFlashTargetOpenOps{
\t\topenTarget: func(string) (*os.File, error) { return nil, errors.New("unexpected target open") },
\t\tverifyOpenTarget: func(*os.File, uint64, uint64) error { return nil },
\t\trevalidateTarget: func(string, uint64) (device.BlockDevice, uint64, error) {
\t\t\treturn device.BlockDevice{}, 0, nil
\t\t},
\t\treadSectorGeometry: func(string) (uint64, uint64, error) { return 512, 512, nil },
\t\tensureSourceOutside: func(*os.File, device.BlockDevice) error { return nil },
\t}
}

'''
if marker not in test:
    raise SystemExit("target-session helper insertion marker not found")
test_path.write_text(test.replace(marker, helper + marker))

# The source-contract phrase spans two comment lines. Match its two stable
# fragments rather than requiring a whitespace-normalized comment rendering.
contract_path = Path("internal/ffu/restore_target_session_policy_contract_test.go")
contract = contract_path.read_text()
old = '''\t\t"ExecutionSupported:             false",
\t\t"exposes no descriptor, read, write, seek, sync, or ioctl method",'''
new = '''\t\t"ExecutionSupported:             false",
\t\t"but exposes",
\t\t"no descriptor, read, write, seek, sync, or ioctl method",'''
if old not in contract:
    raise SystemExit("target-session source-contract phrase not found")
contract_path.write_text(contract.replace(old, new))
