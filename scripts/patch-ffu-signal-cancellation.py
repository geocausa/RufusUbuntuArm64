#!/usr/bin/env python3
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if text.count(old) != 1:
        raise SystemExit(f"{label} anchor count is {text.count(old)}, expected 1")
    return text.replace(old, new, 1)


ffu = Path("cmd/rufus-linux/ffu_linux.go")
text = ffu.read_text()
text = replace_once(
    text,
    '''\t"os"\n\t"strings"\n\t"time"\n''',
    '''\t"os"\n\t"os/signal"\n\t"strings"\n\t"syscall"\n\t"time"\n''',
    "FFU import",
)
text = replace_once(
    text,
    '''var (\n\tffuCLIGeteuid = os.Geteuid\n\tffuCLINow     = time.Now\n)\n\n''',
    '''var (\n\tffuCLIGeteuid = os.Geteuid\n\tffuCLINow     = time.Now\n\tffuCLIContext = func() (context.Context, context.CancelFunc) {\n\t\treturn signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)\n\t}\n)\n\nfunc newFFUCLIContext() (context.Context, context.CancelFunc, error) {\n\tctx, stop := ffuCLIContext()\n\tif ctx == nil || stop == nil {\n\t\tif stop != nil {\n\t\t\tstop()\n\t\t}\n\t\treturn nil, nil, errors.New("FFU signal context factory returned an invalid context")\n\t}\n\treturn ctx, stop, nil\n}\n\n''',
    "FFU context factory",
)
text = replace_once(
    text,
    '''\tprepared, err := prepareFFUCLIReview(context.Background(), options)\n\tif err != nil {\n\t\treturn err\n\t}\n''',
    '''\tctx, stop, err := newFFUCLIContext()\n\tif err != nil {\n\t\treturn err\n\t}\n\tdefer stop()\n\tprepared, err := prepareFFUCLIReview(ctx, options)\n\tif err != nil {\n\t\treturn err\n\t}\n''',
    "review signal context",
)
text = replace_once(
    text,
    '''\tif ffuCLIGeteuid() != 0 {\n\t\treturn errors.New("FFU restore requires administrator privileges")\n\t}\n\tprepared, err := prepareFFUCLIReview(context.Background(), options)\n\tif err != nil {\n\t\treturn err\n\t}\n''',
    '''\tif ffuCLIGeteuid() != 0 {\n\t\treturn errors.New("FFU restore requires administrator privileges")\n\t}\n\tctx, stop, err := newFFUCLIContext()\n\tif err != nil {\n\t\treturn err\n\t}\n\tdefer stop()\n\tprepared, err := prepareFFUCLIReview(ctx, options)\n\tif err != nil {\n\t\treturn err\n\t}\n''',
    "restore signal context",
)
text = replace_once(
    text,
    '''\tctx := context.Background()\n\tsourceLease, err := ffu.AcquireAuthenticatedFullFlashSourceLease(\n''',
    '''\tsourceLease, err := ffu.AcquireAuthenticatedFullFlashSourceLease(\n''',
    "remove restore background context",
)
text = replace_once(
    text,
    '''func prepareFFUCLIReview(ctx context.Context, options ffuCLIOptions) (preparedFFUCLIReview, error) {\n\tmetadataPolicy, err := readStrictFFUCLIJSON[ffu.TrustMetadataPolicy](options.trustMetadataPolicy)\n''',
    '''func prepareFFUCLIReview(ctx context.Context, options ffuCLIOptions) (preparedFFUCLIReview, error) {\n\tif ctx == nil {\n\t\treturn preparedFFUCLIReview{}, errors.New("FFU CLI context is nil")\n\t}\n\tif err := ctx.Err(); err != nil {\n\t\treturn preparedFFUCLIReview{}, err\n\t}\n\tmetadataPolicy, err := readStrictFFUCLIJSON[ffu.TrustMetadataPolicy](options.trustMetadataPolicy)\n''',
    "review pre-input cancellation",
)
ffu.write_text(text)


tests = Path("cmd/rufus-linux/ffu_linux_test.go")
text = tests.read_text()
text = replace_once(
    text,
    '''import (\n\t"os"\n''',
    '''import (\n\t"context"\n\t"errors"\n\t"os"\n''',
    "test imports",
)
text = replace_once(
    text,
    '''func TestFFURestoreRequiresRootBeforeOpeningInputs(t *testing.T) {\n\tprevious := ffuCLIGeteuid\n\tffuCLIGeteuid = func() int { return 1000 }\n\tdefer func() { ffuCLIGeteuid = previous }()\n\targs := append(validFFUCLIArgumentFixture(t), "--confirm", "exact phrase")\n\tif err := runFFURestore(args); err == nil || err.Error() != "FFU restore requires administrator privileges" {\n\t\tt.Fatalf("non-root restore error = %v", err)\n\t}\n}\n\n''',
    '''func TestFFURestoreRequiresRootBeforeOpeningInputs(t *testing.T) {\n\tpreviousUID := ffuCLIGeteuid\n\tpreviousContext := ffuCLIContext\n\tffuCLIGeteuid = func() int { return 1000 }\n\tffuCLIContext = func() (context.Context, context.CancelFunc) {\n\t\tt.Fatal("signal context was created before the root gate")\n\t\treturn nil, nil\n\t}\n\tdefer func() {\n\t\tffuCLIGeteuid = previousUID\n\t\tffuCLIContext = previousContext\n\t}()\n\targs := append(validFFUCLIArgumentFixture(t), "--confirm", "exact phrase")\n\tif err := runFFURestore(args); err == nil || err.Error() != "FFU restore requires administrator privileges" {\n\t\tt.Fatalf("non-root restore error = %v", err)\n\t}\n}\n\nfunc TestFFUReviewHonorsCancellationBeforeOpeningInputs(t *testing.T) {\n\tprevious := ffuCLIContext\n\tffuCLIContext = cancelledFFUCLIContext\n\tdefer func() { ffuCLIContext = previous }()\n\tif err := runFFUReview(validFFUCLIArgumentFixture(t)); !errors.Is(err, context.Canceled) {\n\t\tt.Fatalf("pre-input review cancellation error = %v", err)\n\t}\n}\n\nfunc TestFFURestoreHonorsCancellationBeforeOpeningInputs(t *testing.T) {\n\tpreviousUID := ffuCLIGeteuid\n\tpreviousContext := ffuCLIContext\n\tffuCLIGeteuid = func() int { return 0 }\n\tffuCLIContext = cancelledFFUCLIContext\n\tdefer func() {\n\t\tffuCLIGeteuid = previousUID\n\t\tffuCLIContext = previousContext\n\t}()\n\targs := append(validFFUCLIArgumentFixture(t), "--confirm", "exact phrase")\n\tif err := runFFURestore(args); !errors.Is(err, context.Canceled) {\n\t\tt.Fatalf("pre-input restore cancellation error = %v", err)\n\t}\n}\n\nfunc TestNewFFUCLIContextRejectsInvalidFactoryResult(t *testing.T) {\n\tprevious := ffuCLIContext\n\tffuCLIContext = func() (context.Context, context.CancelFunc) { return nil, nil }\n\tdefer func() { ffuCLIContext = previous }()\n\tif _, _, err := newFFUCLIContext(); err == nil || !strings.Contains(err.Error(), "invalid context") {\n\t\tt.Fatalf("invalid signal context error = %v", err)\n\t}\n}\n\nfunc cancelledFFUCLIContext() (context.Context, context.CancelFunc) {\n\tctx, cancel := context.WithCancel(context.Background())\n\tcancel()\n\treturn ctx, cancel\n}\n\n''',
    "cancellation tests",
)
text = replace_once(
    text,
    '''\t\t"sourcefile.Verify",\n''',
    '''\t\t"sourcefile.Verify",\n\t\t"signal.NotifyContext",\n\t\t"os.Interrupt",\n\t\t"syscall.SIGTERM",\n\t\t"ctx.Err()",\n''',
    "cancellation source contract",
)
tests.write_text(text)


doc = Path("docs/ffu-experimental-cli-provider.md")
text = doc.read_text()
text = replace_once(
    text,
    '''## Output and failure state\n''',
    '''## Signal cancellation\n\nBoth review and restore install one signal-aware context for `SIGINT` and\n`SIGTERM`. Cancellation is checked before policy or image inputs are opened and\nis carried through authentication, source leasing, target acquisition,\nconfirmation, authorization, writing, synchronization, and readback.\n\nA signal observed before the first target write returns without modifying the\ntarget. A signal observed after mutation begins returns the executor's structured\npartial-modification evidence; the command never reports an interrupted target as\nverified.\n\n## Output and failure state\n''',
    "signal cancellation documentation",
)
doc.write_text(text)
