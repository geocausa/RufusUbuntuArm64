from pathlib import Path

source_path = Path("internal/ffu/restore_source_lease_linux.go")
source = source_path.read_text()
source = source.replace('"os"\n\t"sync"', '"os"\n\t"path/filepath"\n\t"strings"\n\t"sync"')
source = source.replace('''\tif uint64(expectedSource.Size) != expectedPreflight.SourceFileSize {
\t\treturn nil, errors.New("FFU source identity size differs from target-preflight evidence")
\t}
''', '')
source = source.replace('sourcefile.VerifyPinned', 'sourcefile.Verify')
old = '''\tif _, err := validateRestoreTargetRequest(RestoreTargetRequest{
\t\tDevicePath:             evidence.TargetDevicePath,
\t\tExpectedTargetIdentity: evidence.ExpectedTargetIdentity,
\t\tTargetSizeBytes:        evidence.TargetSizeBytes,
\t\tLogicalSectorSizeBytes: 512,
\t\tPhysicalSectorSizeBytes: 512,
\t}); err != nil {
\t\t// Only path, identity, and non-zero target size are relevant here. The live
\t\t// sector geometry remains bound by the preflight digest rather than copied.
\t\tif evidence.TargetDevicePath == "" || evidence.ExpectedTargetIdentity == "" || evidence.TargetSizeBytes == 0 {
\t\t\treturn err
\t\t}
\t}
'''
new = '''\tpath := strings.TrimSpace(evidence.TargetDevicePath)
\tif path == "" || path != evidence.TargetDevicePath || !filepath.IsAbs(path) || !strings.HasPrefix(path, "/dev/") || filepath.Clean(path) != path {
\t\treturn errors.New("FFU source-lease evidence contains an invalid target path")
\t}
'''
if old not in source:
    raise SystemExit("source-lease target validation block not found")
source_path.write_text(source.replace(old, new))

contract_path = Path("internal/ffu/restore_source_lease_policy_contract_test.go")
contract = contract_path.read_text()
contract_path.write_text(contract.replace('"caller-owned source descriptor",', '"caller-owned FFU descriptor",'))
