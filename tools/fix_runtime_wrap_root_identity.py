from pathlib import Path

path = Path("internal/runtimeintegrity/transaction_linux.go")
text = path.read_text(encoding="utf-8")

old_verify = '''func verifyFromOpenRoot(ctx context.Context, root *os.File, rootIdentity fileIdentity, maxFiles int) (VerificationResult, error) {
	scan, err := reopenDirectory(root)
'''
new_verify = '''func verifyFromOpenRoot(ctx context.Context, root *os.File, rootIdentity fileIdentity, maxFiles int) (VerificationResult, error) {
	currentRoot, err := identityFromOpenFile(root)
	if err != nil {
		return VerificationResult{}, err
	}
	if !sameKernelObject(rootIdentity, currentRoot) {
		return VerificationResult{}, errors.New("media root was substituted before verification")
	}
	rootIdentity = currentRoot
	scan, err := reopenDirectory(root)
'''
if text.count(old_verify) != 1:
    raise SystemExit(f"verify root refresh matched {text.count(old_verify)} times")
text = text.replace(old_verify, new_verify, 1)

old_final = '''	if !sameStableObject(expected, actual) {
		return errors.New("media root changed during the transaction")
	}
'''
new_final = '''	if !sameKernelObject(expected, actual) {
		return errors.New("media root was substituted during the transaction")
	}
'''
if text.count(old_final) != 1:
    raise SystemExit(f"final root identity check matched {text.count(old_final)} times")
text = text.replace(old_final, new_final, 1)
path.write_text(text, encoding="utf-8")
