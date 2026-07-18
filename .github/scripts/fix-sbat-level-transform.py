from pathlib import Path

path = Path('.github/scripts/apply-sbat-level.py')
source = path.read_text()
old_prefix = "    '''\\tfmt.Printf(\"Root: %s\\nFallback:"
new_prefix = "    r'''\\tfmt.Printf(\"Root: %s\\nFallback:"
if source.count(old_prefix) != 2:
    raise SystemExit(f'expected two Root fmt replacement strings, found {source.count(old_prefix)}')
source = source.replace(old_prefix, new_prefix, 2)
old_revocations = "    '''\\t\\tfor _, revocation := range file.SBATRevocations {"
new_revocations = "    r'''\\t\\tfor _, revocation := range file.SBATRevocations {"
if source.count(old_revocations) != 1:
    raise SystemExit(f'expected one SBAT revocation replacement string, found {source.count(old_revocations)}')
source = source.replace(old_revocations, new_revocations, 1)
path.write_text(source)
