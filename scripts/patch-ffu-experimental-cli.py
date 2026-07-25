#!/usr/bin/env python3
from pathlib import Path

main = Path("cmd/rufus-linux/main.go")
text = main.read_text()
old = '''\tcase "qualify":\n\t\treturn runQualify(args[1:])\n\tcase "version", "--version", "-v":\n'''
new = '''\tcase "qualify":\n\t\treturn runQualify(args[1:])\n\tcase "ffu":\n\t\treturn runFFU(args[1:])\n\tcase "version", "--version", "-v":\n'''
if old not in text:
    raise SystemExit("main command switch anchor not found")
text = text.replace(old, new, 1)
old = '''  sudo rufusarm64-cli qualify verify --record FILE --output FILE [--state-dir DIR] [--json]\n'''
new = '''  sudo rufusarm64-cli qualify verify --record FILE --output FILE [--state-dir DIR] [--json]\n  rufusarm64-cli ffu review --experimental-ffu --image IMAGE.ffu --device /dev/sdX --expected-identity TOKEN --target-size BYTES --logical-sector-size BYTES --physical-sector-size BYTES --trust-store DIR --trust-metadata-policy FILE --publisher-policy FILE [--json]\n  sudo rufusarm64-cli ffu restore --experimental-ffu --image IMAGE.ffu --device /dev/sdX --expected-identity TOKEN --target-size BYTES --logical-sector-size BYTES --physical-sector-size BYTES --trust-store DIR --trust-metadata-policy FILE --publisher-policy FILE --confirm PHRASE [--json]\n'''
if old not in text:
    raise SystemExit("main usage anchor not found")
text = text.replace(old, new, 1)
main.write_text(text)

ffu = Path("cmd/rufus-linux/ffu_linux.go")
text = ffu.read_text()
old = '''\tEvaluationTime          string                           `json:"evaluation_time"`\n\tTrustActivationSHA256   string                           `json:"trust_activation_sha256"`\n\tSourceIdentity          sourcefile.Identity              `json:"source_identity"`\n'''
new = '''\tEvaluationTime          string                           `json:"evaluation_time"`\n\tTrustActivationSHA256   string                           `json:"trust_activation_sha256"`\n\tSourcePath              string                           `json:"source_path"`\n\tSourceIdentity          sourcefile.Identity              `json:"source_identity"`\n'''
if old not in text:
    raise SystemExit("FFU review source field anchor not found")
text = text.replace(old, new, 1)
old = '''\t\tEvaluationTime:          evaluationTime.Format(time.RFC3339),\n\t\tTrustActivationSHA256:   activation.ActivationSHA256,\n\t\tSourceIdentity:          identity,\n'''
new = '''\t\tEvaluationTime:          evaluationTime.Format(time.RFC3339),\n\t\tTrustActivationSHA256:   activation.ActivationSHA256,\n\t\tSourcePath:              resolved,\n\t\tSourceIdentity:          identity,\n'''
if old not in text:
    raise SystemExit("FFU review initializer anchor not found")
text = text.replace(old, new, 1)
old = 'fmt.Printf("FFU source: %s\\n", review.SourceIdentity.ResolvedPath)'
new = 'fmt.Printf("FFU source: %s\\n", review.SourcePath)'
if old not in text:
    raise SystemExit("FFU review output anchor not found")
text = text.replace(old, new, 1)
ffu.write_text(text)
