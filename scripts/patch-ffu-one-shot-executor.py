#!/usr/bin/env python3
from pathlib import Path

path = Path("internal/ffu/restore_mutation_authorization_linux.go")
text = path.read_text()
old = """type FullFlashMutationAuthorization struct {\n\tmu           sync.Mutex\n\tconfirmation *FullFlashDestructiveConfirmation\n\twriteOrder   FullFlashWriteOrderPlan\n\tevidence     FullFlashMutationAuthorizationEvidence\n\tseal         *fullFlashMutationAuthorizationSeal\n}\n"""
new = """type FullFlashMutationAuthorization struct {\n\tmu           sync.Mutex\n\tconfirmation *FullFlashDestructiveConfirmation\n\twriteOrder   FullFlashWriteOrderPlan\n\tevidence     FullFlashMutationAuthorizationEvidence\n\tconsumed     bool\n\tseal         *fullFlashMutationAuthorizationSeal\n}\n"""
if old not in text:
    raise SystemExit("mutation authorization struct anchor not found")
text = text.replace(old, new, 1)
old = """func (authorization *FullFlashMutationAuthorization) validateLocked() error {\n\tif authorization.seal != issuedFullFlashMutationAuthorizationSeal || authorization.confirmation == nil {\n"""
new = """func (authorization *FullFlashMutationAuthorization) validateLocked() error {\n\tif authorization.consumed {\n\t\treturn errors.New(\"FFU mutation authorization has already been consumed\")\n\t}\n\tif authorization.seal != issuedFullFlashMutationAuthorizationSeal || authorization.confirmation == nil {\n"""
if old not in text:
    raise SystemExit("mutation authorization validator anchor not found")
text = text.replace(old, new, 1)
path.write_text(text)

executor = Path("internal/ffu/restore_executor_linux.go")
text = executor.read_text()
text = text.replace('\n\t"fmt"', "")
text = text.replace("\nvar _ = fmt.Sprintf\n", "\n")
text = text.replace(
    "\t\tMutationBytesPlanned:          order.MutationBytes,\n",
    "\t\tMutationBytesPlanned:          order.MutationBytes,\n\t\tAuthorizationConsumed:         authorization.consumed,\n",
    1,
)
executor.write_text(text)
