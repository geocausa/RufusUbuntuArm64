from pathlib import Path

path = Path("internal/ffu/restore_target_preflight_linux.go")
source = path.read_text()
old = """\tactualIdentity := device.IdentityToken(dev)
\tif validation.ExpectedTargetIdentity != actualIdentity {
\t\treturn FullFlashTargetPreflightPlan{}, errors.New(\"FFU target identity differs from the authenticated restore plan\")
\t}
\tif dev.Size != validation.TargetSizeBytes {
\t\treturn FullFlashTargetPreflightPlan{}, fmt.Errorf(\"FFU target capacity changed from %d to %d bytes\", validation.TargetSizeBytes, dev.Size)
\t}"""
new = """\tif dev.Size != validation.TargetSizeBytes {
\t\treturn FullFlashTargetPreflightPlan{}, fmt.Errorf(\"FFU target capacity changed from %d to %d bytes\", validation.TargetSizeBytes, dev.Size)
\t}
\tactualIdentity := device.IdentityToken(dev)
\tif validation.ExpectedTargetIdentity != actualIdentity {
\t\treturn FullFlashTargetPreflightPlan{}, errors.New(\"FFU target identity differs from the authenticated restore plan\")
\t}"""
if old not in source:
    raise SystemExit("target capacity/identity block not found")
path.write_text(source.replace(old, new))
