from pathlib import Path

path = Path('.github/scripts/apply-sbat-level.py')
source = path.read_text()

old_root = "    '''\\tfmt.Printf(\"Root: %s\\nFallback: %s (found: %t)\\nDBX checked: %t\\n\", result.Root, result.FallbackPath, result.FallbackFound, result.DBXChecked)\n"
new_root = "    '''\\tfmt.Printf(\"Root: %s\\\\nFallback: %s (found: %t)\\\\nDBX checked: %t\\\\n\", result.Root, result.FallbackPath, result.FallbackFound, result.DBXChecked)\n"
if source.count(old_root) != 1:
    raise SystemExit(f'expected one existing Root fmt source literal, found {source.count(old_root)}')
source = source.replace(old_root, new_root, 1)

old_new_root = "    '''\\tfmt.Printf(\"Root: %s\\nFallback: %s (found: %t)\\nDBX checked: %t\\nSBAT level checked: %t\\n\", result.Root, result.FallbackPath, result.FallbackFound, result.DBXChecked, result.SBATLevelChecked)\n\\tif result.SBATLevelChecked {\n\\t\\tfmt.Printf(\"SBAT level: %s (datestamp %s)\\n\", result.SBATLevelSource, result.SBATLevelDatestamp)\n\\t}\n"
new_new_root = "    '''\\tfmt.Printf(\"Root: %s\\\\nFallback: %s (found: %t)\\\\nDBX checked: %t\\\\nSBAT level checked: %t\\\\n\", result.Root, result.FallbackPath, result.FallbackFound, result.DBXChecked, result.SBATLevelChecked)\n\\tif result.SBATLevelChecked {\n\\t\\tfmt.Printf(\"SBAT level: %s (datestamp %s)\\\\n\", result.SBATLevelSource, result.SBATLevelDatestamp)\n\\t}\n"
if source.count(old_new_root) != 1:
    raise SystemExit(f'expected one replacement Root fmt source literal, found {source.count(old_new_root)}')
source = source.replace(old_new_root, new_new_root, 1)

old_revocations = "    '''\\t\\tfor _, revocation := range file.SBATRevocations {\n\\t\\t\\tfmt.Printf(\"  SBAT revoked: %s generation %d is below trusted minimum %d\\n\", revocation.Component, revocation.ImageGeneration, revocation.MinimumGeneration)\n\\t\\t}\n\\t\\tfor _, warning := range file.Warnings {\n"
new_revocations = "    '''\\t\\tfor _, revocation := range file.SBATRevocations {\n\\t\\t\\tfmt.Printf(\"  SBAT revoked: %s generation %d is below trusted minimum %d\\\\n\", revocation.Component, revocation.ImageGeneration, revocation.MinimumGeneration)\n\\t\\t}\n\\t\\tfor _, warning := range file.Warnings {\n"
if source.count(old_revocations) != 1:
    raise SystemExit(f'expected one SBAT revocation source literal, found {source.count(old_revocations)}')
source = source.replace(old_revocations, new_revocations, 1)

path.write_text(source)
