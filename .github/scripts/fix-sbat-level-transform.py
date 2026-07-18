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

old_blank = '''\tdata = bytes.TrimRight(data, "\\r\\n")
\tif len(data) == 0 {
\t\treturn nil, errors.New("SBAT level is empty")
\t}
\treader := csv.NewReader(bytes.NewReader(data))
'''
new_blank = '''\tdata = bytes.TrimRight(data, "\\r\\n")
\tif len(data) == 0 {
\t\treturn nil, errors.New("SBAT level is empty")
\t}
\tfor index, line := range strings.Split(string(data), "\\n") {
\t\tif strings.TrimSuffix(line, "\\r") == "" {
\t\t\treturn nil, fmt.Errorf("SBAT level row %d is empty", index+1)
\t\t}
\t}
\treader := csv.NewReader(bytes.NewReader(data))
'''
if source.count(old_blank) != 1:
    raise SystemExit(f'expected one SBAT blank-line parser insertion point, found {source.count(old_blank)}')
source = source.replace(old_blank, new_blank, 1)

path.write_text(source)
