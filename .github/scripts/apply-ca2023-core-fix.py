#!/usr/bin/env python3
from pathlib import Path

path = Path("internal/windowsmedia/ca2023.go")
text = path.read_text(encoding="utf-8")
old_vars = '''var (
\tinspectWindowsCA2023Metadata = InspectWIMMetadata
\tinspectWindowsCA2023WIMPath  = inspectWIMPath
\textractWindowsCA2023Paths     = extractWindowsCA2023
\tinspectWindowsCA2023PE        = inspectCA2023PE
)
'''
new_vars = '''var (
\tinspectWindowsCA2023Metadata = InspectWIMMetadata
\tinspectWindowsCA2023WIMPath  = inspectWIMPath
\twindowsCA2023WIMExecutable   = wimlibExecutable
\textractWindowsCA2023Paths     = extractWindowsCA2023
\tinspectWindowsCA2023PE        = inspectCA2023PE
)
'''
if old_vars in text:
    text = text.replace(old_vars, new_vars, 1)
elif new_vars not in text:
    raise SystemExit("CA 2023 hook block not found")
old_probe = '''\tfor _, index := range indexes {
\t\tcomplete := true
\t\tfor _, path := range []string{windowsCA2023BootmgfwPath, windowsCA2023BootmgrPath, windowsCA2023FontsPath} {
\t\t\tavailable, pathErr := inspectWindowsCA2023WIMPath(ctx, mustWIMExecutable(), bootWIMPath, index, path)
'''
new_probe = '''\texecutable, err := windowsCA2023WIMExecutable()
\tif err != nil {
\t\treturn WindowsCA2023Capability{}, err
\t}
\tfor _, index := range indexes {
\t\tcomplete := true
\t\tfor _, path := range []string{windowsCA2023BootmgfwPath, windowsCA2023BootmgrPath, windowsCA2023FontsPath} {
\t\t\tavailable, pathErr := inspectWindowsCA2023WIMPath(ctx, executable, bootWIMPath, index, path)
'''
if old_probe in text:
    text = text.replace(old_probe, new_probe, 1)
elif new_probe not in text:
    raise SystemExit("CA 2023 capability probe block not found")
old_helper = '''
func mustWIMExecutable() string {
\tpath, err := wimlibExecutable()
\tif err != nil {
\t\treturn ""
\t}
\treturn path
}
'''
if old_helper in text:
    text = text.replace(old_helper, "", 1)
text = text.replace("isoRoot, err := resolveRoot(isoRoot)", "isoRoot, err := resolveWindowsCA2023Root(isoRoot)", 1)
resolver = '''
func resolveWindowsCA2023Root(path string) (string, error) {
\tpath = strings.TrimSpace(path)
\tif path == "" {
\t\treturn "", errors.New("Windows CA 2023 ISO root is empty")
\t}
\tabsolute, err := filepath.Abs(path)
\tif err != nil {
\t\treturn "", err
\t}
\tresolved, err := filepath.EvalSymlinks(absolute)
\tif err != nil {
\t\treturn "", err
\t}
\tinfo, err := os.Stat(resolved)
\tif err != nil {
\t\treturn "", err
\t}
\tif !info.IsDir() {
\t\treturn "", errors.New("Windows CA 2023 ISO root is not a directory")
\t}
\treturn resolved, nil
}

'''
marker = "// InspectWindowsCA2023Capability checks only the two boot.wim indexes used by\n"
if resolver.strip() not in text:
    if marker not in text:
        raise SystemExit("CA 2023 resolver insertion marker not found")
    text = text.replace(marker, resolver + marker, 1)
path.write_text(text, encoding="utf-8")
