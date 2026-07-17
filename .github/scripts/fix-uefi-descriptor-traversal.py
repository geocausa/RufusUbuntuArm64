from pathlib import Path

path = Path("internal/secureboot/uefi_descriptor_linux.go")
source = path.read_text()
source = source.replace(
    "entries, err := directory.Readdir(-1)",
    "entries, err := directory.ReadDir(-1)",
    1,
)
old = '''\t\tif entry.Mode()&os.ModeSymlink != 0 {
\t\t\t*warnings = append(*warnings, "ignored symbolic link "+relative)
\t\t\tcontinue
\t\t}
\t\tif entry.IsDir() {
\t\t\tif hook != nil {
\t\t\t\thook("entry-before-open", relative)
\t\t\t}
\t\t\tchild, err := openUEFIEntry(directory, name, entry, true)
'''
new = '''\t\tentryInfo, err := os.Lstat(filepath.Join(directory.Name(), name))
\t\tif err != nil {
\t\t\treturn fmt.Errorf("stat UEFI entry %s: %w", relative, err)
\t\t}
\t\tif entryInfo.Mode()&os.ModeSymlink != 0 {
\t\t\t*warnings = append(*warnings, "ignored symbolic link "+relative)
\t\t\tcontinue
\t\t}
\t\tif entryInfo.IsDir() {
\t\t\tif hook != nil {
\t\t\t\thook("entry-before-open", relative)
\t\t\t}
\t\t\tchild, err := openUEFIEntry(directory, name, entryInfo, true)
'''
if old not in source:
    raise SystemExit("directory-entry block was not found")
source = source.replace(old, new, 1)
source = source.replace("if !entry.Mode().IsRegular() {", "if !entryInfo.Mode().IsRegular() {", 1)
source = source.replace(
    "file, err := openUEFIEntry(directory, name, entry, false)",
    "file, err := openUEFIEntry(directory, name, entryInfo, false)",
    1,
)
source = source.replace(
    "file := os.NewFile(uintptr(fd), name)",
    "file := os.NewFile(uintptr(fd), filepath.Join(parent.Name(), name))",
    1,
)
path.write_text(source)
