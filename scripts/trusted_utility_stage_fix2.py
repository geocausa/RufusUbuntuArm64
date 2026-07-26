#!/usr/bin/env python3
"""Make the mounted-target test replacement independent of shell-string escaping."""

from pathlib import Path

path = Path("scripts/trusted_utility_stage.py")
text = path.read_text(encoding="utf-8")
start = text.find("    old = '''func TestEnsureNoMountedDescendantsFailsClosed")
end_marker = '    replace_once(tests, old, new, "mounted descendant finder injection")\n'
end = text.find(end_marker, start)
if start < 0 or end < 0:
    raise SystemExit("mounted-target staging block is missing")
end += len(end_marker)
replacement = '''    source_text = tests.read_text(encoding="utf-8")
    function_start = source_text.find("func TestEnsureNoMountedDescendantsFailsClosed(t *testing.T) {")
    next_function = source_text.find("\\nfunc ", function_start + 1)
    if function_start < 0 or next_function < 0:
        raise SystemExit("mounted descendant test function boundary is missing")
    new_function = r''' + "'''" + '''func TestEnsureNoMountedDescendantsFailsClosed(t *testing.T) {
\tuseSafetyDeviceFinder(t, func(path string) (device.BlockDevice, error) {
\t\treturn device.BlockDevice{
\t\t\tPath: path,
\t\t\tType: "disk",
\t\t\tSize: 1000,
\t\t\tTransport: "usb",
\t\t\tChildren: []device.BlockDevice{{
\t\t\t\tPath: "/dev/sda1", Type: "part", Size: 900, Mountpoints: []string{"/media/usb"},
\t\t\t}},
\t\t}, nil
\t})
\tif err := EnsureNoMountedDescendants("/dev/sda"); err == nil || !strings.Contains(err.Error(), "mounted again") {
\t\tt.Fatalf("expected mounted-target refusal, got %v", err)
\t}
}

''' + "'''" + '''
    tests.write_text(
        source_text[:function_start] + new_function + source_text[next_function + 1:],
        encoding="utf-8",
    )
'''
path.write_text(text[:start] + replacement + text[end:], encoding="utf-8")
