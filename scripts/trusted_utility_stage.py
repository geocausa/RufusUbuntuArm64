#!/usr/bin/env python3
"""Apply the exact trusted-utility source transformation on one staging branch."""

from pathlib import Path
import subprocess


def replace_once(path, old, new, label):
    source = path.read_text(encoding="utf-8")
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one source anchor, found {count}")
    path.write_text(source.replace(old, new), encoding="utf-8")


def patch_device():
    source = Path("internal/device/device.go")
    replace_once(
        source,
        '\tcmd := exec.CommandContext(ctx,\n\t\t"lsblk", "--json", "--bytes", "--output",\n',
        '\tlsblkPath, err := resolveDeviceUtility("lsblk")\n'
        '\tif err != nil {\n'
        '\t\treturn nil, fmt.Errorf("resolve trusted lsblk: %w", err)\n'
        '\t}\n'
        '\tcmd := exec.CommandContext(ctx,\n'
        '\t\tlsblkPath, "--json", "--bytes", "--output",\n',
        "device lsblk command",
    )

    tests = Path("internal/device/device_test.go")
    replace_once(
        tests,
        'import (\n\t"os"\n\t"testing"\n)',
        'import (\n\t"errors"\n\t"os"\n\t"path/filepath"\n\t"testing"\n)',
        "device test imports",
    )
    replace_once(tests, 'path := fakeBin + "/lsblk"', 'path := filepath.Join(fakeBin, "lsblk")', "first fake lsblk path")
    replace_once(
        tests,
        't.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))',
        'useDeviceUtility(t, "lsblk", path)',
        "first device PATH injection",
    )
    replace_once(
        tests,
        '\tif err := os.WriteFile(fakeBin+"/lsblk", []byte(script), 0o755); err != nil {\n'
        '\t\tt.Fatal(err)\n'
        '\t}',
        '\tpath := filepath.Join(fakeBin, "lsblk")\n'
        '\tif err := os.WriteFile(path, []byte(script), 0o755); err != nil {\n'
        '\t\tt.Fatal(err)\n'
        '\t}',
        "second fake lsblk path",
    )
    replace_once(
        tests,
        't.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))',
        'useDeviceUtility(t, "lsblk", path)',
        "second device PATH injection",
    )
    text = tests.read_text(encoding="utf-8")
    text += '''

func useDeviceUtility(t *testing.T, expectedName, path string) {
\tt.Helper()
\tprevious := resolveDeviceUtility
\tresolveDeviceUtility = func(name string) (string, error) {
\t\tif name != expectedName {
\t\t\treturn "", errors.New("unexpected utility request: " + name)
\t\t}
\t\treturn path, nil
\t}
\tt.Cleanup(func() { resolveDeviceUtility = previous })
}
'''
    tests.write_text(text, encoding="utf-8")


def patch_safety():
    source = Path("internal/safety/safety_linux.go")
    replace_once(source, '\t"os/exec"\n', '', "remove ambient exec import")
    text = source.read_text(encoding="utf-8")
    count = text.count("device.Find(")
    if count != 3:
        raise SystemExit(f"safety device finder: expected 3 anchors, found {count}")
    source.write_text(text.replace("device.Find(", "findSafetyDevice("), encoding="utf-8")
    replace_once(
        source,
        '\t\tcmd := exec.CommandContext(ctx, "umount", "--", mountpoint)\n'
        '\t\tvar stderr bytes.Buffer\n'
        '\t\tcmd.Stderr = &stderr\n'
        '\t\terr := cmd.Run()\n'
        '\t\tcancel()',
        '\t\tcmd, commandErr := trustedSafetyCommandContext(ctx, "umount", "--", mountpoint)\n'
        '\t\tif commandErr != nil {\n'
        '\t\t\tcancel()\n'
        '\t\t\treturn fmt.Errorf("unmount %s: %w", mountpoint, commandErr)\n'
        '\t\t}\n'
        '\t\tvar stderr bytes.Buffer\n'
        '\t\tcmd.Stderr = &stderr\n'
        '\t\terr := cmd.Run()\n'
        '\t\tcancel()',
        "trusted umount",
    )
    replace_once(
        source,
        'func runCommand(ctx context.Context, name string, args ...string) error {\n'
        '\tcmd := exec.CommandContext(ctx, name, args...)\n'
        '\tvar stderr bytes.Buffer',
        'func runCommand(ctx context.Context, name string, args ...string) error {\n'
        '\tcmd, err := trustedSafetyCommandContext(ctx, name, args...)\n'
        '\tif err != nil {\n'
        '\t\treturn err\n'
        '\t}\n'
        '\tvar stderr bytes.Buffer',
        "trusted runCommand",
    )
    replace_once(
        source,
        '\tcmd := exec.CommandContext(ctx, name, args...)\n\tvar stdout, stderr bytes.Buffer',
        '\tcmd, err := trustedSafetyCommandContext(ctx, name, args...)\n'
        '\tif err != nil {\n'
        '\t\treturn "", err\n'
        '\t}\n'
        '\tvar stdout, stderr bytes.Buffer',
        "trusted commandOutput",
    )

    tests = Path("internal/safety/safety_linux_test.go")
    replace_once(
        tests,
        'import (\n\t"context"\n\t"os"',
        'import (\n\t"context"\n\t"errors"\n\t"os"',
        "safety test imports",
    )
    replace_once(
        tests,
        't.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))',
        'useSafetyUtilities(t, map[string]string{\n'
        '\t\t"findmnt": filepath.Join(fakeBin, "findmnt"),\n'
        '\t\t"lsblk":   filepath.Join(fakeBin, "lsblk"),\n'
        '\t})',
        "backing disk utility injection",
    )
    replace_once(
        tests,
        't.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))',
        'useSafetyUtilities(t, map[string]string{"umount": filepath.Join(fakeBin, "umount")})',
        "umount utility injection",
    )
    old = '''func TestEnsureNoMountedDescendantsFailsClosed(t *testing.T) {
\tfakeBin := t.TempDir()
\tjsonOutput := `{"blockdevices":[{"name":"sda","path":"/dev/sda","type":"disk","size":1000,"model":"","vendor":"","tran":"usb","rm":0,"ro":0,"hotplug":1,"mountpoints":[null],"pkname":null,"maj:min":"8:0","serial":"","wwn":"","children":[{"name":"sda1","path":"/dev/sda1","type":"part","size":900,"model":"","vendor":"","tran":"","rm":0,"ro":0,"hotplug":0,"mountpoints":["/media/usb"],"pkname":"sda","maj:min":"8:1","serial":"","wwn":""}]}]}`
\twriteFake(t, filepath.Join(fakeBin, "lsblk"), "#!/bin/sh\\nprintf '%s\\n' '"+jsonOutput+"'\\n")
\tt.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
\tif err := EnsureNoMountedDescendants("/dev/sda"); err == nil || !strings.Contains(err.Error(), "mounted again") {
\t\tt.Fatalf("expected mounted-target refusal, got %v", err)
\t}
}'''
    new = '''func TestEnsureNoMountedDescendantsFailsClosed(t *testing.T) {
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
}'''
    replace_once(tests, old, new, "mounted descendant finder injection")
    helpers = '''func useSafetyUtilities(t *testing.T, paths map[string]string) {
\tt.Helper()
\tprevious := resolveSafetyUtility
\tresolveSafetyUtility = func(name string) (string, error) {
\t\tpath, ok := paths[name]
\t\tif !ok {
\t\t\treturn "", errors.New("unexpected utility request: " + name)
\t\t}
\t\treturn path, nil
\t}
\tt.Cleanup(func() { resolveSafetyUtility = previous })
}

func useSafetyDeviceFinder(t *testing.T, finder func(string) (device.BlockDevice, error)) {
\tt.Helper()
\tprevious := findSafetyDevice
\tfindSafetyDevice = finder
\tt.Cleanup(func() { findSafetyDevice = previous })
}

func TestUtilityResolutionFailureIsFailClosed(t *testing.T) {
\tprevious := resolveSafetyUtility
\tresolveSafetyUtility = func(string) (string, error) { return "", errors.New("unsafe utility") }
\tt.Cleanup(func() { resolveSafetyUtility = previous })
\tif err := FlushBuffers(context.Background(), "/dev/sda"); err == nil || !strings.Contains(err.Error(), "unsafe utility") {
\t\tt.Fatalf("utility resolution failure was not propagated: %v", err)
\t}
}

'''
    replace_once(tests, 'func writeFake(t *testing.T, path, content string) {', helpers + 'func writeFake(t *testing.T, path, content string) {', "safety test helpers")


def patch_audit():
    subprocess.run(
        ["git", "checkout", "origin/stage3/0.14.0", "--", ".github/workflows/ffu-software-audit.yml"],
        check=True,
    )
    path = Path(".github/workflows/ffu-software-audit.yml")
    text = path.read_text(encoding="utf-8")
    text = text.replace("      - 'internal/safety/**'\n", "      - 'internal/safety/**'\n      - 'internal/trustedexec/**'\n")
    text = text.replace(
        "go test -race ./internal/ffu ./internal/device ./internal/safety ./cmd/rufus-linux",
        "go test -race ./internal/ffu ./internal/device ./internal/safety ./internal/trustedexec ./cmd/rufus-linux",
    )
    text = text.replace(
        "go vet ./internal/ffu ./internal/device ./internal/safety ./cmd/rufus-linux",
        "go vet ./internal/ffu ./internal/device ./internal/safety ./internal/trustedexec ./cmd/rufus-linux",
    )
    replace_anchor = "          executor = Path('internal/ffu/restore_executor_linux.go').read_text(encoding='utf-8')\n\n          required = {"
    replacement = "          executor = Path('internal/ffu/restore_executor_linux.go').read_text(encoding='utf-8')\n          device_source = Path('internal/device/device.go').read_text(encoding='utf-8')\n          safety_source = Path('internal/safety/safety_linux.go').read_text(encoding='utf-8')\n          trusted = Path('internal/trustedexec/trustedexec_linux.go').read_text(encoding='utf-8')\n\n          required = {"
    if text.count(replace_anchor) != 1:
        raise SystemExit("permanent audit source anchor changed")
    text = text.replace(replace_anchor, replacement)
    replace_anchor = "              'unknown target fail-closed warning': (dialog, 'target state is unknown'),\n          }"
    replacement = "              'unknown target fail-closed warning': (dialog, 'target state is unknown'),\n              'trusted utility resolver': (trusted, 'Ambient PATH is never consulted.'),\n              'device trusted lsblk': (device_source, 'resolveDeviceUtility(\"lsblk\")'),\n              'safety trusted commands': (safety_source, 'trustedSafetyCommandContext'),\n          }"
    if text.count(replace_anchor) != 1:
        raise SystemExit("permanent audit requirement anchor changed")
    text = text.replace(replace_anchor, replacement)
    replace_anchor = "          joined = '\\n'.join((cli, binding, dialog, restore))\n          for label, needle in forbidden.items():"
    replacement = "          joined = '\\n'.join((cli, binding, dialog, restore, device_source, safety_source, trusted))\n          for label, needle in forbidden.items():"
    if text.count(replace_anchor) != 1:
        raise SystemExit("permanent audit joined-source anchor changed")
    text = text.replace(replace_anchor, replacement)
    text = text.replace(
        "              'confirmation bypass': '--yes',\n",
        "              'confirmation bypass': '--yes',\n              'ambient utility lookup': 'exec.LookPath',\n",
    )
    path.write_text(text, encoding="utf-8")


patch_device()
patch_safety()
patch_audit()
