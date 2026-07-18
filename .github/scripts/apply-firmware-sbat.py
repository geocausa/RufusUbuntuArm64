from pathlib import Path
import json


def replace_once(path, old, new):
    target = Path(path)
    source = target.read_text()
    count = source.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one replacement, found {count}")
    target.write_text(source.replace(old, new, 1))


Path("internal/secureboot/sbat_firmware_linux.go").write_text(r'''//go:build linux

package secureboot

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	defaultEFIVarFSRoot                           = "/sys/firmware/efi/efivars"
	shimLockVariableGUID                         = "605dab50-e046-4300-abb6-3dd810dd8b23"
	efiVariableNonVolatile                uint32 = 1 << 0
	efiVariableBootServiceAccess          uint32 = 1 << 1
	efiVariableRuntimeAccess              uint32 = 1 << 2
	efiVariableTimeBasedAuthenticatedWrite uint32 = 1 << 5
)

type firmwareSBATVariable struct {
	name       string
	path       string
	attributes uint32
	payload    []byte
}

type firmwareSBATReadHook func(stage, path string)

// FirmwareSBATLevel loads the SBAT level exposed by the running shim through
// efivarfs. SbatLevelRT is the preferred operating-system-visible mirror; the
// persistent SbatLevel is an exact fallback only when the firmware exposes it.
func FirmwareSBATLevel() (*SBATLevel, error) {
	return loadFirmwareSBATLevel(defaultEFIVarFSRoot, nil)
}

func loadFirmwareSBATLevel(root string, hook firmwareSBATReadHook) (*SBATLevel, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, errors.New("efivarfs root is required")
	}

	runtimeVariable, runtimeErr := readFirmwareSBATVariable(root, "SbatLevelRT", hook)
	if runtimeErr != nil && !errors.Is(runtimeErr, os.ErrNotExist) {
		return nil, runtimeErr
	}
	persistentVariable, persistentErr := readFirmwareSBATVariable(root, "SbatLevel", hook)
	if persistentErr != nil && !errors.Is(persistentErr, os.ErrNotExist) {
		return nil, persistentErr
	}
	if runtimeVariable == nil && persistentVariable == nil {
		return nil, errors.New("firmware SBAT level is unavailable; shim may not have published SbatLevelRT or the system may not be booted through shim")
	}
	if runtimeVariable != nil && persistentVariable != nil && !bytes.Equal(runtimeVariable.payload, persistentVariable.payload) {
		return nil, errors.New("firmware SbatLevelRT and SbatLevel payloads differ; refusing an ambiguous enforced SBAT level")
	}

	selected := runtimeVariable
	if selected == nil {
		selected = persistentVariable
	}
	source := fmt.Sprintf("firmware %s (%s; attributes 0x%08x)", selected.name, selected.path, selected.attributes)
	level, err := ParseSBATLevel(selected.payload, source)
	if err != nil {
		return nil, fmt.Errorf("parse firmware %s: %w", selected.name, err)
	}
	return level, nil
}

func readFirmwareSBATVariable(root, name string, hook firmwareSBATReadHook) (*firmwareSBATVariable, error) {
	path := filepath.Join(root, name+"-"+shimLockVariableGUID)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("locate firmware %s variable: %w", name, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("firmware %s variable must not be a symbolic link", name)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("firmware %s variable is not a regular efivarfs file", name)
	}
	expected, err := uefiIdentityFromInfo(info)
	if err != nil {
		return nil, fmt.Errorf("identify firmware %s variable: %w", name, err)
	}
	if hook != nil {
		hook("before-open", path)
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open firmware %s variable without following links: %w", name, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("create descriptor for firmware %s variable", name)
	}
	defer file.Close()
	actual, err := uefiIdentityFromOpenFile(file)
	if err != nil {
		return nil, fmt.Errorf("identify open firmware %s variable: %w", name, err)
	}
	if !sameUEFIKernelObject(expected, actual) {
		return nil, fmt.Errorf("firmware %s variable changed before it was opened", name)
	}
	maximumSize := maximumSBATLevelFileSize + 4
	if actual.size <= 4 || actual.size > maximumSize {
		return nil, fmt.Errorf("firmware %s variable must contain attributes and a non-empty payload no larger than %d bytes", name, maximumSBATLevelFileSize)
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumSize+1))
	if err != nil {
		return nil, fmt.Errorf("read firmware %s variable: %w", name, err)
	}
	after, err := uefiIdentityFromOpenFile(file)
	if err != nil {
		return nil, fmt.Errorf("restat firmware %s variable: %w", name, err)
	}
	if !sameStableUEFIFile(actual, after) || int64(len(data)) != actual.size {
		return nil, fmt.Errorf("firmware %s variable changed while it was being read", name)
	}
	attributes := binary.LittleEndian.Uint32(data[:4])
	if err := validateFirmwareSBATAttributes(name, attributes); err != nil {
		return nil, err
	}
	return &firmwareSBATVariable{
		name:       name,
		path:       path,
		attributes: attributes,
		payload:    append([]byte(nil), data[4:]...),
	}, nil
}

func validateFirmwareSBATAttributes(name string, attributes uint32) error {
	switch name {
	case "SbatLevelRT":
		expected := efiVariableBootServiceAccess | efiVariableRuntimeAccess
		if attributes != expected {
			return fmt.Errorf("firmware SbatLevelRT has attributes 0x%08x; expected exactly boot-service/runtime 0x%08x", attributes, expected)
		}
	case "SbatLevel":
		plain := efiVariableNonVolatile | efiVariableBootServiceAccess
		timeAuthenticated := plain | efiVariableTimeBasedAuthenticatedWrite
		if attributes != plain && attributes != timeAuthenticated {
			return fmt.Errorf("firmware SbatLevel has attributes 0x%08x; expected boot-service/non-volatile 0x%08x or time-authenticated 0x%08x without runtime access", attributes, plain, timeAuthenticated)
		}
	default:
		return fmt.Errorf("unsupported firmware SBAT variable %q", name)
	}
	return nil
}
''')

Path("internal/secureboot/sbat_firmware_test.go").write_text(r'''//go:build linux

package secureboot

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func syntheticSBATLevelPayload() []byte {
	return []byte("sbat,1,2025051000\nshim,4\ngrub,5\n")
}

func writeSyntheticEFIVariable(t *testing.T, root, name string, attributes uint32, payload []byte) string {
	t.Helper()
	path := filepath.Join(root, name+"-"+shimLockVariableGUID)
	data := make([]byte, 4+len(payload))
	binary.LittleEndian.PutUint32(data[:4], attributes)
	copy(data[4:], payload)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFirmwareSBATLevelPrefersRuntimeMirror(t *testing.T) {
	root := t.TempDir()
	payload := syntheticSBATLevelPayload()
	writeSyntheticEFIVariable(t, root, "SbatLevelRT", efiVariableBootServiceAccess|efiVariableRuntimeAccess, payload)
	writeSyntheticEFIVariable(t, root, "SbatLevel", efiVariableNonVolatile|efiVariableBootServiceAccess, payload)
	level, err := loadFirmwareSBATLevel(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if level.Datestamp != "2025051000" || !strings.Contains(level.Source, "SbatLevelRT") || !strings.Contains(level.Source, "0x00000006") {
		t.Fatalf("unexpected firmware SBAT source: %#v", level)
	}
}

func TestFirmwareSBATLevelFallsBackToPersistentVariable(t *testing.T) {
	root := t.TempDir()
	attributes := efiVariableNonVolatile | efiVariableBootServiceAccess | efiVariableTimeBasedAuthenticatedWrite
	writeSyntheticEFIVariable(t, root, "SbatLevel", attributes, syntheticSBATLevelPayload())
	level, err := loadFirmwareSBATLevel(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(level.Source, "SbatLevel") || strings.Contains(level.Source, "SbatLevelRT") || !strings.Contains(level.Source, "0x00000023") {
		t.Fatalf("unexpected persistent firmware source: %q", level.Source)
	}
}

func TestFirmwareSBATLevelRejectsDivergentCopies(t *testing.T) {
	root := t.TempDir()
	writeSyntheticEFIVariable(t, root, "SbatLevelRT", efiVariableBootServiceAccess|efiVariableRuntimeAccess, syntheticSBATLevelPayload())
	writeSyntheticEFIVariable(t, root, "SbatLevel", efiVariableNonVolatile|efiVariableBootServiceAccess, []byte("sbat,1,2025051000\nshim,5\n"))
	if _, err := loadFirmwareSBATLevel(root, nil); err == nil || !strings.Contains(err.Error(), "payloads differ") {
		t.Fatalf("divergent firmware variables error = %v", err)
	}
}

func TestFirmwareSBATLevelRejectsInvalidAttributes(t *testing.T) {
	root := t.TempDir()
	writeSyntheticEFIVariable(t, root, "SbatLevelRT", efiVariableNonVolatile|efiVariableBootServiceAccess|efiVariableRuntimeAccess, syntheticSBATLevelPayload())
	if _, err := loadFirmwareSBATLevel(root, nil); err == nil || !strings.Contains(err.Error(), "expected exactly") {
		t.Fatalf("runtime attribute error = %v", err)
	}
}

func TestFirmwareSBATLevelRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	data := make([]byte, 4+len(syntheticSBATLevelPayload()))
	binary.LittleEndian.PutUint32(data[:4], efiVariableBootServiceAccess|efiVariableRuntimeAccess)
	copy(data[4:], syntheticSBATLevelPayload())
	if err := os.WriteFile(target, data, 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "SbatLevelRT-"+shimLockVariableGUID)
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := loadFirmwareSBATLevel(root, nil); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("symlink error = %v", err)
	}
}

func TestFirmwareSBATLevelRejectsTruncatedAndMalformedPayloads(t *testing.T) {
	t.Run("truncated", func(t *testing.T) {
		root := t.TempDir()
		writeSyntheticEFIVariable(t, root, "SbatLevelRT", efiVariableBootServiceAccess|efiVariableRuntimeAccess, nil)
		if _, err := loadFirmwareSBATLevel(root, nil); err == nil || !strings.Contains(err.Error(), "non-empty payload") {
			t.Fatalf("truncated variable error = %v", err)
		}
	})
	t.Run("malformed", func(t *testing.T) {
		root := t.TempDir()
		writeSyntheticEFIVariable(t, root, "SbatLevelRT", efiVariableBootServiceAccess|efiVariableRuntimeAccess, []byte("shim,4\n"))
		if _, err := loadFirmwareSBATLevel(root, nil); err == nil || !strings.Contains(err.Error(), "must start with sbat") {
			t.Fatalf("malformed payload error = %v", err)
		}
	})
}

func TestFirmwareSBATLevelRejectsAbsence(t *testing.T) {
	if _, err := loadFirmwareSBATLevel(t.TempDir(), nil); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("absence error = %v", err)
	}
}

func TestFirmwareSBATLevelRejectsSubstitutionBeforeOpen(t *testing.T) {
	root := t.TempDir()
	path := writeSyntheticEFIVariable(t, root, "SbatLevelRT", efiVariableBootServiceAccess|efiVariableRuntimeAccess, syntheticSBATLevelPayload())
	replacement := filepath.Join(root, "replacement")
	data := make([]byte, 4+len(syntheticSBATLevelPayload()))
	binary.LittleEndian.PutUint32(data[:4], efiVariableBootServiceAccess|efiVariableRuntimeAccess)
	copy(data[4:], syntheticSBATLevelPayload())
	if err := os.WriteFile(replacement, data, 0o600); err != nil {
		t.Fatal(err)
	}
	changed := false
	hook := func(stage, candidate string) {
		if changed || stage != "before-open" || candidate != path {
			return
		}
		changed = true
		if err := os.Rename(candidate, candidate+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(replacement, candidate); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := loadFirmwareSBATLevel(root, hook); err == nil || !strings.Contains(err.Error(), "changed before it was opened") {
		t.Fatalf("substitution error = %v", err)
	}
}
''')

replace_once(
    "cmd/rufus-linux/main.go",
    "  rufusarm64-cli uefi validate --directory DIR [--arch ARCH] [--dbx FILE | --firmware] [--sbat-level FILE] [--json]\n",
    "  rufusarm64-cli uefi validate --directory DIR [--arch ARCH] [--dbx FILE | --firmware] [--sbat-level FILE | --firmware-sbat] [--json]\n",
)

replace_once(
    "cmd/rufus-linux/main.go",
    '''\tsbatLevelPath := fs.String("sbat-level", "", "optional trusted local shim-compatible SbatLevel CSV file")
\tasJSON := fs.Bool("json", false, "output JSON")
''',
    '''\tsbatLevelPath := fs.String("sbat-level", "", "optional trusted local shim-compatible SbatLevel CSV file")
\tfirmwareSBAT := fs.Bool("firmware-sbat", false, "use the SBAT level exposed by the running shim through efivarfs")
\tasJSON := fs.Bool("json", false, "output JSON")
''',
)

helper = r'''
func loadUEFISBATLevel(path string, firmware bool, firmwareLoader func() (*secureboot.SBATLevel, error)) (*secureboot.SBATLevel, error) {
	path = strings.TrimSpace(path)
	if path != "" && firmware {
		return nil, errors.New("select at most one of --sbat-level or --firmware-sbat")
	}
	if firmware {
		if firmwareLoader == nil {
			return nil, errors.New("firmware SBAT loader is unavailable")
		}
		return firmwareLoader()
	}
	if path != "" {
		return secureboot.LoadSBATLevelFile(path)
	}
	return nil, nil
}

'''
replace_once(
    "cmd/rufus-linux/main.go",
    "func runUEFIValidate(args []string) error {\n",
    helper + "func runUEFIValidate(args []string) error {\n",
)

replace_once(
    "cmd/rufus-linux/main.go",
    '''\tvar sbatLevel *secureboot.SBATLevel
\tif strings.TrimSpace(*sbatLevelPath) != "" {
\t\tsbatLevel, err = secureboot.LoadSBATLevelFile(*sbatLevelPath)
\t\tif err != nil {
\t\t\treturn err
\t\t}
\t}
''',
    '''\tsbatLevel, err := loadUEFISBATLevel(*sbatLevelPath, *firmwareSBAT, secureboot.FirmwareSBATLevel)
\tif err != nil {
\t\treturn err
\t}
''',
)

main_tests = r'''

func TestLoadUEFISBATLevelSelection(t *testing.T) {
	firmwareLevel := &secureboot.SBATLevel{Source: "firmware"}
	called := false
	got, err := loadUEFISBATLevel("", true, func() (*secureboot.SBATLevel, error) {
		called = true
		return firmwareLevel, nil
	})
	if err != nil || got != firmwareLevel || !called {
		t.Fatalf("firmware selection got=%#v called=%t err=%v", got, called, err)
	}
	if _, err := loadUEFISBATLevel("/tmp/SbatLevel.csv", true, func() (*secureboot.SBATLevel, error) {
		t.Fatal("conflicting sources must fail before loading firmware")
		return nil, nil
	}); err == nil || !strings.Contains(err.Error(), "at most one") {
		t.Fatalf("conflicting SBAT sources error = %v", err)
	}
	got, err = loadUEFISBATLevel("", false, func() (*secureboot.SBATLevel, error) {
		t.Fatal("unused firmware loader was called")
		return nil, nil
	})
	if err != nil || got != nil {
		t.Fatalf("empty SBAT selection got=%#v err=%v", got, err)
	}
}

func TestUEFIValidateRejectsConflictingSBATSources(t *testing.T) {
	err := runUEFIValidate([]string{
		"--directory", t.TempDir(),
		"--arch", "arm64",
		"--sbat-level", "/tmp/SbatLevel.csv",
		"--firmware-sbat",
	})
	if err == nil || !strings.Contains(err.Error(), "at most one") {
		t.Fatalf("conflicting SBAT source error = %v", err)
	}
}
'''
main_test_path = Path("cmd/rufus-linux/main_test.go")
main_test_path.write_text(main_test_path.read_text() + main_tests)

replace_once(
    "docs/rufusarm64-cli.1",
    '''.RI [ --sbat-level " FILE" ]
.RI [ --json ]
''',
    '''.RI [ --sbat-level " FILE" | --firmware-sbat ]
.RI [ --json ]
''',
)

replace_once(
    "docs/rufusarm64-cli.1",
    '''minimum. The file is read once from a pinned regular-file descriptor; firmware
SbatLevel acquisition is not performed by this option.
.PP
''',
    '''minimum. The file is read once from a pinned regular-file descriptor.
.TP
.B --firmware-sbat
Use the SBAT level exposed by the running shim through efivarfs. The runtime
SbatLevelRT mirror is preferred and must have exact boot-service/runtime
attributes. A readable persistent SbatLevel fallback must have shim-compatible
boot-service/non-volatile attributes; readable copies must have identical
payloads. Firmware is never modified.
.PP
''',
)

replace_once(
    "README.md",
    "rufusarm64-cli uefi validate --directory /mnt/usb --arch arm64 --sbat-level ./SbatLevel.csv --json\n",
    "rufusarm64-cli uefi validate --directory /mnt/usb --arch arm64 --firmware-sbat --json\n",
)

parity_path = Path("docs/upstream-rufus-parity.json")
parity = json.loads(parity_path.read_text())
for feature in parity["features"]:
    if feature["id"] == "uefi-runtime-validation":
        feature["notes"] = (
            "The 0.11 development line exposes descriptor-rooted CLI and GTK validation of fallback loaders, "
            "PE architecture and EFI subsystem fields, bounded SBAT metadata, optional DBX hash/certificate "
            "revocations, shim-compatible local SbatLevel comparison, and read-only acquisition of the running "
            "shim SbatLevelRT/SbatLevel through strictly validated efivarfs files. GTK SBAT source selection and "
            "complete boot-chain reference resolution remain planned."
        )
        break
else:
    raise SystemExit("UEFI runtime validation parity entry was not found")
parity_path.write_text(json.dumps(parity, indent=2) + "\n")
