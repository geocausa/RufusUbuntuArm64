import json
from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    file_path = Path(path)
    source = file_path.read_text()
    if source.count(old) != 1:
        raise SystemExit(f"{path}: expected one replacement target, found {source.count(old)}")
    file_path.write_text(source.replace(old, new, 1))


replace_once(
    "cmd/rufus-linux/main.go",
    '''\tcase "dbx":
\t\treturn runDBX(args[1:])
\tcase "acquire":
''',
    '''\tcase "dbx":
\t\treturn runDBX(args[1:])
\tcase "uefi":
\t\treturn runUEFI(args[1:])
\tcase "acquire":
''',
)

replace_once(
    "cmd/rufus-linux/main.go",
    '''  rufusarm64-cli hash FILE
  rufusarm64-cli dbx inspect (--file FILE | --firmware) [--json]
''',
    '''  rufusarm64-cli hash FILE
  rufusarm64-cli uefi validate --directory DIR [--arch ARCH] [--dbx FILE | --firmware] [--json]
  rufusarm64-cli dbx inspect (--file FILE | --firmware) [--json]
''',
)

uefi_functions = r'''
func runUEFI(args []string) error {
	if len(args) == 0 {
		return errors.New("uefi requires validate")
	}
	switch args[0] {
	case "validate":
		return runUEFIValidate(args[1:])
	default:
		return fmt.Errorf("unknown uefi command %q", args[0])
	}
}

func resolveUEFIArchitecture(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value != "" && value != "native" {
		return value, nil
	}
	switch runtime.GOARCH {
	case "386", "amd64", "arm", "arm64", "riscv64":
		return runtime.GOARCH, nil
	case "loong64":
		return "loongarch64", nil
	default:
		return "", fmt.Errorf("the native architecture %q is not supported for UEFI validation", runtime.GOARCH)
	}
}

func runUEFIValidate(args []string) error {
	fs := flag.NewFlagSet("uefi validate", flag.ContinueOnError)
	directory := fs.String("directory", "", "mounted or extracted UEFI media root")
	architecture := fs.String("arch", "native", "native, 386, amd64, arm, arm64, riscv64, or loongarch64")
	maxFiles := fs.Int("max-files", 512, "maximum EFI executables to validate")
	requireFallback := fs.Bool("require-fallback", true, "require the architecture removable-media fallback loader")
	dbxPath := fs.String("dbx", "", "optional DBXUpdate.bin or raw DBX file")
	firmware := fs.Bool("firmware", false, "use the running firmware DBX variable")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("uefi validate does not accept positional arguments")
	}
	if strings.TrimSpace(*directory) == "" {
		return errors.New("--directory is required")
	}
	if *maxFiles <= 0 {
		return errors.New("--max-files must be greater than zero")
	}
	if *dbxPath != "" && *firmware {
		return errors.New("select at most one of --dbx or --firmware")
	}
	resolvedArchitecture, err := resolveUEFIArchitecture(*architecture)
	if err != nil {
		return err
	}
	var dbx *secureboot.Database
	if *dbxPath != "" || *firmware {
		dbx, err = loadDBX(*dbxPath, *firmware)
		if err != nil {
			return err
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	result, err := secureboot.ValidateUEFIMedia(ctx, *directory, secureboot.UEFIValidationOptions{
		Architecture:    resolvedArchitecture,
		MaxFiles:        *maxFiles,
		DBX:             dbx,
		RequireFallback: *requireFallback,
	})
	if err != nil {
		return err
	}
	if *asJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(result); err != nil {
			return err
		}
	} else {
		printUEFIValidation(result)
	}
	if !result.Valid {
		return errors.New("UEFI media validation failed")
	}
	return nil
}

func printUEFIValidation(result secureboot.UEFIMediaValidation) {
	status := "VALID"
	if !result.Valid {
		status = "INVALID"
	}
	fmt.Printf("%s UEFI media for %s\n", status, result.Architecture)
	fmt.Printf("Root: %s\nFallback: %s (found: %t)\nDBX checked: %t\n", result.Root, result.FallbackPath, result.FallbackFound, result.DBXChecked)
	for _, file := range result.Files {
		fileStatus := "OK"
		switch {
		case file.DirectHashRevoked || file.X509CertificateRevoked:
			fileStatus = "REVOKED"
		case file.Error != "":
			fileStatus = "ERROR"
		case len(file.Warnings) > 0:
			fileStatus = "WARNING"
		}
		fmt.Printf("%-8s %s [%s; %s; SBAT records: %d]\n", fileStatus, file.Path, file.MachineName, file.SubsystemName, len(file.SBAT))
		for _, warning := range file.Warnings {
			fmt.Printf("  warning: %s\n", warning)
		}
		if file.Error != "" {
			fmt.Printf("  error: %s\n", file.Error)
		}
	}
	for _, warning := range result.Warnings {
		fmt.Printf("Warning: %s\n", warning)
	}
	for _, validationError := range result.Errors {
		fmt.Printf("Error: %s\n", validationError)
	}
}

'''
replace_once(
    "cmd/rufus-linux/main.go",
    "func runDBX(args []string) error {\n",
    uefi_functions + "func runDBX(args []string) error {\n",
)

replace_once(
    "cmd/rufus-linux/main_test.go",
    '''\t"crypto/ed25519"
\t"encoding/base64"
\t"encoding/json"
\t"os"
''',
    '''\t"crypto/ed25519"
\t"encoding/base64"
\t"encoding/binary"
\t"encoding/json"
\t"io"
\t"os"
''',
)
replace_once(
    "cmd/rufus-linux/main_test.go",
    '''\t"path/filepath"
\t"strings"
\t"testing"
''',
    '''\t"path/filepath"
\t"runtime"
\t"strings"
\t"testing"
''',
)
replace_once(
    "cmd/rufus-linux/main_test.go",
    '''\t"github.com/geocausa/RufusArm64/internal/acquisition"
\t"github.com/geocausa/RufusArm64/internal/imaging"
''',
    '''\t"github.com/geocausa/RufusArm64/internal/acquisition"
\t"github.com/geocausa/RufusArm64/internal/imaging"
\t"github.com/geocausa/RufusArm64/internal/secureboot"
''',
)

tests = r'''

func captureCLIStdout(t *testing.T, operation func() error) (string, error) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = writer
	defer func() { os.Stdout = original }()
	operationErr := operation()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	data, readErr := io.ReadAll(reader)
	if closeErr := reader.Close(); readErr == nil {
		readErr = closeErr
	}
	if readErr != nil {
		t.Fatal(readErr)
	}
	return string(data), operationErr
}

func writeCLIUEFIFallback(t *testing.T, root string, machine uint16) {
	t.Helper()
	const (
		peOffset     = 0x80
		optionalSize = 0xf0
		headersSize  = 0x400
	)
	data := make([]byte, headersSize)
	data[0], data[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(data[0x3c:0x40], peOffset)
	copy(data[peOffset:peOffset+4], []byte{'P', 'E', 0, 0})
	coff := peOffset + 4
	binary.LittleEndian.PutUint16(data[coff:coff+2], machine)
	binary.LittleEndian.PutUint16(data[coff+2:coff+4], 1)
	binary.LittleEndian.PutUint16(data[coff+16:coff+18], optionalSize)
	optional := coff + 20
	binary.LittleEndian.PutUint16(data[optional:optional+2], 0x20b)
	binary.LittleEndian.PutUint16(data[optional+68:optional+70], 10)
	section := optional + optionalSize
	copy(data[section:section+8], []byte(".text"))
	path := filepath.Join(root, "EFI", "BOOT", "BOOTAA64.EFI")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestUEFIValidateJSON(t *testing.T) {
	root := t.TempDir()
	writeCLIUEFIFallback(t, root, 0xaa64)
	output, err := captureCLIStdout(t, func() error {
		return run([]string{"uefi", "validate", "--directory", root, "--arch", "arm64", "--json"})
	})
	if err != nil {
		t.Fatalf("validate UEFI media: %v", err)
	}
	var result secureboot.UEFIMediaValidation
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("decode UEFI validation: %v\n%s", err, output)
	}
	if !result.Valid || !result.FallbackFound || result.Architecture != "arm64" || len(result.Files) != 1 {
		t.Fatalf("unexpected UEFI validation: %#v", result)
	}
}

func TestUEFIValidateInvalidJSONPrecedesFailureStatus(t *testing.T) {
	output, err := captureCLIStdout(t, func() error {
		return runUEFIValidate([]string{"--directory", t.TempDir(), "--arch", "arm64", "--json"})
	})
	if err == nil || err.Error() != "UEFI media validation failed" {
		t.Fatalf("invalid media error = %v", err)
	}
	var result secureboot.UEFIMediaValidation
	if decodeErr := json.Unmarshal([]byte(output), &result); decodeErr != nil {
		t.Fatalf("decode invalid UEFI result: %v\n%s", decodeErr, output)
	}
	if result.Valid || len(result.Errors) == 0 {
		t.Fatalf("invalid media result = %#v", result)
	}
}

func TestUEFIValidateCommandValidation(t *testing.T) {
	if err := run([]string{"uefi"}); err == nil || err.Error() != "uefi requires validate" {
		t.Fatalf("missing UEFI subcommand error = %v", err)
	}
	if err := run([]string{"uefi", "unknown"}); err == nil || err.Error() != "unknown uefi command \"unknown\"" {
		t.Fatalf("unknown UEFI subcommand error = %v", err)
	}
	if err := runUEFIValidate(nil); err == nil || err.Error() != "--directory is required" {
		t.Fatalf("missing directory error = %v", err)
	}
	if err := runUEFIValidate([]string{"--directory", t.TempDir(), "--max-files", "0"}); err == nil || !strings.Contains(err.Error(), "greater than zero") {
		t.Fatalf("invalid max-files error = %v", err)
	}
	if err := runUEFIValidate([]string{"--directory", t.TempDir(), "--dbx", "/tmp/dbx", "--firmware"}); err == nil || !strings.Contains(err.Error(), "at most one") {
		t.Fatalf("conflicting DBX source error = %v", err)
	}
}

func TestResolveNativeUEFIArchitecture(t *testing.T) {
	got, err := resolveUEFIArchitecture("native")
	if err != nil {
		t.Fatal(err)
	}
	want := runtime.GOARCH
	if want == "loong64" {
		want = "loongarch64"
	}
	if got != want {
		t.Fatalf("native architecture = %q, want %q", got, want)
	}
}
'''
main_test = Path("cmd/rufus-linux/main_test.go")
main_test.write_text(main_test.read_text() + tests)

replace_once(
    "docs/rufusarm64-cli.1",
    '''.B rufusarm64-cli persistence plan
''',
    '''.B rufusarm64-cli uefi validate
.BI --directory " DIRECTORY"
.RI [ --arch " ARCH" ]
.RI [ --max-files " N" ]
.RI [ --require-fallback=true|false ]
.RI [ --dbx " FILE" | --firmware ]
.RI [ --json ]
.PP
.B rufusarm64-cli persistence plan
''',
)
replace_once(
    "docs/rufusarm64-cli.1",
    ".SH COMMON WRITE OPTIONS\n",
    '''.SH UEFI MEDIA VALIDATION
.B uefi validate
performs a bounded, descriptor-rooted, read-only scan of a mounted or extracted
UEFI media tree. It validates the architecture fallback loader, PE machine and
EFI subsystem fields, bounded SBAT metadata, and optional DBX image-hash and
embedded-certificate revocations. It does not modify firmware or media.
.TP
.BI --directory " DIRECTORY"
Select the mounted or extracted media root. Every directory and EFI executable
is opened relative to a retained descriptor with no-follow semantics.
.TP
.BI --arch " ARCH"
Select native, 386, amd64, arm, arm64, riscv64, or loongarch64. Native is the
default.
.TP
.BI --max-files " N"
Set the bounded EFI executable count. The default is 512 and the library safety
maximum remains 4096.
.TP
.B --require-fallback=true|false
Require the architecture removable-media fallback loader. The default is true.
.TP
.BI --dbx " FILE"
Apply a local DBXUpdate.bin or raw EFI signature-list file.
.TP
.B --firmware
Apply the running firmware DBX instead of a local file.
.PP
JSON output is emitted before an invalid-media failure status, allowing callers
to inspect the complete result while still relying on the process exit code.
.SH COMMON WRITE OPTIONS
''',
)

replace_once(
    "README.md",
    '''rufusarm64-cli acquire channel list --json
rufusarm64-cli persistence plan \\
''',
    '''rufusarm64-cli acquire channel list --json
rufusarm64-cli uefi validate --directory /mnt/usb --arch arm64 --json
rufusarm64-cli persistence plan \\
''',
)

replace_once(
    "scripts/test.sh",
    '''"${native_helper}" dbx inspect --file "${native_dir}/test.dbx" --json | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["sha256_hashes"] == 1 and d["signatures"] == 1'
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build''',
    '''"${native_helper}" dbx inspect --file "${native_dir}/test.dbx" --json | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["sha256_hashes"] == 1 and d["signatures"] == 1'
python3 - "${native_dir}/uefi-media/EFI/BOOT/BOOTAA64.EFI" <<'PYUEFI'
import os, struct, sys
path = sys.argv[1]
os.makedirs(os.path.dirname(path), exist_ok=True)
data = bytearray(0x400)
data[0:2] = b'MZ'
struct.pack_into('<I', data, 0x3c, 0x80)
data[0x80:0x84] = b'PE\\0\\0'
coff = 0x84
struct.pack_into('<H', data, coff, 0xaa64)
struct.pack_into('<H', data, coff + 2, 1)
struct.pack_into('<H', data, coff + 16, 0xf0)
optional = coff + 20
struct.pack_into('<H', data, optional, 0x20b)
struct.pack_into('<H', data, optional + 68, 10)
data[optional + 0xf0:optional + 0xf0 + 5] = b'.text'
open(path, 'wb').write(data)
PYUEFI
"${native_helper}" uefi validate --directory "${native_dir}/uefi-media" --arch arm64 --json | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["valid"] and d["fallback_found"] and d["architecture"] == "arm64"'
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build''',
)

parity_path = Path("docs/upstream-rufus-parity.json")
parity = json.loads(parity_path.read_text())
for feature in parity["features"]:
    if feature["id"] == "uefi-runtime-validation":
        feature["notes"] = "The 0.11 development line exposes descriptor-rooted CLI validation of fallback loaders, PE architecture and EFI subsystem fields, bounded SBAT metadata, and optional DBX hash/certificate revocations. Boot-chain reference resolution and trusted SBAT-level comparison remain planned."
        break
else:
    raise SystemExit("UEFI runtime validation parity entry was not found")
parity_path.write_text(json.dumps(parity, indent=2) + "\n")
