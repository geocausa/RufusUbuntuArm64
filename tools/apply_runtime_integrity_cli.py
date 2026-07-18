from pathlib import Path


def replace_once(path, old, new):
    file = Path(path)
    text = file.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one replacement, found {count}")
    file.write_text(text.replace(old, new, 1), encoding="utf-8")


main = "cmd/rufus-linux/main.go"
replace_once(main,
'''\t"github.com/geocausa/RufusArm64/internal/qualification"
\t"github.com/geocausa/RufusArm64/internal/safety"
''',
'''\t"github.com/geocausa/RufusArm64/internal/qualification"
\t"github.com/geocausa/RufusArm64/internal/runtimeintegrity"
\t"github.com/geocausa/RufusArm64/internal/safety"
''')
replace_once(main,
'''  rufusarm64-cli uefi validate --directory DIR [--arch ARCH] [--dbx FILE | --firmware] [--sbat-level FILE | --firmware-sbat] [--json]
''',
'''  rufusarm64-cli uefi validate --directory DIR [--arch ARCH] [--dbx FILE | --firmware] [--sbat-level FILE | --firmware-sbat] [--json]
  rufusarm64-cli uefi integrity manifest --directory DIR [--max-files N] [--json]
  rufusarm64-cli uefi integrity verify --directory DIR [--max-files N] [--json]
''')
replace_once(main,
'''func runUEFI(args []string) error {
\tif len(args) == 0 {
\t\treturn errors.New("uefi requires validate")
\t}
\tswitch args[0] {
\tcase "validate":
\t\treturn runUEFIValidate(args[1:])
\tdefault:
\t\treturn fmt.Errorf("unknown uefi command %q", args[0])
\t}
}

func resolveUEFIArchitecture''',
'''func runUEFI(args []string) error {
\tif len(args) == 0 {
\t\treturn errors.New("uefi requires validate or integrity")
\t}
\tswitch args[0] {
\tcase "validate":
\t\treturn runUEFIValidate(args[1:])
\tcase "integrity":
\t\treturn runUEFIIntegrity(args[1:])
\tdefault:
\t\treturn fmt.Errorf("unknown uefi command %q", args[0])
\t}
}

type runtimeIntegrityManifestOutput struct {
\tRoot       string                   `json:"root"`
\tManifest   string                   `json:"manifest"`
\tTotalBytes uint64                   `json:"total_bytes"`
\tEntries    []runtimeintegrity.Entry `json:"entries"`
}

func runUEFIIntegrity(args []string) error {
\tif len(args) == 0 {
\t\treturn errors.New("uefi integrity requires manifest or verify")
\t}
\tswitch args[0] {
\tcase "manifest":
\t\treturn runUEFIIntegrityManifest(args[1:])
\tcase "verify":
\t\treturn runUEFIIntegrityVerify(args[1:])
\tdefault:
\t\treturn fmt.Errorf("unknown uefi integrity command %q", args[0])
\t}
}

func parseRuntimeIntegrityFlags(name string, args []string) (*flag.FlagSet, *string, *int, *bool, error) {
\tfs := flag.NewFlagSet(name, flag.ContinueOnError)
\tdirectory := fs.String("directory", "", "mounted or materialized media root")
\tmaxFiles := fs.Int("max-files", runtimeintegrity.DefaultMaximumFiles, "maximum regular files to hash")
\tasJSON := fs.Bool("json", false, "output JSON")
\tif err := fs.Parse(args); err != nil {
\t\treturn nil, nil, nil, nil, err
\t}
\tif fs.NArg() != 0 {
\t\treturn nil, nil, nil, nil, fmt.Errorf("%s does not accept positional arguments", name)
\t}
\tif strings.TrimSpace(*directory) == "" {
\t\treturn nil, nil, nil, nil, errors.New("--directory is required")
\t}
\tif *maxFiles <= 0 || *maxFiles > runtimeintegrity.MaximumManifestLines {
\t\treturn nil, nil, nil, nil, fmt.Errorf("--max-files must be between 1 and %d", runtimeintegrity.MaximumManifestLines)
\t}
\treturn fs, directory, maxFiles, asJSON, nil
}

func resolvedIntegrityRoot(directory string) string {
\tabsolute, err := filepath.Abs(directory)
\tif err != nil {
\t\treturn directory
\t}
\tresolved, err := filepath.EvalSymlinks(absolute)
\tif err != nil {
\t\treturn absolute
\t}
\treturn resolved
}

func runUEFIIntegrityManifest(args []string) error {
\t_, directory, maxFiles, asJSON, err := parseRuntimeIntegrityFlags("uefi integrity manifest", args)
\tif err != nil {
\t\treturn err
\t}
\tctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
\tdefer cancel()
\tmanifest, err := runtimeintegrity.Generate(ctx, *directory, runtimeintegrity.Options{MaxFiles: *maxFiles})
\tif err != nil {
\t\treturn err
\t}
\tdata, err := manifest.MarshalText()
\tif err != nil {
\t\treturn err
\t}
\tif *asJSON {
\t\tencoder := json.NewEncoder(os.Stdout)
\t\tencoder.SetIndent("", "  ")
\t\treturn encoder.Encode(runtimeIntegrityManifestOutput{
\t\t\tRoot:       resolvedIntegrityRoot(*directory),
\t\t\tManifest:   string(data),
\t\t\tTotalBytes: manifest.TotalBytes,
\t\t\tEntries:    manifest.Entries,
\t\t})
\t}
\t_, err = os.Stdout.Write(data)
\treturn err
}

func runUEFIIntegrityVerify(args []string) error {
\t_, directory, maxFiles, asJSON, err := parseRuntimeIntegrityFlags("uefi integrity verify", args)
\tif err != nil {
\t\treturn err
\t}
\tctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
\tdefer cancel()
\tresult, err := runtimeintegrity.Verify(ctx, *directory, runtimeintegrity.Options{MaxFiles: *maxFiles})
\tif err != nil {
\t\treturn err
\t}
\tif *asJSON {
\t\tencoder := json.NewEncoder(os.Stdout)
\t\tencoder.SetIndent("", "  ")
\t\tif err := encoder.Encode(result); err != nil {
\t\t\treturn err
\t\t}
\t} else {
\t\tprintRuntimeIntegrityVerification(result)
\t}
\tif !result.Valid {
\t\treturn errors.New("runtime media integrity verification failed")
\t}
\treturn nil
}

func printRuntimeIntegrityVerification(result runtimeintegrity.VerificationResult) {
\tstatus := "VALID"
\tif !result.Valid {
\t\tstatus = "INVALID"
\t}
\tfmt.Printf("%s runtime media integrity\\n", status)
\tfmt.Printf("Root: %s\\nManifest: %s\\nDeclared bytes: %d\\nActual bytes: %d\\n", result.Root, result.ManifestPath, result.DeclaredTotalBytes, result.ActualTotalBytes)
\tfor _, file := range result.Files {
\t\tif file.Status == "ok" {
\t\t\tcontinue
\t\t}
\t\tfmt.Printf("%-10s %s", strings.ToUpper(file.Status), file.Path)
\t\tif file.Error != "" {
\t\t\tfmt.Printf(": %s", file.Error)
\t\t}
\t\tfmt.Println()
\t}
\tfor _, path := range result.Unexpected {
\t\tfmt.Printf("UNEXPECTED %s\\n", path)
\t}
\tfor _, verificationError := range result.Errors {
\t\tfmt.Printf("Error: %s\\n", verificationError)
\t}
}

func resolveUEFIArchitecture''')


test = "cmd/rufus-linux/main_test.go"
replace_once(test,
'''\t"github.com/geocausa/RufusArm64/internal/imaging"
\t"github.com/geocausa/RufusArm64/internal/secureboot"
''',
'''\t"github.com/geocausa/RufusArm64/internal/imaging"
\t"github.com/geocausa/RufusArm64/internal/runtimeintegrity"
\t"github.com/geocausa/RufusArm64/internal/secureboot"
''')
replace_once(test,
'''func TestHumanBytes(t *testing.T) {
''',
'''func captureStdout(t *testing.T, operation func() error) (string, error) {
\tt.Helper()
\told := os.Stdout
\treader, writer, err := os.Pipe()
\tif err != nil {
\t\tt.Fatal(err)
\t}
\tos.Stdout = writer
\tdefer func() { os.Stdout = old }()
\toperationErr := operation()
\tif err := writer.Close(); err != nil {
\t\tt.Fatal(err)
\t}
\tdata, readErr := io.ReadAll(reader)
\tif closeErr := reader.Close(); readErr == nil {
\t\treadErr = closeErr
\t}
\tif readErr != nil {
\t\tt.Fatal(readErr)
\t}
\treturn string(data), operationErr
}

func TestRuntimeIntegrityCLIManifestAndVerify(t *testing.T) {
\troot := t.TempDir()
\tif err := os.MkdirAll(filepath.Join(root, "EFI", "BOOT"), 0o755); err != nil {
\t\tt.Fatal(err)
\t}
\tloader := filepath.Join(root, "EFI", "BOOT", "BOOTAA64.EFI")
\tif err := os.WriteFile(loader, []byte("arm64 loader"), 0o644); err != nil {
\t\tt.Fatal(err)
\t}
\tif err := os.WriteFile(filepath.Join(root, "README"), []byte("media"), 0o644); err != nil {
\t\tt.Fatal(err)
\t}
\tplain, err := captureStdout(t, func() error {
\t\treturn runUEFIIntegrity([]string{"manifest", "--directory", root})
\t})
\tif err != nil {
\t\tt.Fatalf("manifest command: %v", err)
\t}
\tmanifest, err := runtimeintegrity.Parse([]byte(plain))
\tif err != nil || len(manifest.Entries) != 2 {
\t\tt.Fatalf("parse generated manifest: entries=%d err=%v", len(manifest.Entries), err)
\t}
\tif _, err := os.Stat(filepath.Join(root, runtimeintegrity.ManifestName)); !os.IsNotExist(err) {
\t\tt.Fatalf("manifest command unexpectedly wrote to the media tree: %v", err)
\t}
\tjsonText, err := captureStdout(t, func() error {
\t\treturn runUEFIIntegrity([]string{"manifest", "--directory", root, "--json"})
\t})
\tif err != nil {
\t\tt.Fatal(err)
\t}
\tvar generated runtimeIntegrityManifestOutput
\tif err := json.Unmarshal([]byte(jsonText), &generated); err != nil {
\t\tt.Fatal(err)
\t}
\tif generated.Manifest != plain || generated.TotalBytes != manifest.TotalBytes || len(generated.Entries) != 2 {
\t\tt.Fatalf("unexpected JSON manifest output: %#v", generated)
\t}
\tif err := os.WriteFile(filepath.Join(root, runtimeintegrity.ManifestName), []byte(plain), 0o644); err != nil {
\t\tt.Fatal(err)
\t}
\tverified, err := captureStdout(t, func() error {
\t\treturn runUEFIIntegrity([]string{"verify", "--directory", root, "--json"})
\t})
\tif err != nil {
\t\tt.Fatalf("verify command: %v", err)
\t}
\tvar result runtimeintegrity.VerificationResult
\tif err := json.Unmarshal([]byte(verified), &result); err != nil || !result.Valid {
\t\tt.Fatalf("valid verification result=%#v err=%v", result, err)
\t}
\tif err := os.WriteFile(loader, []byte("changed loader"), 0o644); err != nil {
\t\tt.Fatal(err)
\t}
\tinvalid, err := captureStdout(t, func() error {
\t\treturn runUEFIIntegrity([]string{"verify", "--directory", root, "--json"})
\t})
\tif err == nil || !strings.Contains(err.Error(), "verification failed") {
\t\tt.Fatalf("invalid verification error = %v", err)
\t}
\tif err := json.Unmarshal([]byte(invalid), &result); err != nil || result.Valid {
\t\tt.Fatalf("invalid JSON result=%#v err=%v", result, err)
\t}
\tchanged := false
\tfor _, file := range result.Files {
\t\tchanged = changed || file.Status == "changed"
\t}
\tif !changed {
\t\tt.Fatalf("changed file was not reported: %#v", result.Files)
\t}
}

func TestRuntimeIntegrityCLIRejectsInvalidArguments(t *testing.T) {
\tfor _, args := range [][]string{
\t\t{"manifest"},
\t\t{"verify", "--directory", t.TempDir(), "unexpected"},
\t\t{"manifest", "--directory", t.TempDir(), "--max-files", "0"},
\t\t{"manifest", "--directory", t.TempDir(), "--max-files", "100001"},
\t} {
\t\tif err := runUEFIIntegrity(args); err == nil {
\t\t\tt.Fatalf("invalid arguments accepted: %v", args)
\t\t}
\t}
}

func TestHumanBytes(t *testing.T) {
''')

man = "docs/rufusarm64-cli.1"
replace_once(man,
'''.RI [ --json ]
.PP
.B rufusarm64-cli persistence plan
''',
'''.RI [ --json ]
.PP
.B rufusarm64-cli uefi integrity manifest
.BI --directory " DIRECTORY"
.RI [ --max-files " N" ]
.RI [ --json ]
.PP
.B rufusarm64-cli uefi integrity verify
.BI --directory " DIRECTORY"
.RI [ --max-files " N" ]
.RI [ --json ]
.PP
.B rufusarm64-cli persistence plan
''')
replace_once(man,
'''.PP
JSON output is emitted before an invalid-media failure status, allowing callers
to inspect the complete result while still relying on the process exit code.
.SH COMMON WRITE OPTIONS
''',
'''.PP
JSON output is emitted before an invalid-media failure status, allowing callers
to inspect the complete result while still relying on the process exit code.
.SH UEFI RUNTIME MEDIA INTEGRITY MANIFESTS
.B uefi integrity manifest
performs a descriptor-rooted read-only scan and writes exact uefi-md5sum-compatible
manifest text to standard output. It never writes the media tree. With
.B --json
it emits the same manifest text, total byte count, and ordered records in a
structured document.
.PP
.B uefi integrity verify
reads the exact root
.B md5sum.txt
and reports changed, missing, unexpected, and total-byte mismatches. JSON is
emitted before a non-zero invalid-media status. The default and maximum file
limit is 100000; manifest size is bounded to 64 MiB and paths to 512 bytes.
.PP
These commands are unprivileged. They do not mount images, open block devices,
invoke Polkit, access firmware, or install a bootloader. MD5 is used solely for
interoperability with the upstream boot-time validator; RufusArm64 continues to
use SHA-256 for source identity, downloads, and destructive-write assurance.
.SH COMMON WRITE OPTIONS
''')

readme = "README.md"
replace_once(readme,
'''rufusarm64-cli uefi validate --directory /mnt/usb --arch arm64 --firmware-sbat --json
''',
'''rufusarm64-cli uefi validate --directory /mnt/usb --arch arm64 --firmware-sbat --json
rufusarm64-cli uefi integrity manifest --directory /mnt/usb > md5sum.txt
rufusarm64-cli uefi integrity verify --directory /mnt/usb --json
''')
replace_once(readme,
'''That pre-boot structural/Secure Boot analysis is separate from Rufus's boot-time media-integrity option. The 0.11 development line now includes the descriptor-safe `uefi-md5sum` manifest foundation; it does not yet replace or chainload the media fallback loader.
''',
'''That pre-boot structural/Secure Boot analysis is separate from Rufus's boot-time media-integrity option. The 0.11 development line includes descriptor-safe `uefi-md5sum` manifest generation and verification through the unprivileged CLI; it does not yet replace or chainload the media fallback loader.
''')

ci = ".github/workflows/ci.yml"
replace_once(ci,
'''          test "$("${package_root}/usr/lib/rufusarm64/rufusarm64-persistence-helper" --help 2>&1 || true)" != ""
          "${package_root}/usr/lib/rufusarm64/wimlib-imagex" --version
''',
'''          test "$("${package_root}/usr/lib/rufusarm64/rufusarm64-persistence-helper" --help 2>&1 || true)" != ""
          integrity_root="$(mktemp -d)"
          mkdir -p "${integrity_root}/EFI/BOOT"
          printf 'packaged arm64 loader' > "${integrity_root}/EFI/BOOT/BOOTAA64.EFI"
          "${package_root}/usr/lib/rufusarm64/rufusarm64-helper" uefi integrity manifest \\
            --directory "${integrity_root}" > "${integrity_root}/md5sum.txt"
          "${package_root}/usr/lib/rufusarm64/rufusarm64-helper" uefi integrity verify \\
            --directory "${integrity_root}" --json >/dev/null
          rm -rf "${integrity_root}"
          "${package_root}/usr/lib/rufusarm64/wimlib-imagex" --version
''')
