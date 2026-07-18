from pathlib import Path


def replace_exact(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one anchor, found {count}")
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


runtime_source = r'''//go:build linux

package linuxmedia

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/geocausa/RufusArm64/internal/runtimeintegrity"
	"github.com/geocausa/RufusArm64/internal/secureboot"
	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

const persistentRuntimeMaximumLoaderSize = int64(32 * 1024 * 1024)

// RuntimeIntegrityResult reports the exact installed boot-time media validation
// state. SecureBootCompatible is disclosure metadata and is false for the
// current reproducibly built upstream loader.
type RuntimeIntegrityResult struct {
	OriginalSHA256      string `json:"original_sha256"`
	WrapperSHA256       string `json:"wrapper_sha256"`
	ManifestSHA256      string `json:"manifest_sha256"`
	SourceCommit        string `json:"source_commit"`
	SecureBootCompatible bool   `json:"secure_boot_compatible"`
	VerificationValid   bool   `json:"verification_valid"`
}

type preparedPersistentRuntimeIntegrity struct {
	asset runtimeintegrity.LoaderAsset
}

func preparePersistentRuntimeIntegrity(ctx context.Context, opts PersistentCreateOptions) (*preparedPersistentRuntimeIntegrity, error) {
	if !opts.RuntimeUEFIValidation {
		return nil, nil
	}
	if ctx == nil {
		return nil, errors.New("runtime UEFI validation context is nil")
	}
	architecture := strings.ToLower(strings.TrimSpace(opts.Architecture))
	if architecture != "arm64" && architecture != "aarch64" {
		return nil, fmt.Errorf("runtime UEFI validation requires ARM64 media, not %q", opts.Architecture)
	}
	if !opts.RuntimeUEFIUnsignedAcknowledged {
		return nil, errors.New("runtime UEFI validation requires explicit acknowledgement that the current loader is unsigned")
	}
	path := strings.TrimSpace(opts.RuntimeUEFILoaderPath)
	if path == "" {
		return nil, errors.New("runtime UEFI validation requires an exact loader path")
	}
	expected := strings.ToLower(strings.TrimSpace(opts.RuntimeUEFILoaderSHA256))
	decoded, err := hex.DecodeString(expected)
	if err != nil || len(decoded) != sha256.Size {
		return nil, errors.New("runtime UEFI loader SHA-256 is invalid")
	}
	sourceCommit := strings.TrimSpace(opts.RuntimeUEFILoaderSourceCommit)
	provenance := strings.TrimSpace(opts.RuntimeUEFILoaderProvenance)
	if sourceCommit == "" || provenance == "" {
		return nil, errors.New("runtime UEFI loader source commit and provenance are required")
	}
	_, identity, err := sourcefile.Inspect(path)
	if err != nil {
		return nil, fmt.Errorf("inspect runtime UEFI loader: %w", err)
	}
	if identity.Size <= 0 || identity.Size > persistentRuntimeMaximumLoaderSize {
		return nil, fmt.Errorf("runtime UEFI loader must be between 1 and %d bytes", persistentRuntimeMaximumLoaderSize)
	}
	file, err := sourcefile.OpenRegular(path, identity)
	if err != nil {
		return nil, fmt.Errorf("open runtime UEFI loader: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, persistentRuntimeMaximumLoaderSize+1))
	if err != nil {
		return nil, fmt.Errorf("read runtime UEFI loader: %w", err)
	}
	if int64(len(data)) != identity.Size {
		return nil, errors.New("runtime UEFI loader changed while it was being read")
	}
	if err := sourcefile.VerifyPinned(file, identity); err != nil {
		return nil, fmt.Errorf("revalidate runtime UEFI loader: %w", err)
	}
	digest := sha256.Sum256(data)
	actual := hex.EncodeToString(digest[:])
	if actual != expected {
		return nil, fmt.Errorf("runtime UEFI loader SHA-256 is %s, expected %s", actual, expected)
	}
	image, err := secureboot.InspectEFIImage(data)
	if err != nil {
		return nil, fmt.Errorf("inspect runtime UEFI loader PE image: %w", err)
	}
	if image.Machine != secureboot.MachineARM64 || image.Subsystem != secureboot.SubsystemEFIApplication {
		return nil, fmt.Errorf("runtime UEFI loader is %s/%s, expected ARM64 EFI application", image.MachineName, image.SubsystemName)
	}
	return &preparedPersistentRuntimeIntegrity{asset: runtimeintegrity.LoaderAsset{
		Data:                 data,
		ExpectedSHA256:       expected,
		SourceCommit:         sourceCommit,
		Provenance:           provenance,
		SecureBootCompatible: false,
	}}, nil
}

func hashPersistentRuntimeFallback(ctx context.Context, root string) (string, error) {
	path := filepath.Join(root, filepath.FromSlash(runtimeintegrity.ARM64FallbackPath))
	_, identity, err := sourcefile.Inspect(path)
	if err != nil {
		return "", fmt.Errorf("inspect original ARM64 fallback loader: %w", err)
	}
	file, err := sourcefile.OpenRegular(path, identity)
	if err != nil {
		return "", fmt.Errorf("open original ARM64 fallback loader: %w", err)
	}
	defer file.Close()
	digest, err := sourcefile.SHA256Open(ctx, file, nil)
	if err != nil {
		return "", fmt.Errorf("hash original ARM64 fallback loader: %w", err)
	}
	if err := sourcefile.VerifyPinned(file, identity); err != nil {
		return "", fmt.Errorf("revalidate original ARM64 fallback loader: %w", err)
	}
	return hex.EncodeToString(digest[:]), nil
}

func installPersistentRuntimeIntegrity(ctx context.Context, root string, prepared *preparedPersistentRuntimeIntegrity, maxFiles int) (runtimeintegrity.InstallResult, error) {
	if prepared == nil {
		return runtimeintegrity.InstallResult{}, errors.New("runtime UEFI validation was not prepared")
	}
	return runtimeintegrity.InstallARM64(ctx, root, prepared.asset, runtimeintegrity.TransactionOptions{MaxFiles: maxFiles})
}
'''
Path("internal/linuxmedia/runtime_integrity.go").write_text(runtime_source, encoding="utf-8")

replace_exact(
    "internal/linuxmedia/create.go",
    '''\tCreatorVersion     string\n}\n\ntype PersistentCreateResult struct {\n''',
    '''\tCreatorVersion                       string\n\tRuntimeUEFIValidation                bool\n\tRuntimeUEFILoaderPath                string\n\tRuntimeUEFILoaderSHA256              string\n\tRuntimeUEFILoaderSourceCommit        string\n\tRuntimeUEFILoaderProvenance          string\n\tRuntimeUEFIUnsignedAcknowledged      bool\n}\n\ntype PersistentCreateResult struct {\n''',
)
replace_exact(
    "internal/linuxmedia/create.go",
    '''\tQualificationRecordSHA256 string                `json:"qualification_record_sha256"`\n}\n''',
    '''\tQualificationRecordSHA256 string                  `json:"qualification_record_sha256"`\n\tRuntimeIntegrity          *RuntimeIntegrityResult `json:"runtime_integrity,omitempty"`\n}\n''',
)
replace_exact(
    "internal/linuxmedia/create.go",
    '''\tsourceDigest, err := hashPersistentSource(ctx, isoFile, opts.ExpectedSource, emit, "hash_source", "Hashing the selected Linux image…")\n\tif err != nil {\n\t\treturn result, fmt.Errorf("hash selected Linux image: %w", err)\n\t}\n\tfor _, name := range []string{"mount", "umount", "findmnt", "lsblk", "wipefs", "sync", "blockdev", "mkfs.vfat", "fsck.vfat", "mkfs.ext4", "e2fsck"} {\n''',
    '''\tsourceDigest, err := hashPersistentSource(ctx, isoFile, opts.ExpectedSource, emit, "hash_source", "Hashing the selected Linux image…")\n\tif err != nil {\n\t\treturn result, fmt.Errorf("hash selected Linux image: %w", err)\n\t}\n\tpreparedRuntimeIntegrity, err := preparePersistentRuntimeIntegrity(ctx, opts)\n\tif err != nil {\n\t\treturn result, fmt.Errorf("prepare runtime UEFI media validation: %w", err)\n\t}\n\tfor _, name := range []string{"mount", "umount", "findmnt", "lsblk", "wipefs", "sync", "blockdev", "mkfs.vfat", "fsck.vfat", "mkfs.ext4", "e2fsck"} {\n''',
)
replace_exact(
    "internal/linuxmedia/create.go",
    '''\tcreator := strings.TrimSpace(opts.CreatorVersion)\n\tif creator == "" {\n\t\tcreator = "RufusArm64"\n\t}\n\trecord, err := qualification.WriteRecord(destinationRoot, qualification.CreationRecord{\n''',
    '''\tcreator := strings.TrimSpace(opts.CreatorVersion)\n\tif creator == "" {\n\t\tcreator = "RufusArm64"\n\t}\n\tproperties := map[string]string{\n\t\t"qualification_contract": "start-reboot-verify",\n\t}\n\tif preparedRuntimeIntegrity != nil {\n\t\toriginalSHA256, err := hashPersistentRuntimeFallback(ctx, destinationRoot)\n\t\tif err != nil {\n\t\t\treturn result, err\n\t\t}\n\t\tproperties["runtime_uefi_validation"] = "enabled"\n\t\tproperties["runtime_uefi_original_sha256"] = originalSHA256\n\t\tproperties["runtime_uefi_wrapper_sha256"] = preparedRuntimeIntegrity.asset.ExpectedSHA256\n\t\tproperties["runtime_uefi_source_commit"] = preparedRuntimeIntegrity.asset.SourceCommit\n\t\tproperties["runtime_uefi_secure_boot_compatible"] = "false"\n\t}\n\trecord, err := qualification.WriteRecord(destinationRoot, qualification.CreationRecord{\n''',
)
replace_exact(
    "internal/linuxmedia/create.go",
    '''\t\tProperties: map[string]string{\n\t\t\t"qualification_contract": "start-reboot-verify",\n\t\t},\n\t})\n''',
    '''\t\tProperties:      properties,\n\t})\n''',
)
replace_exact(
    "internal/linuxmedia/create.go",
    '''\tresult.QualificationRecordPath = record.Path\n\tresult.QualificationRecordSHA256 = record.SHA256\n\tsendPersistent(emit, PersistentEvent{Stage: "qualification", Message: "Stored the persistence qualification record", Path: record.Path})\n\tif err := runPersistent(ctx, emit, "sync", "-f", destinationRoot); err != nil {\n''',
    '''\tresult.QualificationRecordPath = record.Path\n\tresult.QualificationRecordSHA256 = record.SHA256\n\tsendPersistent(emit, PersistentEvent{Stage: "qualification", Message: "Stored the persistence qualification record", Path: record.Path})\n\tif preparedRuntimeIntegrity != nil {\n\t\tsendPersistent(emit, PersistentEvent{Stage: "runtime_integrity", Message: "Installing the unsigned ARM64 runtime media validator transactionally…"})\n\t\tinstalled, err := installPersistentRuntimeIntegrity(ctx, destinationRoot, preparedRuntimeIntegrity, opts.ManifestMaxEntries)\n\t\tif err != nil {\n\t\t\treturn result, fmt.Errorf("install runtime UEFI media validation: %w", err)\n\t\t}\n\t\tresult.RuntimeIntegrity = &RuntimeIntegrityResult{\n\t\t\tOriginalSHA256:        installed.Record.OriginalSHA256,\n\t\t\tWrapperSHA256:         installed.Record.WrapperSHA256,\n\t\t\tManifestSHA256:        installed.ManifestSHA256,\n\t\t\tSourceCommit:          installed.Record.WrapperSourceCommit,\n\t\t\tSecureBootCompatible: installed.Record.WrapperSecureBootCompatible,\n\t\t\tVerificationValid:     installed.Verification.Valid,\n\t\t}\n\t\tsendPersistent(emit, PersistentEvent{Stage: "runtime_integrity_verify", Message: "Verified the boot-time media manifest and ARM64 chainload wrapper", Path: "md5sum.txt"})\n\t}\n\tif err := runPersistent(ctx, emit, "sync", "-f", destinationRoot); err != nil {\n''',
)

replace_exact(
    "cmd/rufus-persistence-helper/main.go",
    '''var version = "development"\n''',
    '''var version = "development"\n\nconst (\n\tpackagedRuntimeUEFILoaderPath       = "/usr/lib/rufusarm64/bootaa64-uefi-md5sum.efi"\n\tpackagedRuntimeUEFILoaderSHA256     = "543615a8e97fed1cb5293bee7bdfe10f9feb6979f191b20ab32dafdcf097b502"\n\tpackagedRuntimeUEFILoaderCommit     = "6195f2ef754c2ad390bda6590628708f410d55f6"\n\tpackagedRuntimeUEFILoaderProvenance = "reproducible upstream uefi-md5sum v1.2 ARM64 build; unsigned"\n)\n''',
)
replace_exact(
    "cmd/rufus-persistence-helper/main.go",
    '''\tyes := flags.Bool("yes", false, "confirm the graphical application already obtained explicit erase consent")\n''',
    '''\tyes := flags.Bool("yes", false, "confirm the graphical application already obtained explicit erase consent")\n\truntimeUEFIValidation := flags.Bool("runtime-uefi-validation", false, "install the package-owned unsigned ARM64 boot-time media validator")\n''',
)
replace_exact(
    "cmd/rufus-persistence-helper/main.go",
    '''\t\tCreatorVersion:    "RufusArm64 " + version,\n\t\tBeforeDestructive: targetCheck,\n''',
    '''\t\tCreatorVersion:                    "RufusArm64 " + version,\n\t\tBeforeDestructive:                  targetCheck,\n\t\tRuntimeUEFIValidation:              *runtimeUEFIValidation,\n\t\tRuntimeUEFILoaderPath:              packagedRuntimeUEFILoaderPath,\n\t\tRuntimeUEFILoaderSHA256:            packagedRuntimeUEFILoaderSHA256,\n\t\tRuntimeUEFILoaderSourceCommit:      packagedRuntimeUEFILoaderCommit,\n\t\tRuntimeUEFILoaderProvenance:        packagedRuntimeUEFILoaderProvenance,\n\t\tRuntimeUEFIUnsignedAcknowledged:    *runtimeUEFIValidation,\n''',
)
replace_exact(
    "cmd/rufus-persistence-helper/main.go",
    '''\tif err := safety.RereadPartitionTable(resolvedTarget); err != nil {\n''',
    '''\tif result.RuntimeIntegrity != nil {\n\t\tout.event(jsonEvent{\n\t\t\tEvent:   "log",\n\t\t\tStage:   "runtime_integrity",\n\t\t\tMessage: fmt.Sprintf("Runtime UEFI media validation installed and verified; manifest SHA-256 %s. The loader is unsigned and is not Secure Boot compatible.", result.RuntimeIntegrity.ManifestSHA256),\n\t\t\tHash:    result.RuntimeIntegrity.ManifestSHA256,\n\t\t})\n\t}\n\tif err := safety.RereadPartitionTable(resolvedTarget); err != nil {\n''',
)

replace_exact(
    "internal/linuxmedia/create_test.go",
    '''import (\n\t"context"\n\t"os"\n\t"path/filepath"\n\t"strings"\n\t"testing"\n\n\t"github.com/geocausa/RufusArm64/internal/qualification"\n\t"github.com/geocausa/RufusArm64/internal/sourcefile"\n)\n''',
    '''import (\n\t"bytes"\n\t"context"\n\t"crypto/sha256"\n\t"encoding/binary"\n\t"fmt"\n\t"os"\n\t"path/filepath"\n\t"strings"\n\t"testing"\n\n\t"github.com/geocausa/RufusArm64/internal/qualification"\n\t"github.com/geocausa/RufusArm64/internal/runtimeintegrity"\n\t"github.com/geocausa/RufusArm64/internal/sourcefile"\n)\n''',
)
replace_exact(
    "internal/linuxmedia/create_test.go",
    '''\twriteLinuxTestFile(t, filepath.Join(isoRoot, "EFI", "BOOT", "BOOTAA64.EFI"), "efi")\n\twriteLinuxTestFile(t, filepath.Join(isoRoot, "boot", "grub", "grub.cfg"), "linux /casper/vmlinuz boot=casper --- quiet\\n")\n''',
    '''\toriginalLoader := linuxTestARM64EFI(0x11)\n\twriteLinuxTestBytes(t, filepath.Join(isoRoot, "EFI", "BOOT", "BOOTAA64.EFI"), originalLoader)\n\twriteLinuxTestFile(t, filepath.Join(isoRoot, "boot", "grub", "grub.cfg"), "linux /casper/vmlinuz boot=casper --- quiet\\n")\n\twrapperLoader := linuxTestARM64EFI(0x22)\n\twrapperPath := filepath.Join(t.TempDir(), "bootaa64.efi")\n\twriteLinuxTestBytes(t, wrapperPath, wrapperLoader)\n\twrapperDigest := sha256.Sum256(wrapperLoader)\n''',
)
replace_exact(
    "internal/linuxmedia/create_test.go",
    '''\t\tCreatorVersion:  "RufusArm64 test",\n\t}, func(event PersistentEvent) { stages = append(stages, event.Stage) })\n''',
    '''\t\tCreatorVersion:                    "RufusArm64 test",\n\t\tRuntimeUEFIValidation:              true,\n\t\tRuntimeUEFILoaderPath:              wrapperPath,\n\t\tRuntimeUEFILoaderSHA256:            fmt.Sprintf("%x", wrapperDigest[:]),\n\t\tRuntimeUEFILoaderSourceCommit:      "6195f2ef754c2ad390bda6590628708f410d55f6",\n\t\tRuntimeUEFILoaderProvenance:        "test reproducible unsigned loader",\n\t\tRuntimeUEFIUnsignedAcknowledged:    true,\n\t}, func(event PersistentEvent) { stages = append(stages, event.Stage) })\n''',
)
replace_exact(
    "internal/linuxmedia/create_test.go",
    '''\tif result.Layout.Persistence.SizeBytes != minimumPersistence || len(result.PatchedPaths) != 1 {\n\t\tt.Fatalf("unexpected result: %#v", result)\n\t}\n''',
    '''\tif result.Layout.Persistence.SizeBytes != minimumPersistence || len(result.PatchedPaths) != 1 {\n\t\tt.Fatalf("unexpected result: %#v", result)\n\t}\n\tif result.RuntimeIntegrity == nil || !result.RuntimeIntegrity.VerificationValid || result.RuntimeIntegrity.SecureBootCompatible {\n\t\tt.Fatalf("runtime integrity result = %#v", result.RuntimeIntegrity)\n\t}\n\tactiveLoader, err := os.ReadFile(filepath.Join(bootRoot, filepath.FromSlash(runtimeintegrity.ARM64FallbackPath)))\n\tif err != nil || !bytes.Equal(activeLoader, wrapperLoader) {\n\t\tt.Fatalf("active runtime loader mismatch: err=%v", err)\n\t}\n\tbackedUpLoader, err := os.ReadFile(filepath.Join(bootRoot, filepath.FromSlash(runtimeintegrity.ARM64OriginalPath)))\n\tif err != nil || !bytes.Equal(backedUpLoader, originalLoader) {\n\t\tt.Fatalf("backed-up fallback mismatch: err=%v", err)\n\t}\n\tverification, err := runtimeintegrity.Verify(context.Background(), bootRoot, runtimeintegrity.Options{})\n\tif err != nil || !verification.Valid {\n\t\tt.Fatalf("runtime integrity verification = %#v err=%v", verification, err)\n\t}\n''',
)
replace_exact(
    "internal/linuxmedia/create_test.go",
    '''\tif record.Record.Creator != "RufusArm64 test" || record.Record.SourceSize != uint64(identity.Size) || record.Record.Persistence.Label != "casper-rw" {\n\t\tt.Fatalf("qualification record = %#v", record.Record)\n\t}\n''',
    '''\tif record.Record.Creator != "RufusArm64 test" || record.Record.SourceSize != uint64(identity.Size) || record.Record.Persistence.Label != "casper-rw" {\n\t\tt.Fatalf("qualification record = %#v", record.Record)\n\t}\n\tif record.Record.Properties["runtime_uefi_validation"] != "enabled" || record.Record.Properties["runtime_uefi_wrapper_sha256"] != result.RuntimeIntegrity.WrapperSHA256 || record.Record.Properties["runtime_uefi_secure_boot_compatible"] != "false" {\n\t\tt.Fatalf("runtime integrity qualification properties = %#v", record.Record.Properties)\n\t}\n''',
)
replace_exact(
    "internal/linuxmedia/create_test.go",
    '''func writeLinuxTestFile(t *testing.T, path, content string) {\n\tt.Helper()\n\tif err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {\n\t\tt.Fatal(err)\n\t}\n\tif err := os.WriteFile(path, []byte(content), 0o644); err != nil {\n\t\tt.Fatal(err)\n\t}\n}\n''',
    '''func writeLinuxTestFile(t *testing.T, path, content string) {\n\tt.Helper()\n\twriteLinuxTestBytes(t, path, []byte(content))\n}\n\nfunc writeLinuxTestBytes(t *testing.T, path string, content []byte) {\n\tt.Helper()\n\tif err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {\n\t\tt.Fatal(err)\n\t}\n\tif err := os.WriteFile(path, content, 0o644); err != nil {\n\t\tt.Fatal(err)\n\t}\n}\n\nfunc linuxTestARM64EFI(marker byte) []byte {\n\tdata := make([]byte, 512)\n\tdata[0], data[1] = 'M', 'Z'\n\tbinary.LittleEndian.PutUint32(data[0x3c:0x40], 0x80)\n\tcopy(data[0x80:0x84], []byte{'P', 'E', 0, 0})\n\tcoff := 0x84\n\tbinary.LittleEndian.PutUint16(data[coff:coff+2], 0xaa64)\n\tbinary.LittleEndian.PutUint16(data[coff+16:coff+18], 0xf0)\n\toptional := coff + 20\n\tbinary.LittleEndian.PutUint16(data[optional:optional+2], 0x20b)\n\tbinary.LittleEndian.PutUint16(data[optional+68:optional+70], 10)\n\tdata[len(data)-1] = marker\n\treturn data\n}\n''',
)
Path("internal/linuxmedia/create_test.go").write_text(
    Path("internal/linuxmedia/create_test.go").read_text(encoding="utf-8")
    + r'''

func TestCreatePersistentRejectsRuntimeLoaderBeforeTargetMutation(t *testing.T) {
	isoPath := filepath.Join(t.TempDir(), "ubuntu.iso")
	writeLinuxTestFile(t, isoPath, "pinned-image")
	_, identity, err := sourcefile.Inspect(isoPath)
	if err != nil {
		t.Fatal(err)
	}
	loaderPath := filepath.Join(t.TempDir(), "bootaa64.efi")
	writeLinuxTestBytes(t, loaderPath, linuxTestARM64EFI(0x33))
	targetPath := filepath.Join(t.TempDir(), "target.img")
	writeLinuxTestFile(t, targetPath, "unchanged-target")
	before, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = CreatePersistent(context.Background(), isoPath, targetPath, PersistentCreateOptions{
		ExpectedSource:                    identity,
		Architecture:                      "arm64",
		RuntimeUEFIValidation:              true,
		RuntimeUEFILoaderPath:              loaderPath,
		RuntimeUEFILoaderSHA256:            strings.Repeat("0", 64),
		RuntimeUEFILoaderSourceCommit:      "6195f2ef754c2ad390bda6590628708f410d55f6",
		RuntimeUEFILoaderProvenance:        "test provenance",
		RuntimeUEFIUnsignedAcknowledged:    true,
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "loader SHA-256") {
		t.Fatalf("wrong loader digest error = %v", err)
	}
	after, readErr := os.ReadFile(targetPath)
	if readErr != nil || !bytes.Equal(before, after) {
		t.Fatalf("target changed before loader refusal: err=%v", readErr)
	}
}

func TestCreatePersistentRejectsRuntimeValidationOnNonARM64(t *testing.T) {
	isoPath := filepath.Join(t.TempDir(), "ubuntu.iso")
	writeLinuxTestFile(t, isoPath, "pinned-image")
	_, identity, err := sourcefile.Inspect(isoPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = CreatePersistent(context.Background(), isoPath, filepath.Join(t.TempDir(), "target.img"), PersistentCreateOptions{
		ExpectedSource:                 identity,
		Architecture:                   "amd64",
		RuntimeUEFIValidation:           true,
		RuntimeUEFIUnsignedAcknowledged: true,
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "requires ARM64") {
		t.Fatalf("non-ARM64 runtime validation error = %v", err)
	}
}
''',
    encoding="utf-8",
)

Path("cmd/rufus-persistence-helper/main_test.go").write_text(
    Path("cmd/rufus-persistence-helper/main_test.go").read_text(encoding="utf-8")
    + r'''

func TestPackagedRuntimeUEFILoaderContract(t *testing.T) {
	if packagedRuntimeUEFILoaderPath != "/usr/lib/rufusarm64/bootaa64-uefi-md5sum.efi" {
		t.Fatalf("loader path = %q", packagedRuntimeUEFILoaderPath)
	}
	if packagedRuntimeUEFILoaderSHA256 != "543615a8e97fed1cb5293bee7bdfe10f9feb6979f191b20ab32dafdcf097b502" {
		t.Fatalf("loader digest = %q", packagedRuntimeUEFILoaderSHA256)
	}
	if !strings.Contains(packagedRuntimeUEFILoaderProvenance, "unsigned") {
		t.Fatalf("loader provenance must disclose unsigned status: %q", packagedRuntimeUEFILoaderProvenance)
	}
}
''',
    encoding="utf-8",
)

replace_exact(
    "scripts/build-deb.sh",
    '''install -Dm644 "${ROOT_DIR}/vendor/wimlib/arm64/wimlib-imagex.sha256" \\\n  "${PACKAGE_DIR}/usr/share/doc/rufusarm64/wimlib/wimlib-imagex.sha256"\n\n# Include Rufus 4.15's pinned, multi-architecture UEFI:NTFS FAT image.\n''',
    '''install -Dm644 "${ROOT_DIR}/vendor/wimlib/arm64/wimlib-imagex.sha256" \\\n  "${PACKAGE_DIR}/usr/share/doc/rufusarm64/wimlib/wimlib-imagex.sha256"\n\n# Include the independently reproduced upstream ARM64 uefi-md5sum loader. It is\n# unsigned and package-private; the writer must disclose that state explicitly.\nUEFI_MD5SUM_DIR="${UEFI_MD5SUM_DIR:-${ROOT_DIR}/vendor/uefi-md5sum/arm64}"\nUEFI_MD5SUM_SHA256="543615a8e97fed1cb5293bee7bdfe10f9feb6979f191b20ab32dafdcf097b502"\nfor file in bootaa64.efi bootaa64.efi.sha256 provenance.json SOURCE-COMMITS.txt \\\n  REPRODUCIBILITY.txt uefi-md5sum-v1.2-source.tar.gz uefi-md5sum-v1.2-source.tar.gz.sha256; do\n  [[ -f "${UEFI_MD5SUM_DIR}/${file}" ]] || {\n    echo "Missing reproduced ARM64 uefi-md5sum artifact: ${file}" >&2\n    exit 1\n  }\ndone\nactual_md5sum_hash="$(sha256sum "${UEFI_MD5SUM_DIR}/bootaa64.efi" | awk '{print $1}')"\n[[ "${actual_md5sum_hash}" == "${UEFI_MD5SUM_SHA256}" ]] || {\n  echo "Refusing modified ARM64 uefi-md5sum loader: ${actual_md5sum_hash}" >&2\n  exit 1\n}\n[[ "$(stat -c %s "${UEFI_MD5SUM_DIR}/bootaa64.efi")" -eq 40960 ]] || {\n  echo "Unexpected ARM64 uefi-md5sum loader size" >&2\n  exit 1\n}\n(\n  cd "${UEFI_MD5SUM_DIR}"\n  sha256sum -c bootaa64.efi.sha256\n  sha256sum -c uefi-md5sum-v1.2-source.tar.gz.sha256\n)\npython3 - "${UEFI_MD5SUM_DIR}/provenance.json" <<'PYUEFIMD5'\nimport json, sys\nwith open(sys.argv[1], encoding="utf-8") as handle:\n    data = json.load(handle)\nartifact = data["artifact"]\nassert artifact["sha256"] == "543615a8e97fed1cb5293bee7bdfe10f9feb6979f191b20ab32dafdcf097b502"\nassert artifact["size"] == 40960\nassert artifact["pe"]["machine"] == 0xAA64\nassert artifact["pe"]["subsystem"] == 10\nassert artifact["authenticode"]["present"] is False\nassert artifact["secure_boot"]["compatibility_established"] is False\nPYUEFIMD5\ninstall -Dm644 "${UEFI_MD5SUM_DIR}/bootaa64.efi" \\\n  "${PACKAGE_DIR}/usr/lib/rufusarm64/bootaa64-uefi-md5sum.efi"\nfor file in bootaa64.efi.sha256 provenance.json SOURCE-COMMITS.txt REPRODUCIBILITY.txt \\\n  uefi-md5sum-v1.2-source.tar.gz uefi-md5sum-v1.2-source.tar.gz.sha256; do\n  install -Dm644 "${UEFI_MD5SUM_DIR}/${file}" \\\n    "${PACKAGE_DIR}/usr/share/doc/rufusarm64/uefi-md5sum/${file}"\ndone\n\n# Include Rufus 4.15's pinned, multi-architecture UEFI:NTFS FAT image.\n''',
)

replace_exact(
    "scripts/test.sh",
    '''[[ "${actual_wim_hash}" == "${expected_wim_hash}" ]]\nuefi_image="${extract_dir}/usr/lib/rufusarm64/uefi-ntfs.img"\n''',
    '''[[ "${actual_wim_hash}" == "${expected_wim_hash}" ]]\nruntime_loader="${extract_dir}/usr/lib/rufusarm64/bootaa64-uefi-md5sum.efi"\n[[ -f "${runtime_loader}" ]]\n[[ "$(stat -c %s "${runtime_loader}")" -eq 40960 ]]\n[[ "$(sha256sum "${runtime_loader}" | awk '{print $1}')" == "543615a8e97fed1cb5293bee7bdfe10f9feb6979f191b20ab32dafdcf097b502" ]]\nfor file in bootaa64.efi.sha256 provenance.json SOURCE-COMMITS.txt REPRODUCIBILITY.txt \\\n  uefi-md5sum-v1.2-source.tar.gz uefi-md5sum-v1.2-source.tar.gz.sha256; do\n  [[ -f "${extract_dir}/usr/share/doc/rufusarm64/uefi-md5sum/${file}" ]]\ndone\npython3 - "${extract_dir}/usr/share/doc/rufusarm64/uefi-md5sum/provenance.json" <<'PYUEFIPKG'\nimport json, sys\nwith open(sys.argv[1], encoding="utf-8") as handle:\n    data = json.load(handle)\nassert data["artifact"]["authenticode"]["present"] is False\nassert data["artifact"]["secure_boot"]["compatibility_established"] is False\nPYUEFIPKG\nuefi_image="${extract_dir}/usr/lib/rufusarm64/uefi-ntfs.img"\n''',
)

replace_exact(
    ".github/workflows/ci.yml",
    '''  test-and-package:\n    name: Audit and package\n    needs: [go-minimum, wim-engine]\n''',
    '''  uefi-md5sum-loader:\n    name: Reproduce ARM64 uefi-md5sum loader\n    runs-on: ubuntu-24.04\n    timeout-minutes: 75\n    steps:\n      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4\n        with:\n          persist-credentials: false\n      - name: Install pinned loader build dependencies\n        run: |\n          sudo apt-get update\n          sudo apt-get install -y --no-install-recommends \\\n            build-essential git gzip nasm python3 python3-setuptools uuid-dev \\\n            gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu sbsigntool\n      - name: Build twice and require identical provenance\n        run: |\n          bash scripts/build-uefi-md5sum-arm64.sh dist/uefi-md5sum-a\n          bash scripts/build-uefi-md5sum-arm64.sh dist/uefi-md5sum-b\n          for file in bootaa64.efi bootaa64.efi.sha256 provenance.json SOURCE-COMMITS.txt \\\n            uefi-md5sum-v1.2-source.tar.gz uefi-md5sum-v1.2-source.tar.gz.sha256; do\n            cmp "dist/uefi-md5sum-a/${file}" "dist/uefi-md5sum-b/${file}"\n          done\n          printf '%s\\n' \\\n            'Two independent Ubuntu 24.04 builds produced byte-for-byte identical artifacts.' \\\n            'The loader is unsigned and is not claimed Secure Boot compatible.' \\\n            > dist/uefi-md5sum-a/REPRODUCIBILITY.txt\n          mkdir -p vendor/uefi-md5sum/arm64\n          cp -a dist/uefi-md5sum-a/. vendor/uefi-md5sum/arm64/\n      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4\n        with:\n          name: uefi-md5sum-arm64\n          path: vendor/uefi-md5sum/arm64/\n          if-no-files-found: error\n\n  test-and-package:\n    name: Audit and package\n    needs: [go-minimum, wim-engine, uefi-md5sum-loader]\n''',
)
replace_exact(
    ".github/workflows/ci.yml",
    '''      - uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4\n        with:\n          name: wimlib-arm64\n          path: vendor/wimlib\n      - name: Install audit validators\n''',
    '''      - uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4\n        with:\n          name: wimlib-arm64\n          path: vendor/wimlib\n      - uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4\n        with:\n          name: uefi-md5sum-arm64\n          path: vendor/uefi-md5sum/arm64\n      - name: Install audit validators\n''',
)
replace_exact(
    ".github/workflows/ci.yml",
    '''  native-arm64-smoke:\n    name: Native ARM64 execution\n    needs: [go-minimum, wim-engine]\n''',
    '''  native-arm64-smoke:\n    name: Native ARM64 execution\n    needs: [go-minimum, wim-engine, uefi-md5sum-loader]\n''',
)
replace_exact(
    ".github/workflows/ci.yml",
    '''      - uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4\n        with:\n          name: wimlib-arm64\n          path: vendor/wimlib\n      - name: Read canonical project version\n''',
    '''      - uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4\n        with:\n          name: wimlib-arm64\n          path: vendor/wimlib\n      - uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4\n        with:\n          name: uefi-md5sum-arm64\n          path: vendor/uefi-md5sum/arm64\n      - name: Read canonical project version\n''',
)
replace_exact(
    ".github/workflows/ci.yml",
    '''          test "$("${package_root}/usr/lib/rufusarm64/rufusarm64-persistence-helper" --help 2>&1 || true)" != ""\n          integrity_root="$(mktemp -d)"\n''',
    '''          test "$("${package_root}/usr/lib/rufusarm64/rufusarm64-persistence-helper" --help 2>&1 || true)" != ""\n          runtime_loader="${package_root}/usr/lib/rufusarm64/bootaa64-uefi-md5sum.efi"\n          test "$(stat -c %s "${runtime_loader}")" -eq 40960\n          test "$(sha256sum "${runtime_loader}" | awk '{print $1}')" = "543615a8e97fed1cb5293bee7bdfe10f9feb6979f191b20ab32dafdcf097b502"\n          integrity_root="$(mktemp -d)"\n''',
)

Path("docs/persistence-user-guide.md").write_text(
    Path("docs/persistence-user-guide.md").read_text(encoding="utf-8")
    + '''\n\n## Development option: boot-time UEFI media validation\n\nThe privileged persistent-media helper accepts `--runtime-uefi-validation` for the ARM64 writable-copy path. It installs the package-owned, reproducibly built upstream `uefi-md5sum` loader transactionally, preserves the original fallback loader as `EFI/BOOT/bootaa64_original.efi`, and writes a verified root `md5sum.txt`. The current loader is unsigned; enabling this option does not establish Secure Boot compatibility. Raw-image, Windows, NTFS, compressed-stream, and virtual-disk writers do not accept this option.\n''',
    encoding="utf-8",
)
