package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/geocausa/RufusArm64/internal/acquisition"
	"github.com/geocausa/RufusArm64/internal/imaging"
	"github.com/geocausa/RufusArm64/internal/secureboot"
)

func TestSelectWriteMode(t *testing.T) {
	cases := []struct {
		name       string
		requested  string
		inspection imaging.ImageInfo
		force      bool
		want       string
		wantErr    bool
	}{
		{"hybrid iso raw", "auto", imaging.ImageInfo{HasISO9660: true, HasMBR: true, HasMBRPartition: true}, false, "raw", false},
		{"plain optical windows", "auto", imaging.ImageInfo{HasISO9660: true}, false, "windows", false},
		{"gpt raw", "auto", imaging.ImageInfo{HasGPT: true}, false, "raw", false},
		{"unknown rejected", "auto", imaging.ImageInfo{}, false, "", true},
		{"unknown expert force", "auto", imaging.ImageInfo{}, true, "raw", false},
		{"plain optical explicit raw rejected", "raw", imaging.ImageInfo{HasUDF: true}, false, "", true},
		{"plain optical expert force", "auto", imaging.ImageInfo{HasUDF: true}, true, "raw", false},
		{"explicit persistent mode", "linux-persistent", imaging.ImageInfo{HasISO9660: true, HasMBR: true, HasMBRPartition: true}, false, "linux-persistent", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := selectWriteMode(tc.requested, tc.inspection, tc.force)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("got=%q want=%q", got, tc.want)
			}
		})
	}
}

func TestHumanBytes(t *testing.T) {
	if got := humanBytes(1024); got != "1.0 KiB" {
		t.Fatalf("got %q", got)
	}
}

func TestPKExecWriterRejectsExpertBypassFlags(t *testing.T) {
	t.Setenv("PKEXEC_UID", "1000")
	for _, flag := range []string{"--allow-fixed", "--no-unmount", "--force-raw", "--allow-foreign-windows-architecture"} {
		args := []string{
			"write", "--image", "/tmp/image.iso", "--device", "/dev/sda",
			"--mode", "auto", "--yes", "--json-progress",
			"--expected-identity", "identity", "--cancel-file", "/run/user/1000/rufusarm64-test.cancel",
			flag,
		}
		err := run(args)
		if err == nil || err.Error() != "unsafe or unsupported arguments were supplied to the graphical privileged writer" {
			t.Fatalf("flag %s was not rejected at the privilege boundary: %v", flag, err)
		}
	}
}

func TestPKExecWriterRejectsExperimentalPersistenceMode(t *testing.T) {
	t.Setenv("PKEXEC_UID", "1000")
	err := run([]string{
		"write", "--image", "/tmp/image.iso", "--device", "/dev/sda",
		"--mode", "linux-persistent", "--experimental-persistence", "--yes", "--json-progress",
		"--expected-identity", "identity", "--cancel-file", "/run/user/1000/rufusarm64-test.cancel",
	})
	if err == nil || err.Error() != "unsafe or unsupported arguments were supplied to the graphical privileged writer" {
		t.Fatalf("experimental persistence crossed the graphical privilege boundary: %v", err)
	}
}

func TestParseClusterSize(t *testing.T) {
	for input, want := range map[string]uint64{"": 0, "auto": 0, "4096": 4096, "32768": 32768} {
		got, err := parseClusterSize(input)
		if err != nil || got != want {
			t.Fatalf("%q => %d, %v; want %d", input, got, err, want)
		}
	}
	for _, input := range []string{"2048", "65536", "8K"} {
		if _, err := parseClusterSize(input); err == nil {
			t.Fatalf("invalid cluster size %q accepted", input)
		}
	}
}

func TestAcquireCatalogCommands(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(100 + i)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	now := time.Now().UTC()
	catalog := acquisition.Catalog{
		Schema:    acquisition.SchemaVersion,
		Generated: now.Add(-time.Hour).Format(time.RFC3339),
		Expires:   now.Add(24 * time.Hour).Format(time.RFC3339),
		Images: []acquisition.Image{{
			ID: "test-arm64", Name: "Test", Version: "1", Architecture: "arm64",
			Filename: "test.iso", URL: "https://downloads.example.com/test.iso",
			SHA256: strings.Repeat("ab", 32), Size: 1024,
		}},
	}
	catalogBytes, err := json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	catalogPath := filepath.Join(directory, "catalog.json")
	signaturePath := filepath.Join(directory, "catalog.sig")
	keyPath := filepath.Join(directory, "catalog.pub")
	if err := os.WriteFile(catalogPath, catalogBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(signaturePath, []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, catalogBytes))), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(publicKey)), 0o600); err != nil {
		t.Fatal(err)
	}
	flags := []string{"--catalog", catalogPath, "--signature", signaturePath, "--public-key", keyPath, "--json"}
	if err := runAcquireVerify(flags); err != nil {
		t.Fatalf("verify catalog: %v", err)
	}
	if err := runAcquireList(flags); err != nil {
		t.Fatalf("list catalog: %v", err)
	}
	catalogBytes[0] ^= 1
	if err := os.WriteFile(catalogPath, catalogBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runAcquireVerify(flags); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("tampered catalog error = %v", err)
	}
}

func TestReadLimitedRegularFileRejectsDirectory(t *testing.T) {
	if _, err := readLimitedRegularFile(t.TempDir(), 1024); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("directory error = %v", err)
	}
}

func TestWriterContextHasNoAutomaticDeadline(t *testing.T) {
	ctx, cleanup, err := newWriterCancellationContext(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if _, ok := ctx.Deadline(); ok {
		t.Fatal("normal USB writer unexpectedly has an automatic deadline")
	}
}

func TestPersistenceAnalysisContextHasBoundedDeadline(t *testing.T) {
	ctx, cleanup, err := newPersistenceAnalysisContext(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("read-only persistence analysis is missing its cleanup deadline")
	}
	remaining := time.Until(deadline)
	if remaining < 119*time.Second || remaining > 121*time.Second {
		t.Fatalf("unexpected persistence analysis deadline: %v", remaining)
	}
}

func TestPKExecPersistenceAnalyzeRequiresJSONAndCancellationChannel(t *testing.T) {
	t.Setenv("PKEXEC_UID", "1000")
	base := []string{
		"--image", "/tmp/linux.iso",
		"--expected-source-identity", "1:2:3:4:5",
		"--target-size", "4G",
	}
	if err := runPersistenceAnalyze(base); err == nil || !strings.Contains(err.Error(), "requires --json and a trusted --cancel-file") {
		t.Fatalf("missing graphical boundary flags error = %v", err)
	}
	withJSON := append(append([]string{}, base...), "--json")
	if err := runPersistenceAnalyze(withJSON); err == nil || !strings.Contains(err.Error(), "requires --json and a trusted --cancel-file") {
		t.Fatalf("missing cancellation channel error = %v", err)
	}
}

func TestPersistenceAnalyzeRejectsPositionalArguments(t *testing.T) {
	err := runPersistenceAnalyze([]string{"unexpected"})
	if err == nil || !strings.Contains(err.Error(), "does not accept positional arguments") {
		t.Fatalf("positional argument error = %v", err)
	}
}

func TestPersistenceAnalyzeRejectsMalformedSourceIdentityBeforePrivilege(t *testing.T) {
	t.Setenv("PKEXEC_UID", "1000")
	err := runPersistenceAnalyze([]string{
		"--image", "/tmp/linux.iso",
		"--expected-source-identity", "not-an-identity",
		"--target-size", "4G",
		"--cancel-file", "/run/user/1000/rufusarm64-test.cancel",
		"--json",
	})
	if err == nil || !strings.Contains(err.Error(), "parse --expected-source-identity") {
		t.Fatalf("malformed source identity error = %v", err)
	}
}

func TestPersistencePlanCommand(t *testing.T) {
	imagePath := filepath.Join(t.TempDir(), "ubuntu.iso")
	image := make([]byte, 64*1024*1024)
	image[510], image[511] = 0x55, 0xaa
	image[446+4] = 0x17
	image[446+8] = 64
	image[446+12] = 1
	image[16*2048] = 1
	copy(image[16*2048+1:], "CD001")
	image[16*2048+6] = 1
	if err := os.WriteFile(imagePath, image, 0o600); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	for name, data := range map[string]string{
		".disk/info":         "Ubuntu 24.04.2 LTS arm64\n",
		"casper/vmlinuz":     "kernel",
		"casper/initrd":      "initrd",
		"boot/grub/grub.cfg": "linux /casper/vmlinuz boot=casper quiet\n",
	} {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := runPersistencePlan([]string{"--image", imagePath, "--media-root", root, "--target-size", "4G", "--size", "1G", "--json"}); err != nil {
		t.Fatalf("plan persistence: %v", err)
	}
}

func TestPersistencePlanRejectsCompressedInput(t *testing.T) {
	imagePath := filepath.Join(t.TempDir(), "image.gz")
	if err := os.WriteFile(imagePath, []byte{0x1f, 0x8b, 0, 0}, 0o600); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	err := runPersistencePlan([]string{"--image", imagePath, "--media-root", root, "--target-size", "4G"})
	if err == nil || !strings.Contains(err.Error(), "plain ISOHybrid") {
		t.Fatalf("compressed input error = %v", err)
	}
}

func TestQualifyCommandValidation(t *testing.T) {
	if err := run([]string{"qualify"}); err == nil || err.Error() != "qualify requires start or verify" {
		t.Fatalf("missing phase error = %v", err)
	}
	if err := run([]string{"qualify", "unknown"}); err == nil || err.Error() != "unknown qualify command \"unknown\"" {
		t.Fatalf("unknown phase error = %v", err)
	}
	if err := run([]string{"qualify", "start"}); err == nil || err.Error() != "--record and --output are required" {
		t.Fatalf("missing start flags error = %v", err)
	}
	if err := run([]string{"qualify", "verify", "--record", "/tmp/creation.json"}); err == nil || err.Error() != "--record and --output are required" {
		t.Fatalf("missing verify output error = %v", err)
	}
}

func TestAcquireChannelCommandValidation(t *testing.T) {
	if err := runAcquireChannel(nil); err == nil || !strings.Contains(err.Error(), "requires verify, list, or download") {
		t.Fatalf("missing channel subcommand error = %v", err)
	}
	if err := runAcquireChannelList([]string{"unexpected"}); err == nil || !strings.Contains(err.Error(), "does not accept positional") {
		t.Fatalf("channel list positional error = %v", err)
	}
	if err := runAcquireChannelDownload(nil); err == nil || !strings.Contains(err.Error(), "--id is required") {
		t.Fatalf("missing channel image id error = %v", err)
	}
}

func TestAcquireChannelDisabledPackageConfiguration(t *testing.T) {
	directory := t.TempDir()
	config := filepath.Join(directory, "channel.json")
	if err := os.WriteFile(config, []byte(`{"schema":1,"enabled":false,"bootstrap_root":"","root_url":"","catalog_url":"","allowed_hosts":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runAcquireChannelList([]string{"--config", config, "--cache-dir", filepath.Join(directory, "cache"), "--json"})
	if err == nil || !strings.Contains(err.Error(), "not provisioned") {
		t.Fatalf("disabled package channel error = %v", err)
	}
}

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

func TestUEFIValidateLoadsTrustedSBATLevel(t *testing.T) {
	root := t.TempDir()
	writeCLIUEFIFallback(t, root, 0xaa64)
	levelPath := filepath.Join(t.TempDir(), "SbatLevel.csv")
	if err := os.WriteFile(levelPath, []byte("sbat,1,2025051000\nshim,4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := captureCLIStdout(t, func() error {
		return runUEFIValidate([]string{"--directory", root, "--arch", "arm64", "--sbat-level", levelPath, "--json"})
	})
	if err != nil {
		t.Fatalf("validate with SBAT level: %v", err)
	}
	var result secureboot.UEFIMediaValidation
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatalf("decode UEFI validation: %v\n%s", err, output)
	}
	if !result.Valid || !result.SBATLevelChecked || result.SBATLevelDatestamp != "2025051000" || result.SBATRevoked {
		t.Fatalf("unexpected SBAT-level validation: %#v", result)
	}
}

func TestUEFIValidateRejectsMalformedSBATLevel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad-sbat.csv")
	if err := os.WriteFile(path, []byte("shim,4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runUEFIValidate([]string{"--directory", t.TempDir(), "--arch", "arm64", "--sbat-level", path})
	if err == nil || !strings.Contains(err.Error(), "must start with sbat") {
		t.Fatalf("malformed SBAT level error = %v", err)
	}
}

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
