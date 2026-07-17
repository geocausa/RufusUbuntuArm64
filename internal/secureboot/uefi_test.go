package secureboot

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type syntheticUEFISection struct {
	name string
	data []byte
}

func syntheticUEFIPE(machine, subsystem uint16, sections ...syntheticUEFISection) []byte {
	const (
		peOffset     = 0x80
		optionalSize = 0xf0
		headersSize  = 0x400
		sectionAlign = 0x200
	)
	if len(sections) == 0 {
		sections = []syntheticUEFISection{{name: ".text", data: []byte("EFI payload")}}
	}
	total := headersSize
	for _, section := range sections {
		total += (len(section.data) + sectionAlign - 1) &^ (sectionAlign - 1)
	}
	data := make([]byte, total)
	data[0], data[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(data[0x3c:0x40], peOffset)
	copy(data[peOffset:peOffset+4], []byte{'P', 'E', 0, 0})
	coff := peOffset + 4
	binary.LittleEndian.PutUint16(data[coff:coff+2], machine)
	binary.LittleEndian.PutUint16(data[coff+2:coff+4], uint16(len(sections)))
	binary.LittleEndian.PutUint16(data[coff+16:coff+18], optionalSize)
	optional := coff + 20
	binary.LittleEndian.PutUint16(data[optional:optional+2], pe32PlusMagic)
	binary.LittleEndian.PutUint32(data[optional+60:optional+64], headersSize)
	binary.LittleEndian.PutUint16(data[optional+68:optional+70], subsystem)
	binary.LittleEndian.PutUint32(data[optional+108:optional+112], 16)

	sectionTable := optional + optionalSize
	offset := headersSize
	for index, section := range sections {
		entry := data[sectionTable+index*peSectionSize : sectionTable+(index+1)*peSectionSize]
		copy(entry[:8], []byte(section.name))
		rawSize := (len(section.data) + sectionAlign - 1) &^ (sectionAlign - 1)
		binary.LittleEndian.PutUint32(entry[8:12], uint32(len(section.data)))
		binary.LittleEndian.PutUint32(entry[16:20], uint32(rawSize))
		binary.LittleEndian.PutUint32(entry[20:24], uint32(offset))
		copy(data[offset:offset+len(section.data)], section.data)
		offset += rawSize
	}
	return data
}

func writeSyntheticEFI(t *testing.T, root, relative string, data []byte) string {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func validSBAT() []byte {
	return []byte("sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim\nshim,4,Ubuntu,shim,15.8,https://launchpad.net/ubuntu\n")
}

func TestValidateUEFIMediaAcceptsARM64FallbackAndSBAT(t *testing.T) {
	root := t.TempDir()
	writeSyntheticEFI(t, root, "EFI/BOOT/BOOTAA64.EFI", syntheticUEFIPE(
		imageFileMachineARM64,
		imageSubsystemEFIApp,
		syntheticUEFISection{name: ".text", data: []byte("fallback")},
		syntheticUEFISection{name: ".sbat", data: validSBAT()},
	))
	writeSyntheticEFI(t, root, "EFI/ubuntu/grubaa64.efi", syntheticUEFIPE(
		imageFileMachineARM64,
		imageSubsystemEFIApp,
		syntheticUEFISection{name: ".text", data: []byte("grub")},
		syntheticUEFISection{name: ".sbat", data: validSBAT()},
	))

	result, err := ValidateUEFIMedia(context.Background(), root, UEFIValidationOptions{
		Architecture:    "arm64",
		RequireFallback: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid || !result.FallbackFound || result.Revoked || len(result.Files) != 2 {
		t.Fatalf("unexpected result: %#v", result)
	}
	if len(result.Files[0].SBAT) != 2 && len(result.Files[1].SBAT) != 2 {
		t.Fatalf("SBAT metadata was not parsed: %#v", result.Files)
	}
}

func TestValidateUEFIMediaRejectsWrongFallbackArchitecture(t *testing.T) {
	root := t.TempDir()
	writeSyntheticEFI(t, root, "EFI/BOOT/BOOTAA64.EFI", syntheticUEFIPE(imageFileMachineAMD64, imageSubsystemEFIApp))
	result, err := ValidateUEFIMedia(context.Background(), root, UEFIValidationOptions{Architecture: "arm64", RequireFallback: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid || len(result.Errors) == 0 || !strings.Contains(strings.Join(result.Errors, "\n"), "expected arm64") {
		t.Fatalf("wrong architecture was not rejected: %#v", result)
	}
}

func TestValidateUEFIMediaRequiresFallbackLoader(t *testing.T) {
	root := t.TempDir()
	writeSyntheticEFI(t, root, "EFI/ubuntu/grubaa64.efi", syntheticUEFIPE(imageFileMachineARM64, imageSubsystemEFIApp))
	result, err := ValidateUEFIMedia(context.Background(), root, UEFIValidationOptions{Architecture: "arm64", RequireFallback: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid || result.FallbackFound || !strings.Contains(strings.Join(result.Errors, "\n"), "BOOTAA64.EFI") {
		t.Fatalf("missing fallback was not rejected: %#v", result)
	}
}

func TestValidateUEFIMediaRejectsMalformedSBAT(t *testing.T) {
	root := t.TempDir()
	writeSyntheticEFI(t, root, "EFI/BOOT/BOOTAA64.EFI", syntheticUEFIPE(
		imageFileMachineARM64,
		imageSubsystemEFIApp,
		syntheticUEFISection{name: ".text", data: []byte("fallback")},
		syntheticUEFISection{name: ".sbat", data: []byte("shim,not-a-generation,Ubuntu\n")},
	))
	result, err := ValidateUEFIMedia(context.Background(), root, UEFIValidationOptions{Architecture: "arm64", RequireFallback: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid || !strings.Contains(strings.Join(result.Errors, "\n"), ".sbat") {
		t.Fatalf("malformed SBAT was not rejected: %#v", result)
	}
}

func TestValidateUEFIMediaRejectsRevokedFallback(t *testing.T) {
	root := t.TempDir()
	pe := syntheticUEFIPE(
		imageFileMachineARM64,
		imageSubsystemEFIApp,
		syntheticUEFISection{name: ".text", data: []byte("revoked fallback")},
		syntheticUEFISection{name: ".sbat", data: validSBAT()},
	)
	writeSyntheticEFI(t, root, "EFI/BOOT/BOOTAA64.EFI", pe)
	hash, err := AuthenticodeSHA256(pe)
	if err != nil {
		t.Fatal(err)
	}
	digestBytes, err := hex.DecodeString(hash.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	var digest [sha256.Size]byte
	copy(digest[:], digestBytes)
	dbx := &Database{SHA256: map[[sha256.Size]byte]struct{}{digest: {}}, X509: make(map[[sha256.Size]byte]struct{})}

	result, err := ValidateUEFIMedia(context.Background(), root, UEFIValidationOptions{
		Architecture:    "arm64",
		RequireFallback: true,
		DBX:             dbx,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid || !result.Revoked || !result.DBXChecked || !result.Files[0].DirectHashRevoked {
		t.Fatalf("revoked fallback was not rejected: %#v", result)
	}
}

func TestValidateUEFIMediaAllowsForeignNonFallbackWithWarning(t *testing.T) {
	root := t.TempDir()
	writeSyntheticEFI(t, root, "EFI/BOOT/BOOTAA64.EFI", syntheticUEFIPE(
		imageFileMachineARM64,
		imageSubsystemEFIApp,
		syntheticUEFISection{name: ".sbat", data: validSBAT()},
	))
	writeSyntheticEFI(t, root, "EFI/tools/shellx64.efi", syntheticUEFIPE(imageFileMachineAMD64, imageSubsystemEFIApp))
	result, err := ValidateUEFIMedia(context.Background(), root, UEFIValidationOptions{Architecture: "arm64", RequireFallback: true})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid || len(result.Files) != 2 {
		t.Fatalf("foreign optional tool invalidated media: %#v", result)
	}
	var warned bool
	for _, file := range result.Files {
		warned = warned || strings.Contains(strings.Join(file.Warnings, "\n"), "foreign-architecture")
	}
	if !warned {
		t.Fatalf("foreign architecture was not reported: %#v", result.Files)
	}
}

func TestValidateUEFIMediaRejectsNonEFISubsystem(t *testing.T) {
	root := t.TempDir()
	writeSyntheticEFI(t, root, "EFI/BOOT/BOOTAA64.EFI", syntheticUEFIPE(imageFileMachineARM64, 3))
	result, err := ValidateUEFIMedia(context.Background(), root, UEFIValidationOptions{Architecture: "arm64", RequireFallback: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid || !strings.Contains(strings.Join(result.Errors, "\n"), "not an EFI") {
		t.Fatalf("non-EFI subsystem was not rejected: %#v", result)
	}
}

func TestValidateUEFIMediaBoundsFileCount(t *testing.T) {
	root := t.TempDir()
	writeSyntheticEFI(t, root, "EFI/BOOT/BOOTAA64.EFI", syntheticUEFIPE(imageFileMachineARM64, imageSubsystemEFIApp))
	writeSyntheticEFI(t, root, "EFI/tools/second.efi", syntheticUEFIPE(imageFileMachineARM64, imageSubsystemEFIApp))
	_, err := ValidateUEFIMedia(context.Background(), root, UEFIValidationOptions{Architecture: "arm64", MaxFiles: 1})
	if err == nil || !strings.Contains(err.Error(), "unbounded scan") {
		t.Fatalf("file-count bound was not enforced: %v", err)
	}
}
