package main

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	inspectISOBlockSize = 2048
	inspectCatalogLBA   = 20
	inspectImageLBA     = 30
)

func TestInspectElToritoUEFIEvidenceAcceptsOneExactImage(t *testing.T) {
	path := writeInspectElToritoFixture(t, false, 0xef)
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	var result inspectResult
	inspectElToritoUEFIEvidence(file, info.Size(), &result)
	if result.ElToritoUEFI == nil || result.ElToritoUEFIRefusal != "" {
		t.Fatalf("unexpected evidence: %#v", result)
	}
	if result.ElToritoUEFI.PlatformID != 0xef || result.ElToritoUEFI.MediaType != 0 ||
		result.ElToritoUEFI.ImageLength != 4096 || result.ElToritoUEFI.PlanSHA256 == "" {
		t.Fatalf("unexpected plan: %#v", result.ElToritoUEFI)
	}
}

func TestInspectElToritoUEFIEvidenceReportsAmbiguityAndMissingEFI(t *testing.T) {
	for name, path := range map[string]string{
		"ambiguous": writeInspectElToritoFixture(t, true, 0xef),
		"BIOS only": writeInspectElToritoFixture(t, false, 0x00),
	} {
		t.Run(name, func(t *testing.T) {
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			info, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			var result inspectResult
			inspectElToritoUEFIEvidence(file, info.Size(), &result)
			if result.ElToritoUEFI != nil || strings.TrimSpace(result.ElToritoUEFIRefusal) == "" {
				t.Fatalf("unsafe evidence accepted: %#v", result)
			}
		})
	}
}

func TestRunInspectPublishesStrictElToritoEvidence(t *testing.T) {
	path := writeInspectElToritoFixture(t, false, 0xef)
	output, err := captureStdout(t, func() error {
		return runInspect([]string{"--image", path, "--json"})
	})
	if err != nil {
		t.Fatal(err)
	}
	var result inspectResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Recognized || result.Mode != "raw" || result.ElToritoUEFI == nil || result.ElToritoUEFIRefusal != "" {
		t.Fatalf("unexpected inspect result: %#v", result)
	}
}

func writeInspectElToritoFixture(t *testing.T, secondEFI bool, platform byte) string {
	t.Helper()
	const volumeSectors = 64
	data := make([]byte, volumeSectors*inspectISOBlockSize)
	pvd := data[16*inspectISOBlockSize : 17*inspectISOBlockSize]
	pvd[0] = 1
	copy(pvd[1:6], "CD001")
	pvd[6] = 1
	binary.LittleEndian.PutUint32(pvd[80:84], volumeSectors)
	binary.BigEndian.PutUint32(pvd[84:88], volumeSectors)
	boot := data[17*inspectISOBlockSize : 18*inspectISOBlockSize]
	boot[0] = 0
	copy(boot[1:6], "CD001")
	boot[6] = 1
	copy(boot[7:39], "EL TORITO SPECIFICATION")
	binary.LittleEndian.PutUint32(boot[71:75], inspectCatalogLBA)
	end := data[18*inspectISOBlockSize : 19*inspectISOBlockSize]
	end[0] = 255
	copy(end[1:6], "CD001")
	end[6] = 1
	catalog := data[inspectCatalogLBA*inspectISOBlockSize : (inspectCatalogLBA+1)*inspectISOBlockSize]
	validation := catalog[:32]
	validation[0] = 1
	validation[1] = platform
	copy(validation[4:28], "RufusArm64 inspection")
	validation[30], validation[31] = 0x55, 0xaa
	setInspectElToritoChecksum(validation)
	entry := catalog[32:64]
	entry[0] = 0x88
	entry[1] = 0
	binary.LittleEndian.PutUint16(entry[6:8], 8)
	binary.LittleEndian.PutUint32(entry[8:12], inspectImageLBA)
	if secondEFI {
		header := catalog[64:96]
		header[0], header[1] = 0x91, 0xef
		binary.LittleEndian.PutUint16(header[2:4], 1)
		second := catalog[96:128]
		second[0] = 0x88
		second[1] = 0
		binary.LittleEndian.PutUint16(second[6:8], 8)
		binary.LittleEndian.PutUint32(second[8:12], inspectImageLBA+4)
	}
	image := data[inspectImageLBA*inspectISOBlockSize : inspectImageLBA*inspectISOBlockSize+4096]
	for index := range image {
		image[index] = byte((index*13 + 7) % 251)
	}
	path := filepath.Join(t.TempDir(), "el-torito.iso")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func setInspectElToritoChecksum(entry []byte) {
	entry[28], entry[29] = 0, 0
	var sum uint16
	for offset := 0; offset < 32; offset += 2 {
		sum += binary.LittleEndian.Uint16(entry[offset : offset+2])
	}
	binary.LittleEndian.PutUint16(entry[28:30], uint16(0-sum))
}
