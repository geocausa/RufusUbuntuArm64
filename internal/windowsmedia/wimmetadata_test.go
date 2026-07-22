//go:build linux

package windowsmedia

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestParseWIMMetadata(t *testing.T) {
	xml := `<WIM>
  <IMAGE INDEX="1"><NAME>Windows 11 Pro</NAME><WINDOWS><ARCH>12</ARCH><PRODUCTNAME>Microsoft Windows 11 Pro</PRODUCTNAME><INSTALLATIONTYPE>Client</INSTALLATIONTYPE><VERSION><MAJOR>10</MAJOR><MINOR>0</MINOR><BUILD>26100</BUILD></VERSION></WINDOWS></IMAGE>
  <IMAGE INDEX="2"><NAME>Windows 11 Home</NAME><WINDOWS><ARCH>12</ARCH><PRODUCTNAME>Microsoft Windows 11 Home</PRODUCTNAME><INSTALLATIONTYPE>Client</INSTALLATIONTYPE><VERSION><MAJOR>10</MAJOR><MINOR>0</MINOR><BUILD>26100</BUILD></VERSION></WINDOWS></IMAGE>
</WIM>`
	metadata, err := parseWIMMetadata(strings.NewReader(xml))
	if err != nil {
		t.Fatalf("parseWIMMetadata: %v", err)
	}
	if metadata.ProductName != "Microsoft Windows 11 Pro" || metadata.Version != "10.0.26100" || metadata.Architecture != "arm64" || metadata.InstallationType != "Client" {
		t.Fatalf("metadata = %#v", metadata)
	}
	if metadata.ImageCount != 2 {
		t.Fatalf("image count=%d, want 2", metadata.ImageCount)
	}
	if got := strings.Join(metadata.EditionNames, "|"); got != "Windows 11 Pro|Windows 11 Home" {
		t.Fatalf("edition names=%q", got)
	}
}

func TestParseWIMMetadataAcceptsUTF16(t *testing.T) {
	tests := []struct {
		name        string
		declaration string
		order       binary.ByteOrder
		bom         uint16
	}{
		{name: "little endian", declaration: "UTF-16LE", order: binary.LittleEndian, bom: 0xfeff},
		{name: "big endian", declaration: "UTF-16BE", order: binary.BigEndian, bom: 0xfeff},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			xml := `<?xml version="1.0" encoding="` + test.declaration + `"?><WIM><IMAGE INDEX="1"><NAME>Windows 11 Pro</NAME><WINDOWS><ARCH>12</ARCH><PRODUCTNAME>Microsoft Windows 11 Pro</PRODUCTNAME><INSTALLATIONTYPE>Client</INSTALLATIONTYPE><VERSION><MAJOR>10</MAJOR><MINOR>0</MINOR><BUILD>26100</BUILD></VERSION></WINDOWS></IMAGE></WIM>`
			metadata, err := parseWIMMetadata(bytes.NewReader(encodeUTF16(test.order, test.bom, xml)))
			if err != nil {
				t.Fatal(err)
			}
			if metadata.ProductName != "Microsoft Windows 11 Pro" || metadata.Architecture != "arm64" || metadata.ImageCount != 1 {
				t.Fatalf("metadata=%#v", metadata)
			}
		})
	}
}

func TestParseWIMMetadataAcceptsUTF8BOM(t *testing.T) {
	xml := []byte(`<WIM><IMAGE INDEX="1"><NAME>Windows 11 Pro</NAME><WINDOWS><ARCH>12</ARCH><PRODUCTNAME>Windows 11 Pro</PRODUCTNAME><INSTALLATIONTYPE>Client</INSTALLATIONTYPE></WINDOWS></IMAGE></WIM>`)
	data := append([]byte{0xef, 0xbb, 0xbf}, xml...)
	metadata, err := parseWIMMetadata(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if metadata.ImageCount != 1 || metadata.Architecture != "arm64" {
		t.Fatalf("metadata=%#v", metadata)
	}
}

func TestParseWIMMetadataRejectsMalformedUTF16(t *testing.T) {
	tests := [][]byte{
		{0xff, 0xfe, '<'},
		{0xff, 0xfe, 0x00, 0xd8},
		{0xff, 0xfe, 0x00, 0xdc},
		{0xff, 0xfe, 0x00, 0xd8, '<', 0x00},
	}
	for index, data := range tests {
		if _, err := parseWIMMetadata(bytes.NewReader(data)); err == nil || !strings.Contains(err.Error(), "UTF-16") {
			t.Fatalf("case %d error=%v, want UTF-16 rejection", index, err)
		}
	}
}

func encodeUTF16(order binary.ByteOrder, bom uint16, value string) []byte {
	units := utf16.Encode([]rune(value))
	data := make([]byte, 2+len(units)*2)
	order.PutUint16(data[:2], bom)
	for index, unit := range units {
		order.PutUint16(data[2+index*2:2+index*2+2], unit)
	}
	return data
}

func TestParseWIMMetadataDeduplicatesEditionNamesWithoutHidingImageCount(t *testing.T) {
	xml := `<WIM>
  <IMAGE INDEX="1"><NAME>Windows 11 Pro</NAME><WINDOWS><ARCH>9</ARCH><PRODUCTNAME>Windows 11 Pro</PRODUCTNAME><INSTALLATIONTYPE>Client</INSTALLATIONTYPE></WINDOWS></IMAGE>
  <IMAGE INDEX="2"><NAME>windows 11 pro</NAME><WINDOWS><ARCH>9</ARCH><PRODUCTNAME>Windows 11 Pro</PRODUCTNAME><INSTALLATIONTYPE>Client</INSTALLATIONTYPE></WINDOWS></IMAGE>
</WIM>`
	metadata, err := parseWIMMetadata(strings.NewReader(xml))
	if err != nil {
		t.Fatal(err)
	}
	if metadata.ImageCount != 2 || len(metadata.EditionNames) != 1 || metadata.EditionNames[0] != "Windows 11 Pro" {
		t.Fatalf("metadata=%#v", metadata)
	}
}

func TestParseWIMMetadataRejectsConflictingEditions(t *testing.T) {
	xml := `<WIM>
  <IMAGE INDEX="1"><WINDOWS><ARCH>9</ARCH><PRODUCTNAME>Windows 11 Pro</PRODUCTNAME><INSTALLATIONTYPE>Client</INSTALLATIONTYPE><VERSION><MAJOR>10</MAJOR><MINOR>0</MINOR></VERSION></WINDOWS></IMAGE>
  <IMAGE INDEX="2"><WINDOWS><ARCH>9</ARCH><PRODUCTNAME>Windows Server 2025</PRODUCTNAME><INSTALLATIONTYPE>Server</INSTALLATIONTYPE><VERSION><MAJOR>10</MAJOR><MINOR>0</MINOR></VERSION></WINDOWS></IMAGE>
</WIM>`
	if _, err := parseWIMMetadata(strings.NewReader(xml)); err == nil || !strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("error = %v, want conflicting metadata", err)
	}
}

func TestParseWIMMetadataRejectsUnboundedEditionSets(t *testing.T) {
	var xml strings.Builder
	xml.WriteString("<WIM>")
	for index := 0; index < maxWIMImages+1; index++ {
		fmt.Fprintf(&xml, `<IMAGE INDEX="%d"><NAME>Windows 11 Pro</NAME><WINDOWS><ARCH>9</ARCH><PRODUCTNAME>Windows 11 Pro</PRODUCTNAME><INSTALLATIONTYPE>Client</INSTALLATIONTYPE></WINDOWS></IMAGE>`, index+1)
	}
	xml.WriteString("</WIM>")
	if _, err := parseWIMMetadata(strings.NewReader(xml.String())); err == nil || !strings.Contains(err.Error(), "safe limit") {
		t.Fatalf("unbounded image set accepted: %v", err)
	}
}

func TestParseWIMMetadataRejectsOversizedEditionName(t *testing.T) {
	name := strings.Repeat("X", maxWIMEditionName+1)
	xml := `<WIM><IMAGE INDEX="1"><NAME>` + name + `</NAME><WINDOWS><ARCH>9</ARCH><PRODUCTNAME>Windows 11 Pro</PRODUCTNAME><INSTALLATIONTYPE>Client</INSTALLATIONTYPE></WINDOWS></IMAGE></WIM>`
	if _, err := parseWIMMetadata(strings.NewReader(xml)); err == nil || !strings.Contains(err.Error(), "edition name") {
		t.Fatalf("oversized edition name accepted: %v", err)
	}
}

func TestParseWIMMetadataFailsClosed(t *testing.T) {
	tests := []struct {
		name string
		xml  string
	}{
		{name: "empty document", xml: `<WIM></WIM>`},
		{name: "invalid XML", xml: `<WIM>`},
		{name: "missing identity", xml: `<WIM><IMAGE INDEX="1"><WINDOWS/></IMAGE></WIM>`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			metadata, err := parseWIMMetadata(strings.NewReader(test.xml))
			if err == nil && metadataClass(metadata) == "|||" {
				t.Fatalf("unidentified metadata was accepted: %#v", metadata)
			}
		})
	}
}

func TestNormalizeWIMArchitecture(t *testing.T) {
	for input, expected := range map[string]string{"12": "arm64", "9": "amd64", "0": "x86", "aarch64": "arm64"} {
		if actual := normalizeWIMArchitecture(input); actual != expected {
			t.Fatalf("normalizeWIMArchitecture(%q) = %q, want %q", input, actual, expected)
		}
	}
}

func TestParseWIMMetadataUsesDisplayNameForWindows11Identity(t *testing.T) {
	xml := `<WIM><IMAGE INDEX="1"><NAME>Professional</NAME><DISPLAYNAME>Windows 11 Pro</DISPLAYNAME><WINDOWS><ARCH>12</ARCH><PRODUCTNAME>Microsoft Windows Operating System</PRODUCTNAME><INSTALLATIONTYPE>Client</INSTALLATIONTYPE><VERSION><MAJOR>10</MAJOR><MINOR>0</MINOR><BUILD>26100</BUILD></VERSION></WINDOWS></IMAGE></WIM>`
	metadata, err := parseWIMMetadata(strings.NewReader(xml))
	if err != nil {
		t.Fatal(err)
	}
	if metadata.ProductName != "Windows 11 Pro" {
		t.Fatalf("product name=%q, want display name", metadata.ProductName)
	}
	if got := metadataClass(metadata); got != "11|client|arm64|" {
		t.Fatalf("metadata class=%q, want recognized Windows 11 ARM64 client", got)
	}
	if len(metadata.EditionNames) != 1 || metadata.EditionNames[0] != "Windows 11 Pro" {
		t.Fatalf("edition names=%v", metadata.EditionNames)
	}
}
