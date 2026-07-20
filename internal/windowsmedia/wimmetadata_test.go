//go:build linux

package windowsmedia

import (
	"fmt"
	"strings"
	"testing"
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
