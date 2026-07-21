package secureboot

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMicrosoftDBXPinsUseReviewedImmutableObjects(t *testing.T) {
	expected := map[string]string{
		"x86":   "142584cbd3ac2045aa6936e3c5e1814fc8b28149",
		"amd64": "f6ccec74a078267d56222b44d31ad30757ee8717",
		"arm":   "feb134b01b59c0d95730466ca75a31d326848c99",
		"arm64": "33520068f2602fbd2c739b7f71e8946f5ba6ccd4",
	}
	for architecture, blob := range expected {
		t.Run(architecture, func(t *testing.T) {
			pin, err := MicrosoftDBXPinForArchitecture(architecture)
			if err != nil {
				t.Fatal(err)
			}
			if pin.Architecture != architecture || pin.RepositoryCommit != microsoftDBXRepositoryCommit || pin.GitBlobSHA1 != blob {
				t.Fatalf("unexpected pin: %#v", pin)
			}
			if strings.Contains(pin.URL, "/main/") || !strings.Contains(pin.URL, "/"+microsoftDBXRepositoryCommit+"/") {
				t.Fatalf("URL is not commit-qualified: %s", pin.URL)
			}
			if err := validateMicrosoftDBXPin(pin); err != nil {
				t.Fatal(err)
			}
		})
	}
	if _, err := MicrosoftDBXPinForArchitecture("ia64"); err == nil || !strings.Contains(err.Error(), "no reviewed pinned") {
		t.Fatalf("ia64 pin error=%v", err)
	}
}

func TestGitBlobIdentityUsesGitObjectFraming(t *testing.T) {
	actual, err := verifyGitBlobSHA1(nil, "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391")
	if err != nil {
		t.Fatal(err)
	}
	if actual != "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391" {
		t.Fatalf("empty Git blob=%s", actual)
	}
	if _, err := verifyGitBlobSHA1([]byte("tampered"), actual); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("tamper error=%v", err)
	}
}

func TestMicrosoftDBXPinValidationRejectsMutableOrMalformedReferences(t *testing.T) {
	base := MicrosoftDBXPin{
		Architecture:     "arm64",
		RepositoryCommit: strings.Repeat("a", 40),
		GitBlobSHA1:       strings.Repeat("b", 40),
		URL:               "https://raw.githubusercontent.com/microsoft/secureboot_objects/" + strings.Repeat("a", 40) + "/PostSignedObjects/DBX/arm64/DBXUpdate.bin",
	}
	cases := map[string]func(*MicrosoftDBXPin){
		"moving branch URL": func(pin *MicrosoftDBXPin) {
			pin.URL = "https://raw.githubusercontent.com/microsoft/secureboot_objects/main/PostSignedObjects/DBX/arm64/DBXUpdate.bin"
		},
		"short commit":              func(pin *MicrosoftDBXPin) { pin.RepositoryCommit = "abc" },
		"uppercase blob":            func(pin *MicrosoftDBXPin) { pin.GitBlobSHA1 = strings.Repeat("B", 40) },
		"noncanonical architecture": func(pin *MicrosoftDBXPin) { pin.Architecture = "aarch64" },
		"architecture mismatch": func(pin *MicrosoftDBXPin) {
			pin.Architecture = "amd64"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			if err := validateMicrosoftDBXPin(candidate); err == nil {
				t.Fatalf("invalid pin accepted: %#v", candidate)
			}
		})
	}
}

func TestPinnedDBXValidationPrecedesCachePublication(t *testing.T) {
	data := authenticatedDBXFixture(t)
	blob := hex.EncodeToString(gitBlobSHA1(data))
	commit := strings.Repeat("c", 40)
	pin := MicrosoftDBXPin{
		Architecture:     "arm64",
		RepositoryCommit: commit,
		GitBlobSHA1:       blob,
		URL:               "https://raw.githubusercontent.com/microsoft/secureboot_objects/" + commit + "/PostSignedObjects/DBX/arm64/DBXUpdate.bin",
	}
	root := t.TempDir()
	destination := filepath.Join(root, "cache", "arm64-DBXUpdate.bin")
	tampered := append([]byte(nil), data...)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := validateAndCachePinnedDBX(tampered, pin, destination); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("tampered cache error=%v", err)
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatalf("tampered DBX was published: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(destination)); !os.IsNotExist(err) {
		t.Fatalf("cache directory created before pin validation: %v", err)
	}

	result, err := validateAndCachePinnedDBX(data, pin, destination)
	if err != nil {
		t.Fatal(err)
	}
	if result.Path != destination || result.RepositoryCommit != commit || result.GitBlobSHA1 != blob || result.URL != pin.URL || !result.Summary.Authenticated {
		t.Fatalf("unexpected result: %#v", result)
	}
	published, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(published) != string(data) {
		t.Fatal("published DBX bytes differ")
	}
}

func authenticatedDBXFixture(t *testing.T) []byte {
	t.Helper()
	owner := GUID{7, 6, 5, [8]byte{4, 3, 2, 1}}
	digest := sha256.Sum256([]byte("pinned-revocation"))
	payload := signatureList(certSHA256GUID, owner, digest[:])
	certificate := []byte{0x30, 0x01, 0x00}
	certificateLength := 24 + len(certificate)
	data := make([]byte, 16+certificateLength+len(payload))
	when := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	binary.LittleEndian.PutUint16(data[0:2], uint16(when.Year()))
	data[2], data[3], data[4], data[5], data[6] = byte(when.Month()), byte(when.Day()), byte(when.Hour()), byte(when.Minute()), byte(when.Second())
	binary.LittleEndian.PutUint32(data[16:20], uint32(certificateLength))
	binary.LittleEndian.PutUint16(data[20:22], 0x0200)
	binary.LittleEndian.PutUint16(data[22:24], 0x0ef1)
	copy(data[24:40], encodeGUID(certPKCS7GUID))
	copy(data[40:40+len(certificate)], certificate)
	copy(data[16+certificateLength:], payload)
	return data
}
