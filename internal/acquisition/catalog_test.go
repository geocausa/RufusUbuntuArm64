package acquisition

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testSigningKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	return privateKey.Public().(ed25519.PublicKey), privateKey
}

func validCatalogBytes(t *testing.T) []byte {
	t.Helper()
	catalog := Catalog{
		Schema:    SchemaVersion,
		Generated: "2026-07-16T10:00:00Z",
		Expires:   "2026-08-16T10:00:00Z",
		Images: []Image{{
			ID:            "ubuntu-24.04.2-arm64",
			Name:          "Ubuntu Desktop",
			Version:       "24.04.2 LTS",
			Architecture:  "arm64",
			Filename:      "ubuntu-24.04.2-desktop-arm64.iso",
			URL:           "https://releases.ubuntu.com/example.iso",
			SHA256:        strings.Repeat("ab", 32),
			Size:          5 * 1024 * 1024 * 1024,
			RedirectHosts: []string{"cdimage.ubuntu.com"},
		}},
	}
	data, err := json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestVerifyCatalog(t *testing.T) {
	publicKey, privateKey := testSigningKey()
	data := validCatalogBytes(t)
	signature := ed25519.Sign(privateKey, data)
	verified, err := VerifyCatalog(data, []byte(base64.StdEncoding.EncodeToString(signature)), []byte(base64.StdEncoding.EncodeToString(publicKey)), time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if verified.Schema != SchemaVersion || len(verified.Images) != 1 || verified.SHA256 == "" {
		t.Fatalf("unexpected verified catalog: %+v", verified)
	}
	image, err := verified.Find("UBUNTU-24.04.2-ARM64")
	if err != nil || image.Architecture != "arm64" {
		t.Fatalf("find image: %+v, %v", image, err)
	}
}

func TestVerifyCatalogRejectsTamperingAndExpiry(t *testing.T) {
	publicKey, privateKey := testSigningKey()
	data := validCatalogBytes(t)
	signature := ed25519.Sign(privateKey, data)
	tampered := append([]byte(nil), data...)
	tampered[len(tampered)-2] ^= 1
	if _, err := VerifyCatalog(tampered, signature, publicKey, time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("tampered catalog was accepted")
	}
	if _, err := VerifyCatalog(data, signature, publicKey, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired catalog error = %v", err)
	}
}

func TestCatalogValidationRejectsUnsafeEntries(t *testing.T) {
	publicKey, privateKey := testSigningKey()
	base := validCatalogBytes(t)
	var catalog Catalog
	if err := json.Unmarshal(base, &catalog); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*Catalog)
	}{
		{"non https", func(c *Catalog) { c.Images[0].URL = "http://releases.ubuntu.com/example.iso" }},
		{"path filename", func(c *Catalog) { c.Images[0].Filename = "../image.iso" }},
		{"bad digest", func(c *Catalog) { c.Images[0].SHA256 = "abcd" }},
		{"private redirect", func(c *Catalog) { c.Images[0].RedirectHosts = []string{"127.0.0.1"} }},
		{"duplicate id", func(c *Catalog) { c.Images = append(c.Images, c.Images[0]) }},
		{"unknown architecture separator", func(c *Catalog) { c.Images[0].Architecture = "arm64 / amd64" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			copyCatalog := catalog
			copyCatalog.Images = append([]Image(nil), catalog.Images...)
			test.mutate(&copyCatalog)
			data, err := json.Marshal(copyCatalog)
			if err != nil {
				t.Fatal(err)
			}
			signature := ed25519.Sign(privateKey, data)
			if _, err := VerifyCatalog(data, signature, publicKey, time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)); err == nil {
				t.Fatal("unsafe catalog entry was accepted")
			}
		})
	}
}

func TestCatalogRejectsUnknownFields(t *testing.T) {
	publicKey, privateKey := testSigningKey()
	data := []byte(`{"schema":1,"generated":"2026-07-16T10:00:00Z","expires":"2026-08-16T10:00:00Z","unknown":true,"images":[]}`)
	signature := ed25519.Sign(privateKey, data)
	if _, err := VerifyCatalog(data, signature, publicKey, time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field error = %v", err)
	}
}
