package secureboot

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseFileRequiresBoundedRegularInput(t *testing.T) {
	directory := t.TempDir()
	if _, err := ParseFile(directory); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("directory error=%v", err)
	}
	path := filepath.Join(directory, "large.dbx")
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readStableDBXFile(path, 4); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("size-limit error=%v", err)
	}
}

func TestFirmwareDBXFromExactFile(t *testing.T) {
	owner := GUID{1, 2, 3, [8]byte{4, 5, 6, 7, 8, 9, 10, 11}}
	digest := sha256.Sum256([]byte("firmware-revocation"))
	payload := signatureList(certSHA256GUID, owner, digest[:])
	data := make([]byte, 4+len(payload))
	binary.LittleEndian.PutUint32(data[:4], 0x27)
	copy(data[4:], payload)
	path := filepath.Join(t.TempDir(), "dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := firmwareDBXFromPath(path)
	if err != nil {
		t.Fatal(err)
	}
	if db.Source != path || !db.IsSHA256Revoked(digest) {
		t.Fatalf("unexpected firmware DBX: %#v", db.Summary())
	}
	if err := os.WriteFile(path, data[:4], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := firmwareDBXFromPath(path); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("short firmware variable error=%v", err)
	}
}

func TestParseEFITimeRejectsNormalizedValues(t *testing.T) {
	valid := make([]byte, 16)
	binary.LittleEndian.PutUint16(valid[0:2], 2024)
	valid[2], valid[3], valid[4], valid[5], valid[6] = 2, 29, 23, 59, 59
	binary.LittleEndian.PutUint32(valid[8:12], 999_999_999)
	when, ok := parseEFITime(valid)
	if !ok || !when.Equal(time.Date(2024, 2, 29, 23, 59, 59, 999_999_999, time.UTC)) {
		t.Fatalf("valid EFI time rejected: %v %t", when, ok)
	}
	cases := map[string]func([]byte){
		"impossible day":            func(value []byte) { value[3] = 30 },
		"leap second normalization": func(value []byte) { value[6] = 60 },
		"pad1":                      func(value []byte) { value[7] = 1 },
		"pad2":                      func(value []byte) { value[15] = 1 },
		"nanosecond overflow":       func(value []byte) { binary.LittleEndian.PutUint32(value[8:12], 1_000_000_000) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := append([]byte(nil), valid...)
			mutate(candidate)
			if parsed, ok := parseEFITime(candidate); ok {
				t.Fatalf("malformed EFI time accepted as %v", parsed)
			}
		})
	}
}

func TestValidateDBXRedirectPolicy(t *testing.T) {
	trusted, _ := http.NewRequest(http.MethodGet, "https://objects.githubusercontent.com/path", nil)
	if err := validateDBXRedirect(trusted, []*http.Request{{}}); err != nil {
		t.Fatalf("trusted redirect rejected: %v", err)
	}
	cases := []struct {
		name string
		url  string
	}{
		{"plaintext downgrade", "http://github.com/path"},
		{"foreign host", "https://example.com/path"},
		{"URL credentials", "https://user:pass@github.com/path"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, test.url, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateDBXRedirect(request, []*http.Request{{}}); err == nil {
				t.Fatal("unsafe redirect accepted")
			}
		})
	}
	tooMany, _ := http.NewRequest(http.MethodGet, "https://github.com/path", nil)
	if err := validateDBXRedirect(tooMany, make([]*http.Request, 5)); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Fatalf("redirect-count error=%v", err)
	}
	if err := validateDBXRedirect(&http.Request{URL: (*url.URL)(nil)}, nil); err == nil {
		t.Fatal("nil redirect URL accepted")
	}
}

func TestDownloadMicrosoftDBXRequiresContext(t *testing.T) {
	if _, err := DownloadMicrosoftDBX(nil, "arm64", ""); err == nil || !strings.Contains(err.Error(), "context") {
		t.Fatalf("nil context error=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DownloadMicrosoftDBX(ctx, "unsupported", ""); err == nil || !strings.Contains(err.Error(), "architecture") {
		t.Fatalf("architecture error=%v", err)
	}
}
