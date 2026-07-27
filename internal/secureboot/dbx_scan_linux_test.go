//go:build linux

package secureboot

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func databaseForPEHashes(t *testing.T, images ...[]byte) *Database {
	t.Helper()
	db := &Database{SHA256: make(map[[sha256.Size]byte]struct{}), X509: make(map[[sha256.Size]byte]struct{})}
	for _, image := range images {
		hash, err := AuthenticodeSHA256(image)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := hex.DecodeString(hash.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		var digest [sha256.Size]byte
		copy(digest[:], decoded)
		db.SHA256[digest] = struct{}{}
	}
	return db
}

func TestScanEFIDirectoryContextIncludesBootmgrAndEFI(t *testing.T) {
	root := t.TempDir()
	bootmgr := syntheticPE([]byte("root boot manager"), nil)
	fallback := syntheticPE([]byte("UEFI fallback loader"), nil)
	if err := os.WriteFile(filepath.Join(root, "bootmgr"), bootmgr, 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "EFI", "BOOT", "BOOTAA64.EFI")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, fallback, 0o600); err != nil {
		t.Fatal(err)
	}

	results, err := ScanEFIDirectoryContext(context.Background(), root, databaseForPEHashes(t, bootmgr, fallback), 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("results=%#v", results)
	}
	if results[0].Path != "EFI/BOOT/BOOTAA64.EFI" || results[1].Path != "bootmgr" {
		t.Fatalf("unexpected deterministic paths: %#v", results)
	}
	for _, result := range results {
		if result.Error != "" || !result.DirectHashRevoked || !result.X509RevocationChecked {
			t.Fatalf("unexpected DBX result: %#v", result)
		}
	}
}

func TestScanEFIDirectoryCompatibilityWrapperUsesDescriptorScanner(t *testing.T) {
	root := t.TempDir()
	image := syntheticPE([]byte("compatibility wrapper"), nil)
	if err := os.WriteFile(filepath.Join(root, "bootmgr"), image, 0o600); err != nil {
		t.Fatal(err)
	}
	results, err := ScanEFIDirectory(root, databaseForPEHashes(t, image), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Path != "bootmgr" || !results[0].DirectHashRevoked {
		t.Fatalf("compatibility wrapper returned %#v", results)
	}
}

func TestScanEFIDirectoryRejectsEntryReplacementBeforeOpen(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "bootmgr")
	replacement := filepath.Join(root, "replacement")
	if err := os.WriteFile(path, syntheticPE([]byte("first"), nil), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(replacement, syntheticPE([]byte("second"), nil), 0o600); err != nil {
		t.Fatal(err)
	}
	changed := false
	hook := func(stage, relative string) {
		if changed || stage != "entry-before-open" || relative != "bootmgr" {
			return
		}
		changed = true
		if err := os.Rename(path, filepath.Join(root, "original")); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(replacement, path); err != nil {
			t.Fatal(err)
		}
	}
	_, err := scanEFIDirectoryContextWithHook(context.Background(), root, databaseForPEHashes(t), 1, hook)
	if err == nil || !strings.Contains(err.Error(), "entry changed during validation") {
		t.Fatalf("replacement race was not rejected: %v", err)
	}
}

func TestWalkDBXDirectoryCountsUnrelatedEntries(t *testing.T) {
	root := t.TempDir()
	for index := 0; index < 4; index++ {
		if err := os.WriteFile(filepath.Join(root, string(rune('a'+index))+".txt"), []byte("unrelated"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, rootFile, err := openDBXScanRoot(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rootFile.Close()
	limits := &uefiTraversalLimits{maxFiles: 1, maxEntries: 3, maxDepth: 2, maxTotalBytes: 4096}
	if err := limits.validate(); err != nil {
		t.Fatal(err)
	}
	var files []uefiMediaFile
	err = walkDBXDirectory(context.Background(), rootFile, "", 0, limits, nil, &files)
	if err == nil || !strings.Contains(err.Error(), "more than 3 total entries") {
		t.Fatalf("unrelated entry flood was not bounded: %v", err)
	}
}

func TestScanEFIDirectoryHonorsCancellationAndRequiresDatabase(t *testing.T) {
	root := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ScanEFIDirectoryContext(ctx, root, databaseForPEHashes(t), 1)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation was not preserved: %v", err)
	}
	if _, err := ScanEFIDirectoryContext(context.Background(), root, nil, 1); err == nil || !strings.Contains(err.Error(), "database is required") {
		t.Fatalf("nil database was accepted: %v", err)
	}
}

func TestCheckPEFileUsesOneByteSnapshotForHashAndCertificateFacts(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "Single snapshot signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	image := syntheticPE([]byte("one stable snapshot"), winCertificate(testPKCS7WithCertificate(t, certificateDER)))
	db := databaseForPEHashes(t, image)
	db.X509[sha256.Sum256(certificateDER)] = struct{}{}
	path := filepath.Join(t.TempDir(), "bootaa64.efi")
	if err := os.WriteFile(path, image, 0o600); err != nil {
		t.Fatal(err)
	}
	result := CheckPEFile(path, db)
	if result.Error != "" || !result.DirectHashRevoked || !result.X509CertificateRevoked || result.EmbeddedCertificates != 1 {
		t.Fatalf("single-snapshot check failed: %#v", result)
	}
}

func TestCheckPEFileRejectsNilDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bootaa64.efi")
	if err := os.WriteFile(path, syntheticPE([]byte("nil database"), nil), 0o600); err != nil {
		t.Fatal(err)
	}
	result := CheckPEFile(path, nil)
	if !strings.Contains(result.Error, "database is required") {
		t.Fatalf("nil database was not rejected: %#v", result)
	}
}
