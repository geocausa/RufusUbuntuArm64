package secureboot

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func syntheticPE(sectionData, certificate []byte) []byte {
	peOffset := 0x80
	optionalSize := 0xf0
	headersSize := 0x200
	sectionOffset := 0x200
	sectionSize := 0x200
	certOffset := sectionOffset + sectionSize
	total := certOffset + len(certificate)
	data := make([]byte, total)
	data[0], data[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(data[0x3c:0x40], uint32(peOffset))
	copy(data[peOffset:peOffset+4], []byte{'P', 'E', 0, 0})
	coff := peOffset + 4
	binary.LittleEndian.PutUint16(data[coff:coff+2], 0xaa64)
	binary.LittleEndian.PutUint16(data[coff+2:coff+4], 1)
	binary.LittleEndian.PutUint16(data[coff+16:coff+18], uint16(optionalSize))
	optional := coff + 20
	binary.LittleEndian.PutUint16(data[optional:optional+2], pe32PlusMagic)
	binary.LittleEndian.PutUint32(data[optional+60:optional+64], uint32(headersSize))
	binary.LittleEndian.PutUint32(data[optional+64:optional+68], 0x12345678)
	binary.LittleEndian.PutUint32(data[optional+108:optional+112], 16)
	security := optional + 112 + 4*8
	if len(certificate) > 0 {
		binary.LittleEndian.PutUint32(data[security:security+4], uint32(certOffset))
		binary.LittleEndian.PutUint32(data[security+4:security+8], uint32(len(certificate)))
	}
	section := optional + optionalSize
	copy(data[section:section+8], []byte(".text\x00\x00\x00"))
	binary.LittleEndian.PutUint32(data[section+16:section+20], uint32(sectionSize))
	binary.LittleEndian.PutUint32(data[section+20:section+24], uint32(sectionOffset))
	copy(data[sectionOffset:sectionOffset+sectionSize], sectionData)
	copy(data[certOffset:], certificate)
	return data
}

func TestAuthenticodeHashExcludesChecksumAndCertificate(t *testing.T) {
	section := make([]byte, 0x200)
	copy(section, []byte("bootloader payload"))
	first := syntheticPE(section, []byte("certificate one"))
	second := append([]byte(nil), first...)
	// Change the optional-header checksum and certificate bytes. Neither should
	// affect the Authenticode digest.
	peOffset := int(binary.LittleEndian.Uint32(second[0x3c:0x40]))
	optional := peOffset + 24
	binary.LittleEndian.PutUint32(second[optional+64:optional+68], 0xaabbccdd)
	copy(second[len(second)-len("certificate one"):], []byte("certificate two"))
	a, err := AuthenticodeSHA256(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := AuthenticodeSHA256(second)
	if err != nil {
		t.Fatal(err)
	}
	if a.SHA256 != b.SHA256 {
		t.Fatalf("excluded fields changed hash: %s != %s", a.SHA256, b.SHA256)
	}
	second[0x200] ^= 0xff
	c, err := AuthenticodeSHA256(second)
	if err != nil {
		t.Fatal(err)
	}
	if c.SHA256 == a.SHA256 {
		t.Fatal("section content change did not alter hash")
	}
}

func TestCheckPEFileMatchesDBXHash(t *testing.T) {
	pe := syntheticPE([]byte("revoked image"), nil)
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
	db := &Database{SHA256: map[[sha256.Size]byte]struct{}{digest: {}}}
	path := filepath.Join(t.TempDir(), "bootaa64.efi")
	if err := os.WriteFile(path, pe, 0o600); err != nil {
		t.Fatal(err)
	}
	result := CheckPEFile(path, db)
	if result.Error != "" || !result.DirectHashRevoked {
		t.Fatalf("result=%#v", result)
	}
}

func TestInvalidPERejected(t *testing.T) {
	if _, err := AuthenticodeSHA256([]byte("not a PE")); err == nil {
		t.Fatal("invalid PE accepted")
	}
}

func derElement(tag byte, content []byte) []byte {
	result := []byte{tag}
	switch {
	case len(content) < 0x80:
		result = append(result, byte(len(content)))
	case len(content) <= 0xff:
		result = append(result, 0x81, byte(len(content)))
	default:
		result = append(result, 0x82, byte(len(content)>>8), byte(len(content)))
	}
	return append(result, content...)
}

func testPKCS7WithCertificate(t *testing.T, certificate []byte) []byte {
	t.Helper()
	version, _ := asn1.Marshal(1)
	signedOID, _ := asn1.Marshal(oidPKCS7SignedData)
	dataOID, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1})
	signedData := derElement(0x30, bytes.Join([][]byte{
		version,
		derElement(0x31, nil),
		derElement(0x30, dataOID),
		derElement(0xa0, certificate),
		derElement(0x31, nil),
	}, nil))
	return derElement(0x30, append(signedOID, derElement(0xa0, signedData)...))
}

func winCertificate(pkcs7 []byte) []byte {
	length := 8 + len(pkcs7)
	padded := (length + 7) &^ 7
	result := make([]byte, padded)
	binary.LittleEndian.PutUint32(result[:4], uint32(length))
	binary.LittleEndian.PutUint16(result[4:6], 0x0200)
	binary.LittleEndian.PutUint16(result[6:8], 0x0002)
	copy(result[8:], pkcs7)
	return result
}

func TestCheckPEFileMatchesEmbeddedRevokedCertificate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "Revoked test signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pe := syntheticPE([]byte("signed image"), winCertificate(testPKCS7WithCertificate(t, certificateDER)))
	path := filepath.Join(t.TempDir(), "bootaa64.efi")
	if err := os.WriteFile(path, pe, 0o600); err != nil {
		t.Fatal(err)
	}
	db := &Database{SHA256: make(map[[sha256.Size]byte]struct{}), X509: map[[sha256.Size]byte]struct{}{sha256.Sum256(certificateDER): {}}}
	result := CheckPEFile(path, db)
	if result.Error != "" || !result.X509RevocationChecked || !result.X509CertificateRevoked || result.EmbeddedCertificates != 1 {
		t.Fatalf("result=%#v", result)
	}
}
