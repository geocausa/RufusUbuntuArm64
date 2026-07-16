package secureboot

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"
)

func encodeGUID(g GUID) []byte {
	result := make([]byte, 16)
	binary.LittleEndian.PutUint32(result[0:4], g.Data1)
	binary.LittleEndian.PutUint16(result[4:6], g.Data2)
	binary.LittleEndian.PutUint16(result[6:8], g.Data3)
	copy(result[8:16], g.Data4[:])
	return result
}

func signatureList(kind GUID, owner GUID, values ...[]byte) []byte {
	signatureSize := 16 + len(values[0])
	listSize := 28 + signatureSize*len(values)
	result := make([]byte, listSize)
	copy(result[:16], encodeGUID(kind))
	binary.LittleEndian.PutUint32(result[16:20], uint32(listSize))
	binary.LittleEndian.PutUint32(result[20:24], 0)
	binary.LittleEndian.PutUint32(result[24:28], uint32(signatureSize))
	offset := 28
	for _, value := range values {
		copy(result[offset:offset+16], encodeGUID(owner))
		copy(result[offset+16:offset+signatureSize], value)
		offset += signatureSize
	}
	return result
}

func TestParseRawSignatureLists(t *testing.T) {
	owner := GUID{1, 2, 3, [8]byte{4, 5, 6, 7, 8, 9, 10, 11}}
	first := sha256.Sum256([]byte("first"))
	second := sha256.Sum256([]byte("second"))
	cert := []byte{0x30, 0x03, 0x01, 0x02, 0x03}
	data := append(signatureList(certSHA256GUID, owner, first[:], second[:]), signatureList(certX509GUID, owner, cert)...)
	db, err := Parse(data, "synthetic")
	if err != nil {
		t.Fatal(err)
	}
	if db.Authenticated || db.SignatureListCount != 2 || db.SignatureCount != 3 || len(db.SHA256) != 2 || len(db.X509Certificates) != 1 {
		t.Fatalf("unexpected DBX: %#v", db.Summary())
	}
	if !db.IsSHA256Revoked(first) || !db.IsSHA256Revoked(second) {
		t.Fatal("expected hashes were not indexed")
	}
}

func TestParseAuthenticatedUpdate(t *testing.T) {
	owner := GUID{9, 8, 7, [8]byte{6, 5, 4, 3, 2, 1}}
	digest := sha256.Sum256([]byte("revoked"))
	payload := signatureList(certSHA256GUID, owner, digest[:])
	certData := []byte{0x30, 0x01, 0x00}
	certLength := 24 + len(certData)
	data := make([]byte, 16+certLength+len(payload))
	when := time.Date(2026, 7, 16, 12, 30, 5, 0, time.UTC)
	binary.LittleEndian.PutUint16(data[0:2], uint16(when.Year()))
	data[2], data[3], data[4], data[5], data[6] = byte(when.Month()), byte(when.Day()), byte(when.Hour()), byte(when.Minute()), byte(when.Second())
	binary.LittleEndian.PutUint32(data[16:20], uint32(certLength))
	binary.LittleEndian.PutUint16(data[20:22], 0x0200)
	binary.LittleEndian.PutUint16(data[22:24], 0x0ef1)
	copy(data[24:40], encodeGUID(certPKCS7GUID))
	copy(data[40:40+len(certData)], certData)
	copy(data[16+certLength:], payload)
	db, err := Parse(data, "authenticated")
	if err != nil {
		t.Fatal(err)
	}
	if !db.Authenticated || db.Timestamp == nil || !db.Timestamp.Equal(when) || db.PayloadOffset != 16+certLength {
		t.Fatalf("authentication metadata not parsed: %#v", db.Summary())
	}
}

func TestMalformedSignatureListRejected(t *testing.T) {
	data := make([]byte, 28)
	copy(data[:16], encodeGUID(certSHA256GUID))
	binary.LittleEndian.PutUint32(data[16:20], 4096)
	binary.LittleEndian.PutUint32(data[24:28], 48)
	if _, err := Parse(data, "broken"); err == nil {
		t.Fatal("malformed DBX accepted")
	}
}

func TestArchitectureAndURL(t *testing.T) {
	arch, err := ArchitectureName("aarch64")
	if err != nil || arch != "arm64" {
		t.Fatalf("arch=%q err=%v", arch, err)
	}
	url, err := MicrosoftDBXURL("arm64")
	if err != nil || url != "https://raw.githubusercontent.com/microsoft/secureboot_objects/main/PostSignedObjects/DBX/arm64/DBXUpdate.bin" {
		t.Fatalf("url=%q err=%v", url, err)
	}
}

func TestFileHashRecorded(t *testing.T) {
	owner := GUID{}
	digest := sha256.Sum256([]byte("x"))
	data := signatureList(certSHA256GUID, owner, digest[:])
	db, err := Parse(data, "x")
	if err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256(data)
	if db.FileSHA256 != hex.EncodeToString(expected[:]) {
		t.Fatalf("file hash=%s", db.FileSHA256)
	}
}
