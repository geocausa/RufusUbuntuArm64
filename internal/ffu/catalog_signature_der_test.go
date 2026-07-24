package ffu

import (
	"bytes"
	"crypto/sha256"
	"sort"
	"strings"
	"testing"
)

func TestParseCatalogSignatureSignerRequiresCanonicalDERAttributeOrder(t *testing.T) {
	contentTypeAttribute := derSequence(derOID(oidPKCS9ContentType), derSet(derOID(oidMicrosoftCTL)))
	messageDigest := sha256.Sum256([]byte("catalog content"))
	messageDigestAttribute := derSequence(derOID(oidPKCS9MessageDigest), derSet(derOctet(messageDigest[:])))
	attributes := [][]byte{contentTypeAttribute, messageDigestAttribute}
	sort.Slice(attributes, func(left, right int) bool {
		return bytes.Compare(attributes[left], attributes[right]) < 0
	})
	attributes[0], attributes[1] = attributes[1], attributes[0]

	signerDER := derSequence(
		derInteger(3),
		derContextPrimitive(0, bytes.Repeat([]byte{0x22}, 20)),
		derAlgorithm(oidSHA256),
		derContext(0, attributes...),
		derSequence(derOID(oidEd25519)),
		derOctet(bytes.Repeat([]byte{0x33}, 64)),
	)
	value, rest, err := parseDERValue(signerDER, &derBudget{})
	if err != nil || len(rest) != 0 {
		t.Fatalf("parse signer fixture: rest=%d error=%v", len(rest), err)
	}
	_, err = parseCatalogSignatureSigner(value, &derBudget{})
	if err == nil || !strings.Contains(err.Error(), "canonical DER SET order") {
		t.Fatalf("error=%v", err)
	}
}

func TestParseCatalogSignatureSignerAcceptsCanonicalDERAttributeOrder(t *testing.T) {
	contentTypeAttribute := derSequence(derOID(oidPKCS9ContentType), derSet(derOID(oidMicrosoftCTL)))
	messageDigest := sha256.Sum256([]byte("catalog content"))
	messageDigestAttribute := derSequence(derOID(oidPKCS9MessageDigest), derSet(derOctet(messageDigest[:])))
	attributes := [][]byte{contentTypeAttribute, messageDigestAttribute}
	sort.Slice(attributes, func(left, right int) bool {
		return bytes.Compare(attributes[left], attributes[right]) < 0
	})

	signerDER := derSequence(
		derInteger(3),
		derContextPrimitive(0, bytes.Repeat([]byte{0x22}, 20)),
		derAlgorithm(oidSHA256),
		derContext(0, attributes...),
		derSequence(derOID(oidEd25519)),
		derOctet(bytes.Repeat([]byte{0x33}, 64)),
	)
	value, rest, err := parseDERValue(signerDER, &derBudget{})
	if err != nil || len(rest) != 0 {
		t.Fatalf("parse signer fixture: rest=%d error=%v", len(rest), err)
	}
	if _, err := parseCatalogSignatureSigner(value, &derBudget{}); err != nil {
		t.Fatal(err)
	}
}

func TestCatalogSignerSHA1RemainsUnsupported(t *testing.T) {
	if _, _, err := calculateCatalogContentDigest(oidSHA1, []byte("catalog content")); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("digest error=%v", err)
	}
	if _, _, err := catalogSignatureAlgorithm(oidSHA1, oidSHA1WithRSA); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("signature error=%v", err)
	}
}
