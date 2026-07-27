package ffu

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha1" // #nosec G505 -- fixture encodes the legacy catalog member digest required by the format under test.
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"math/big"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestVerifyCatalogSignatureWithoutPublisherTrust(t *testing.T) {
	data := signedCatalogFixture(t, signedCatalogOptions{})
	inspection, hashPlan, memberPlan, signaturePlan, err := VerifyCatalogSignature(context.Background(), bytes.NewReader(data), uint64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if inspection.ImageHeaderOffset != 4096 || hashPlan.HashEntryCount != 6 || !memberPlan.HashTableMemberMatches {
		t.Fatalf("unexpected prerequisite plans: inspection=%#v hash=%#v member=%#v", inspection, hashPlan, memberPlan)
	}
	if !signaturePlan.ContentDigestVerified || !signaturePlan.SignatureVerificationAttempted || !signaturePlan.CryptographicSignatureVerified {
		t.Fatalf("signature did not verify: %#v", signaturePlan)
	}
	if signaturePlan.CertificateChainBuilt || signaturePlan.PublisherTrusted || signaturePlan.HashTableCatalogAuthenticated {
		t.Fatalf("cryptographic verification silently became publisher trust: %#v", signaturePlan)
	}
	if signaturePlan.DigestAlgorithmOID != oidSHA256 || signaturePlan.SignatureAlgorithmOID != oidEd25519 {
		t.Fatalf("unexpected algorithms: %#v", signaturePlan)
	}
	if signaturePlan.CertificateIndex != 0 || signaturePlan.CertificateSHA256 == "" || !strings.Contains(signaturePlan.CertificateSubject, "RufusArm64 FFU Signature Test") {
		t.Fatalf("unexpected certificate binding: %#v", signaturePlan)
	}
	if signaturePlan.EncodedMessageDigest != signaturePlan.CalculatedMessageDigest || len(signaturePlan.PlanSHA256) != 64 {
		t.Fatalf("unexpected digest state: %#v", signaturePlan)
	}
	if !containsString(signaturePlan.SignedAttributeOIDs, oidPKCS9ContentType) || !containsString(signaturePlan.SignedAttributeOIDs, oidPKCS9MessageDigest) {
		t.Fatalf("missing mandatory signed attributes: %#v", signaturePlan.SignedAttributeOIDs)
	}

	_, _, _, second, err := VerifyCatalogSignature(context.Background(), bytes.NewReader(data), uint64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if second.PlanSHA256 != signaturePlan.PlanSHA256 {
		t.Fatalf("signature plan digest changed: %s != %s", second.PlanSHA256, signaturePlan.PlanSHA256)
	}
}

func TestVerifyCatalogSignatureRejectsWrongContentDigestBeforeSignature(t *testing.T) {
	data := signedCatalogFixture(t, signedCatalogOptions{wrongMessageDigest: true})
	_, _, _, plan, err := VerifyCatalogSignature(context.Background(), bytes.NewReader(data), uint64(len(data)))
	if err == nil || !strings.Contains(err.Error(), "message-digest attribute does not match") {
		t.Fatalf("error=%v", err)
	}
	if plan.ContentDigestVerified || plan.SignatureVerificationAttempted || plan.CryptographicSignatureVerified {
		t.Fatalf("signature was attempted after content-digest failure: %#v", plan)
	}
	if plan.EncodedMessageDigest == plan.CalculatedMessageDigest || len(plan.PlanSHA256) != 64 {
		t.Fatalf("missing deterministic digest-mismatch evidence: %#v", plan)
	}
}

func TestVerifyCatalogSignatureRejectsCorruptedSignature(t *testing.T) {
	data := signedCatalogFixture(t, signedCatalogOptions{corruptSignature: true})
	_, _, _, plan, err := VerifyCatalogSignature(context.Background(), bytes.NewReader(data), uint64(len(data)))
	if err == nil || !strings.Contains(err.Error(), "verify FFU catalog SignerInfo signature") {
		t.Fatalf("error=%v", err)
	}
	if !plan.ContentDigestVerified || !plan.SignatureVerificationAttempted || plan.CryptographicSignatureVerified {
		t.Fatalf("unexpected corrupted-signature state: %#v", plan)
	}
}

func TestVerifyCatalogSignatureRejectsWrongEmbeddedKey(t *testing.T) {
	data := signedCatalogFixture(t, signedCatalogOptions{wrongEmbeddedKey: true})
	_, _, _, plan, err := VerifyCatalogSignature(context.Background(), bytes.NewReader(data), uint64(len(data)))
	if err == nil || !strings.Contains(err.Error(), "verify FFU catalog SignerInfo signature") {
		t.Fatalf("error=%v", err)
	}
	if !plan.ContentDigestVerified || !plan.SignatureVerificationAttempted || plan.CryptographicSignatureVerified {
		t.Fatalf("unexpected wrong-key state: %#v", plan)
	}
}

func TestVerifyCatalogSignatureRejectsAmbiguousSignerCertificate(t *testing.T) {
	data := signedCatalogFixture(t, signedCatalogOptions{duplicateCertificate: true})
	_, _, _, _, err := VerifyCatalogSignature(context.Background(), bytes.NewReader(data), uint64(len(data)))
	if err == nil || !strings.Contains(err.Error(), "matches multiple embedded certificates") {
		t.Fatalf("error=%v", err)
	}
}

func TestVerifyCatalogSignatureRejectsMandatoryAttributeErrors(t *testing.T) {
	tests := []struct {
		name    string
		options signedCatalogOptions
		want    string
	}{
		{name: "missing message digest", options: signedCatalogOptions{omitMessageDigest: true}, want: "requires exactly one content-type and one message-digest"},
		{name: "duplicate message digest", options: signedCatalogOptions{duplicateMessageDigest: true}, want: "duplicate message-digest attributes"},
		{name: "missing content type", options: signedCatalogOptions{omitContentType: true}, want: "requires exactly one content-type and one message-digest"},
		{name: "duplicate content type", options: signedCatalogOptions{duplicateContentType: true}, want: "duplicate content-type attributes"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := signedCatalogFixture(t, test.options)
			_, _, _, _, err := VerifyCatalogSignature(context.Background(), bytes.NewReader(data), uint64(len(data)))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want substring %q", err, test.want)
			}
		})
	}
}

func TestVerifyCatalogSignatureRejectsUnsupportedAlgorithm(t *testing.T) {
	data := signedCatalogFixture(t, signedCatalogOptions{signatureOID: "1.2.3.4.5"})
	_, _, _, _, err := VerifyCatalogSignature(context.Background(), bytes.NewReader(data), uint64(len(data)))
	if err == nil || !strings.Contains(err.Error(), "unsupported FFU catalog signature/digest combination") {
		t.Fatalf("error=%v", err)
	}
}

func TestVerifyCatalogSignatureRejectsMissingSignerCertificate(t *testing.T) {
	data := signedCatalogFixture(t, signedCatalogOptions{omitCertificate: true})
	_, _, _, _, err := VerifyCatalogSignature(context.Background(), bytes.NewReader(data), uint64(len(data)))
	if err == nil || !strings.Contains(err.Error(), "contains no embedded certificates") {
		t.Fatalf("error=%v", err)
	}
}

func TestVerifyCatalogSignatureHonoursCancellationAndNilContext(t *testing.T) {
	data := signedCatalogFixture(t, signedCatalogOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, _, err := VerifyCatalogSignature(ctx, bytes.NewReader(data), uint64(len(data))); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error=%v", err)
	}
	var nilContext context.Context
	if _, _, _, _, err := VerifyCatalogSignature(nilContext, bytes.NewReader(data), uint64(len(data))); err == nil || !strings.Contains(err.Error(), "context is nil") {
		t.Fatalf("nil error=%v", err)
	}
}

func FuzzParseCatalogSignatureEnvelopeDoesNotPanic(f *testing.F) {
	valid := signedCatalogBytesForFuzz()
	f.Add(valid)
	f.Add([]byte("not a signed catalog"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseCatalogSignatureEnvelope(data)
	})
}

type signedCatalogOptions struct {
	wrongMessageDigest     bool
	corruptSignature       bool
	wrongEmbeddedKey       bool
	duplicateCertificate   bool
	omitCertificate        bool
	omitMessageDigest      bool
	duplicateMessageDigest bool
	omitContentType        bool
	duplicateContentType   bool
	signatureOID           string
}

func signedCatalogFixture(t *testing.T, options signedCatalogOptions) []byte {
	t.Helper()
	data := validV1PlanFixture()
	table := fixtureHashTable(data)
	catalog := buildSignedCatalog(t, table, options)
	if 32+len(catalog)+len(table) >= 4096 {
		t.Fatalf("signed catalog fixture security area is too large: catalog=%d table=%d", len(catalog), len(table))
	}
	binary.LittleEndian.PutUint32(data[24:28], uint32(len(catalog)))
	binary.LittleEndian.PutUint32(data[28:32], uint32(len(table)))
	copy(data[32:32+len(catalog)], catalog)
	copy(data[32+len(catalog):32+len(catalog)+len(table)], table)
	return data
}

func signedCatalogBytesForFuzz() []byte {
	table := bytes.Repeat([]byte{0x21}, 2*sha256.Size)
	certificateDER, certificate, privateKey := signatureCertificateFixture(nil, 0x52, 52)
	return buildSignedCatalogDER(table, signedCatalogOptions{}, certificateDER, certificate, privateKey)
}

func buildSignedCatalog(t *testing.T, table []byte, options signedCatalogOptions) []byte {
	t.Helper()
	certificateDER, certificate, privateKey := signatureCertificateFixture(t, 0x52, 52)
	if options.wrongEmbeddedKey {
		certificateDER, certificate, _ = signatureCertificateFixture(t, 0x53, 52)
	}
	return buildSignedCatalogDER(table, options, certificateDER, certificate, privateKey)
}

func buildSignedCatalogDER(table []byte, options signedCatalogOptions, certificateDER []byte, certificate *x509.Certificate, privateKey ed25519.PrivateKey) []byte {
	memberDigest := sha1.Sum(table) // #nosec G401 -- fixture represents the legacy catalog member digest field.
	member := fixtureCatalogMember(catalogHashTableMember, oidSHA1, memberDigest[:])
	ctl := derSequence(
		derSequence(derOID("1.3.6.1.4.1.311.12.1.1")),
		derOctet([]byte("RufusArm64.Signature.Test")),
		derUTCTime(time.Date(2026, 7, 24, 13, 0, 0, 0, time.UTC)),
		derSequence(derOID("1.3.6.1.4.1.311.12.1.2")),
		derSequence(member),
	)
	contentDigest := sha256.Sum256(ctl)
	messageDigest := append([]byte(nil), contentDigest[:]...)
	if options.wrongMessageDigest {
		messageDigest[0] ^= 0xff
	}
	contentTypeAttribute := derSequence(derOID(oidPKCS9ContentType), derSet(derOID(oidMicrosoftCTL)))
	messageDigestAttribute := derSequence(derOID(oidPKCS9MessageDigest), derSet(derOctet(messageDigest)))
	attributes := make([][]byte, 0, 4)
	if !options.omitContentType {
		attributes = append(attributes, contentTypeAttribute)
	}
	if options.duplicateContentType {
		attributes = append(attributes, append([]byte(nil), contentTypeAttribute...))
	}
	if !options.omitMessageDigest {
		attributes = append(attributes, messageDigestAttribute)
	}
	if options.duplicateMessageDigest {
		attributes = append(attributes, append([]byte(nil), messageDigestAttribute...))
	}
	sort.Slice(attributes, func(left, right int) bool {
		return bytes.Compare(attributes[left], attributes[right]) < 0
	})
	signedAttributesDER := derSet(attributes...)
	signature := ed25519.Sign(privateKey, signedAttributesDER)
	if options.corruptSignature {
		signature[0] ^= 0xff
	}
	signatureOID := options.signatureOID
	if signatureOID == "" {
		signatureOID = oidEd25519
	}
	identifier := derSequence(certificate.RawIssuer, derBigInteger(certificate.SerialNumber))
	signer := derSequence(
		derInteger(1),
		identifier,
		derAlgorithm(oidSHA256),
		derContext(0, attributes...),
		derSequence(derOID(signatureOID)),
		derOctet(signature),
	)
	signedParts := [][]byte{
		derInteger(1),
		derSet(derAlgorithm(oidSHA256)),
		derSequence(derOID(oidMicrosoftCTL), derContext(0, derOctet(ctl))),
	}
	if !options.omitCertificate {
		certificateParts := [][]byte{certificateDER}
		if options.duplicateCertificate {
			certificateParts = append(certificateParts, append([]byte(nil), certificateDER...))
		}
		signedParts = append(signedParts, derContext(0, certificateParts...))
	}
	signedParts = append(signedParts, derSet(signer))
	return derSequence(derOID(oidPKCS7SignedData), derContext(0, derSequence(signedParts...)))
}

func signatureCertificateFixture(t *testing.T, seedByte byte, serial int64) ([]byte, *x509.Certificate, ed25519.PrivateKey) {
	if t != nil {
		t.Helper()
	}
	seed := bytes.Repeat([]byte{seedByte}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName:   "RufusArm64 FFU Signature Test",
			Organization: []string{"RufusArm64 Tests"},
		},
		Issuer:                pkix.Name{CommonName: "RufusArm64 FFU Signature Test"},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    x509.PureEd25519,
	}
	certificateDER, err := x509.CreateCertificate(nil, template, template, publicKey, privateKey)
	if err != nil {
		if t != nil {
			t.Fatal(err)
		}
		panic(err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		if t != nil {
			t.Fatal(err)
		}
		panic(err)
	}
	return certificateDER, certificate, privateKey
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
