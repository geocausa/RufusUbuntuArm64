package ffu

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

var trustEvaluationTime = time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)

func TestParseTrustBundleValidatesStructureWithoutActivatingTrust(t *testing.T) {
	rootB := trustRootDocument(t, "oem.root", 0x42, 42)
	rootA := trustRootDocument(t, "microsoft.root", 0x41, 41)
	distrusted := strings.Repeat("ab", sha256.Size)
	document := TrustBundleDocument{
		Schema:           ffuTrustBundleSchema,
		Purpose:          ffuTrustBundlePurpose,
		Sequence:         7,
		GeneratedAt:      "2026-07-01T00:00:00Z",
		ExpiresAt:        "2027-07-01T00:00:00Z",
		Roots:            []TrustAnchorDocument{rootB, rootA},
		DistrustedSHA256: []string{distrusted},
	}
	data := marshalTrustBundle(t, document)
	plan, err := ParseTrustBundleBytes(data, 5, trustEvaluationTime)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.BundleStructureValidated || plan.BundleSignatureAuthenticated || plan.TrustAnchorsActivated {
		t.Fatalf("unexpected bundle state: %#v", plan)
	}
	if plan.HostTLSStoreConsulted || plan.CertificateChainBuilt || plan.PublisherTrusted {
		t.Fatalf("parsing silently became a trust decision: %#v", plan)
	}
	if plan.Sequence != 7 || plan.MinimumAcceptedSequence != 5 || plan.RootCount != 2 || plan.DistrustedCount != 1 {
		t.Fatalf("unexpected bundle accounting: %#v", plan)
	}
	if plan.Roots[0].ID != "microsoft.root" || plan.Roots[1].ID != "oem.root" {
		t.Fatalf("roots were not normalized deterministically: %#v", plan.Roots)
	}
	for _, root := range plan.Roots {
		if !root.SelfSigned || !root.IsCA || !root.CanSignCertificates || len(root.CertificateSHA256) != 64 {
			t.Fatalf("unexpected root metadata: %#v", root)
		}
	}
	if len(plan.BundleSHA256) != 64 || len(plan.PlanSHA256) != 64 {
		t.Fatalf("missing deterministic digests: %#v", plan)
	}
	second, err := ParseTrustBundle(bytes.NewReader(data), 5, trustEvaluationTime)
	if err != nil {
		t.Fatal(err)
	}
	if second.PlanSHA256 != plan.PlanSHA256 || second.BundleSHA256 != plan.BundleSHA256 {
		t.Fatalf("bundle plan changed: %#v %#v", plan, second)
	}
}

func TestParseTrustBundleEnforcesRollbackAndValidityWindow(t *testing.T) {
	document := validTrustBundleDocument(t)
	tests := []struct {
		name       string
		minimum    uint64
		evaluation time.Time
		want       string
	}{
		{name: "rollback", minimum: document.Sequence + 1, evaluation: trustEvaluationTime, want: "below rollback floor"},
		{name: "not yet valid", minimum: 0, evaluation: time.Date(2026, 6, 30, 23, 59, 59, 0, time.UTC), want: "not valid before"},
		{name: "expired", minimum: 0, evaluation: time.Date(2027, 7, 1, 0, 0, 0, 0, time.UTC), want: "expired"},
	}
	data := marshalTrustBundle(t, document)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseTrustBundleBytes(data, test.minimum, test.evaluation)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want substring %q", err, test.want)
			}
		})
	}
}

func TestParseTrustBundleRejectsStrictJSONAndMetadataErrors(t *testing.T) {
	valid := validTrustBundleDocument(t)
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{name: "unknown field", data: append(bytes.TrimSuffix(marshalTrustBundle(t, valid), []byte("}")), []byte(",\"unknown\":true}")...), want: "unknown field"},
		{name: "multiple values", data: append(marshalTrustBundle(t, valid), []byte(" {}")...), want: "multiple JSON values"},
		{name: "wrong purpose", data: marshalTrustBundle(t, mutateTrustBundle(valid, func(document *TrustBundleDocument) { document.Purpose = "tls" })), want: "unsupported FFU trust-bundle purpose"},
		{name: "zero sequence", data: marshalTrustBundle(t, mutateTrustBundle(valid, func(document *TrustBundleDocument) { document.Sequence = 0 })), want: "sequence must be non-zero"},
		{name: "noncanonical time", data: marshalTrustBundle(t, mutateTrustBundle(valid, func(document *TrustBundleDocument) { document.GeneratedAt = "2026-07-01T01:00:00+01:00" })), want: "canonical UTC RFC3339"},
		{name: "invalid interval", data: marshalTrustBundle(t, mutateTrustBundle(valid, func(document *TrustBundleDocument) { document.ExpiresAt = document.GeneratedAt })), want: "expiry must be after"},
		{name: "no roots", data: marshalTrustBundle(t, mutateTrustBundle(valid, func(document *TrustBundleDocument) { document.Roots = nil })), want: "contains no roots"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseTrustBundleBytes(test.data, 0, trustEvaluationTime)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want substring %q", err, test.want)
			}
		})
	}
}

func TestParseTrustBundleRejectsRootIdentityAndCertificateErrors(t *testing.T) {
	valid := validTrustBundleDocument(t)
	wrongFingerprint := mutateTrustBundle(valid, func(document *TrustBundleDocument) {
		document.Roots[0].CertificateSHA256 = strings.Repeat("00", sha256.Size)
	})
	duplicateID := mutateTrustBundle(valid, func(document *TrustBundleDocument) {
		second := trustRootDocument(t, document.Roots[0].ID, 0x44, 44)
		document.Roots = append(document.Roots, second)
	})
	duplicateCertificate := mutateTrustBundle(valid, func(document *TrustBundleDocument) {
		second := document.Roots[0]
		second.ID = "duplicate.root"
		document.Roots = append(document.Roots, second)
	})
	invalidID := mutateTrustBundle(valid, func(document *TrustBundleDocument) {
		document.Roots[0].ID = "Not Allowed"
	})
	nonCA := mutateTrustBundle(valid, func(document *TrustBundleDocument) {
		document.Roots[0] = trustLeafDocument(t, "leaf.root", 0x45, 45)
	})
	trustedAndDistrusted := mutateTrustBundle(valid, func(document *TrustBundleDocument) {
		document.DistrustedSHA256 = []string{document.Roots[0].CertificateSHA256}
	})
	tests := []struct {
		name     string
		document TrustBundleDocument
		want     string
	}{
		{name: "wrong fingerprint", document: wrongFingerprint, want: "fingerprint does not match"},
		{name: "duplicate id", document: duplicateID, want: "duplicate root id"},
		{name: "duplicate certificate", document: duplicateCertificate, want: "duplicate root certificate"},
		{name: "invalid id", document: invalidID, want: "invalid id"},
		{name: "not ca", document: nonCA, want: "not a valid CA certificate"},
		{name: "trust and distrust", document: trustedAndDistrusted, want: "both trusts and distrusts"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseTrustBundleBytes(marshalTrustBundle(t, test.document), 0, trustEvaluationTime)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want substring %q", err, test.want)
			}
		})
	}
}

func TestParseTrustBundleRejectsNilZeroAndOversizedInputs(t *testing.T) {
	if _, err := ParseTrustBundle(nil, 0, trustEvaluationTime); err == nil || !strings.Contains(err.Error(), "reader is nil") {
		t.Fatalf("nil reader error=%v", err)
	}
	if _, err := ParseTrustBundleBytes([]byte("{}"), 0, time.Time{}); err == nil || !strings.Contains(err.Error(), "evaluation time is zero") {
		t.Fatalf("zero time error=%v", err)
	}
	oversized := bytes.Repeat([]byte{' '}, int(maxFFUTrustBundleBytes)+1)
	if _, err := ParseTrustBundle(bytes.NewReader(oversized), 0, trustEvaluationTime); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized reader error=%v", err)
	}
}

func FuzzParseTrustBundleDoesNotPanic(f *testing.F) {
	seed := marshalTrustBundleForFuzz(validTrustBundleDocumentForFuzz())
	f.Add(seed)
	f.Add([]byte("not json"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseTrustBundleBytes(data, 0, trustEvaluationTime)
	})
}

func validTrustBundleDocument(t *testing.T) TrustBundleDocument {
	t.Helper()
	return TrustBundleDocument{
		Schema:      ffuTrustBundleSchema,
		Purpose:     ffuTrustBundlePurpose,
		Sequence:    7,
		GeneratedAt: "2026-07-01T00:00:00Z",
		ExpiresAt:   "2027-07-01T00:00:00Z",
		Roots:       []TrustAnchorDocument{trustRootDocument(t, "test.root", 0x41, 41)},
	}
}

func validTrustBundleDocumentForFuzz() TrustBundleDocument {
	return TrustBundleDocument{
		Schema:      ffuTrustBundleSchema,
		Purpose:     ffuTrustBundlePurpose,
		Sequence:    1,
		GeneratedAt: "2026-07-01T00:00:00Z",
		ExpiresAt:   "2027-07-01T00:00:00Z",
		Roots:       []TrustAnchorDocument{trustRootDocumentWithoutTest("fuzz.root", 0x46, 46, true)},
	}
}

func trustRootDocument(t *testing.T, id string, seedByte byte, serial int64) TrustAnchorDocument {
	t.Helper()
	return trustCertificateDocument(t, id, seedByte, serial, true)
}

func trustLeafDocument(t *testing.T, id string, seedByte byte, serial int64) TrustAnchorDocument {
	t.Helper()
	return trustCertificateDocument(t, id, seedByte, serial, false)
}

func trustCertificateDocument(t *testing.T, id string, seedByte byte, serial int64, isCA bool) TrustAnchorDocument {
	t.Helper()
	return trustRootDocumentWithoutTest(id, seedByte, serial, isCA)
}

func trustRootDocumentWithoutTest(id string, seedByte byte, serial int64, isCA bool) TrustAnchorDocument {
	seed := bytes.Repeat([]byte{seedByte}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyUsage := x509.KeyUsageDigitalSignature
	if isCA {
		keyUsage |= x509.KeyUsageCertSign
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName:   "RufusArm64 " + id,
			Organization: []string{"RufusArm64 Trust Tests"},
		},
		Issuer:                pkix.Name{CommonName: "RufusArm64 " + id, Organization: []string{"RufusArm64 Trust Tests"}},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              keyUsage,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		SignatureAlgorithm:    x509.PureEd25519,
	}
	der, err := x509.CreateCertificate(bytes.NewReader(bytes.Repeat([]byte{0x11}, 128)), template, template, publicKey, privateKey)
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(der)
	return TrustAnchorDocument{
		ID:                   id,
		CertificateDERBase64: base64.StdEncoding.EncodeToString(der),
		CertificateSHA256:    hex.EncodeToString(digest[:]),
	}
}

func mutateTrustBundle(document TrustBundleDocument, mutate func(*TrustBundleDocument)) TrustBundleDocument {
	copyDocument := document
	copyDocument.Roots = append([]TrustAnchorDocument(nil), document.Roots...)
	copyDocument.DistrustedSHA256 = append([]string(nil), document.DistrustedSHA256...)
	mutate(&copyDocument)
	return copyDocument
}

func marshalTrustBundle(t *testing.T, document TrustBundleDocument) []byte {
	t.Helper()
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func marshalTrustBundleForFuzz(document TrustBundleDocument) []byte {
	data, err := json.Marshal(document)
	if err != nil {
		panic(err)
	}
	return data
}
