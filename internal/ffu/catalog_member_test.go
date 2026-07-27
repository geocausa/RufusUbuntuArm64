package ffu

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha1" // #nosec G505 -- fixture encodes the legacy catalog member digest required by the format under test.
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestPlanCatalogMemberBindsHashTableWithoutTrustClaim(t *testing.T) {
	data := catalogMemberFixture(t, catalogFixtureOptions{})
	inspection, hashPlan, plan, err := PlanCatalogMember(context.Background(), bytes.NewReader(data), uint64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if inspection.ImageHeaderOffset != 4096 || hashPlan.HashEntryCount != 6 {
		t.Fatalf("unexpected FFU geometry: inspection=%#v hash=%#v", inspection, hashPlan)
	}
	if plan.OuterContentTypeOID != oidPKCS7SignedData || plan.EncapsulatedContentTypeOID != oidMicrosoftCTL {
		t.Fatalf("unexpected content types: %#v", plan)
	}
	if plan.CatalogMemberCount != 1 || plan.HashTableMemberName != catalogHashTableMember || plan.HashTableMemberDigestOID != oidSHA1 {
		t.Fatalf("unexpected member: %#v", plan)
	}
	if !plan.HashTableMemberMatches || !plan.SignatureStructureParsed {
		t.Fatalf("catalog member did not bind: %#v", plan)
	}
	if plan.CryptographicSignatureVerified || plan.CertificateChainBuilt || plan.PublisherTrusted || plan.HashTableCatalogAuthenticated {
		t.Fatalf("unexpected trust claim: %#v", plan)
	}
	if len(plan.Certificates) != 1 || len(plan.Signers) != 1 {
		t.Fatalf("missing certificate/signer metadata: %#v %#v", plan.Certificates, plan.Signers)
	}
	certificate := plan.Certificates[0]
	if !strings.Contains(certificate.Subject, "RufusArm64 FFU Catalog Test") || certificate.SHA256 == "" || certificate.PublicKeyAlgorithm != "Ed25519" {
		t.Fatalf("unexpected certificate metadata: %#v", certificate)
	}
	signer := plan.Signers[0]
	if signer.IdentifierType != "issuer-and-serial" || signer.DigestAlgorithmOID != "2.16.840.1.101.3.4.2.1" || signer.SignatureAlgorithmOID != "1.3.101.112" {
		t.Fatalf("unexpected signer metadata: %#v", signer)
	}
	if len(signer.SignedAttributeOIDs) != 1 || signer.SignedAttributeOIDs[0] != "1.2.840.113549.1.9.3" {
		t.Fatalf("unexpected signed attributes: %#v", signer.SignedAttributeOIDs)
	}
	if len(plan.PlanSHA256) != 64 || plan.HashTableMemberDigest != plan.CalculatedHashTableDigest {
		t.Fatalf("unexpected plan digest state: %#v", plan)
	}

	_, _, second, err := PlanCatalogMember(context.Background(), bytes.NewReader(data), uint64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if second.PlanSHA256 != plan.PlanSHA256 {
		t.Fatalf("catalog plan digest changed: %s != %s", second.PlanSHA256, plan.PlanSHA256)
	}
}

func TestPlanCatalogMemberRejectsWrongHashTableDigest(t *testing.T) {
	wrong := bytes.Repeat([]byte{0x5a}, sha1.Size)
	data := catalogMemberFixture(t, catalogFixtureOptions{memberDigest: wrong})
	_, _, plan, err := PlanCatalogMember(context.Background(), bytes.NewReader(data), uint64(len(data)))
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("error=%v", err)
	}
	if plan.HashTableMemberMatches || plan.HashTableCatalogAuthenticated || plan.HashTableMemberDigest == plan.CalculatedHashTableDigest {
		t.Fatalf("unexpected mismatch state: %#v", plan)
	}
}

func TestPlanCatalogMemberRejectsMissingAndDuplicateMember(t *testing.T) {
	tests := []struct {
		name    string
		options catalogFixtureOptions
		want    string
	}{
		{name: "missing", options: catalogFixtureOptions{memberName: "Other.blob"}, want: "no supported HashTable.blob member"},
		{name: "duplicate", options: catalogFixtureOptions{duplicateMember: true}, want: "multiple HashTable.blob members"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := catalogMemberFixture(t, test.options)
			_, _, _, err := PlanCatalogMember(context.Background(), bytes.NewReader(data), uint64(len(data)))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want substring %q", err, test.want)
			}
		})
	}
}

func TestPlanCatalogMemberRejectsUnsupportedMemberDigest(t *testing.T) {
	data := catalogMemberFixture(t, catalogFixtureOptions{
		memberDigestOID: "2.16.840.1.101.3.4.2.1",
		memberDigest:    bytes.Repeat([]byte{0x11}, sha256.Size),
	})
	_, _, _, err := PlanCatalogMember(context.Background(), bytes.NewReader(data), uint64(len(data)))
	if err == nil || !strings.Contains(err.Error(), "unsupported catalog HashTable.blob digest algorithm") {
		t.Fatalf("error=%v", err)
	}
}

func TestPlanCatalogMemberRejectsMalformedCatalogEnvelope(t *testing.T) {
	data := catalogMemberFixture(t, catalogFixtureOptions{catalogTrailingByte: true})
	_, _, _, err := PlanCatalogMember(context.Background(), bytes.NewReader(data), uint64(len(data)))
	if err == nil || !strings.Contains(err.Error(), "trailing bytes") {
		t.Fatalf("error=%v", err)
	}
}

func TestPlanCatalogMemberRejectsCancelledAndNilContexts(t *testing.T) {
	data := catalogMemberFixture(t, catalogFixtureOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, err := PlanCatalogMember(ctx, bytes.NewReader(data), uint64(len(data))); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error=%v", err)
	}
	var nilContext context.Context
	if _, _, _, err := PlanCatalogMember(nilContext, bytes.NewReader(data), uint64(len(data))); err == nil || !strings.Contains(err.Error(), "context is nil") {
		t.Fatalf("nil error=%v", err)
	}
}

func TestPlanCatalogMemberBoundsCatalogRead(t *testing.T) {
	data := catalogMemberFixture(t, catalogFixtureOptions{})
	reader := &maxReadAtReader{reader: bytes.NewReader(data)}
	_, _, plan, err := PlanCatalogMember(context.Background(), reader, uint64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if !plan.HashTableMemberMatches {
		t.Fatalf("catalog member did not match: %#v", plan)
	}
	if reader.maximum > int(maxFFUCatalogBytes) {
		t.Fatalf("maximum ReadAt request=%d exceeds catalog limit %d", reader.maximum, maxFFUCatalogBytes)
	}
}

func TestParseWindowsCatalogRejectsNonMinimalAndIndefiniteDER(t *testing.T) {
	for _, test := range []struct {
		name string
		data []byte
		want string
	}{
		{name: "indefinite", data: []byte{0x30, 0x80, 0x00, 0x00}, want: "indefinite"},
		{name: "non-minimal", data: []byte{0x30, 0x81, 0x01, 0x00}, want: "non-minimal"},
		{name: "high tag", data: []byte{0x3f, 0x01, 0x00}, want: "high-tag-number"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseWindowsCatalog(test.data)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want substring %q", err, test.want)
			}
		})
	}
}

func FuzzParseWindowsCatalogDoesNotPanic(f *testing.F) {
	valid := catalogMemberFixtureForFuzz()
	f.Add(valid)
	f.Add([]byte("not a catalog"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseWindowsCatalog(data)
	})
}

type catalogFixtureOptions struct {
	memberName          string
	memberDigestOID     string
	memberDigest        []byte
	duplicateMember     bool
	catalogTrailingByte bool
}

func catalogMemberFixture(t *testing.T, options catalogFixtureOptions) []byte {
	t.Helper()
	data := validV1PlanFixture()
	table := fixtureHashTable(data)
	catalog := buildCatalogFixture(t, table, options)
	if 32+len(catalog)+len(table) >= 4096 {
		t.Fatalf("catalog fixture security area is too large: catalog=%d table=%d", len(catalog), len(table))
	}
	binary.LittleEndian.PutUint32(data[24:28], uint32(len(catalog)))
	binary.LittleEndian.PutUint32(data[28:32], uint32(len(table)))
	copy(data[32:32+len(catalog)], catalog)
	copy(data[32+len(catalog):32+len(catalog)+len(table)], table)
	return data
}

func catalogMemberFixtureForFuzz() []byte {
	table := bytes.Repeat([]byte{0x42}, 2*sha256.Size)
	return buildCatalogFixtureWithoutCertificate(table, catalogFixtureOptions{})
}

func fixtureHashTable(data []byte) []byte {
	const (
		imageOffset = 4096
		chunkSize   = 4096
	)
	coverageLength := len(data) - imageOffset
	chunkCount := (coverageLength + chunkSize - 1) / chunkSize
	table := make([]byte, chunkCount*sha256.Size)
	for index := 0; index < chunkCount; index++ {
		start := imageOffset + index*chunkSize
		end := start + chunkSize
		chunk := make([]byte, chunkSize)
		if end > len(data) {
			end = len(data)
		}
		copy(chunk, data[start:end])
		digest := sha256.Sum256(chunk)
		copy(table[index*sha256.Size:(index+1)*sha256.Size], digest[:])
	}
	return table
}

func buildCatalogFixture(t *testing.T, table []byte, options catalogFixtureOptions) []byte {
	t.Helper()
	certificateDER, certificate := fixtureCertificate(t)
	return buildCatalogDER(table, options, certificateDER, certificate)
}

func buildCatalogFixtureWithoutCertificate(table []byte, options catalogFixtureOptions) []byte {
	return buildCatalogDER(table, options, nil, nil)
}

func buildCatalogDER(table []byte, options catalogFixtureOptions, certificateDER []byte, certificate *x509.Certificate) []byte {
	memberName := options.memberName
	if memberName == "" {
		memberName = catalogHashTableMember
	}
	digestOID := options.memberDigestOID
	if digestOID == "" {
		digestOID = oidSHA1
	}
	digest := options.memberDigest
	if digest == nil {
		sum := sha1.Sum(table) // #nosec G401 -- fixture represents the legacy catalog digest field.
		digest = sum[:]
	}
	member := fixtureCatalogMember(memberName, digestOID, digest)
	members := [][]byte{member}
	if options.duplicateMember {
		members = append(members, fixtureCatalogMember(catalogHashTableMember, digestOID, digest))
	}
	ctl := derSequence(
		derSequence(derOID("1.3.6.1.4.1.311.12.1.1")),
		derOctet([]byte("RufusArm64.Catalog.Test")),
		derUTCTime(time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)),
		derSequence(derOID("1.3.6.1.4.1.311.12.1.2")),
		derSequence(members...),
	)
	encapsulated := derSequence(derOID(oidMicrosoftCTL), derContext(0, ctl))
	digestAlgorithms := derSet(derAlgorithm("2.16.840.1.101.3.4.2.1"))
	signer := fixtureSigner(certificate)
	signedParts := [][]byte{derInteger(1), digestAlgorithms, encapsulated}
	if len(certificateDER) != 0 {
		signedParts = append(signedParts, derContext(0, certificateDER))
	}
	signedParts = append(signedParts, derSet(signer))
	signedData := derSequence(signedParts...)
	catalog := derSequence(derOID(oidPKCS7SignedData), derContext(0, signedData))
	if options.catalogTrailingByte {
		catalog = append(catalog, 0)
	}
	return catalog
}

func fixtureCatalogMember(name, digestOID string, digest []byte) []byte {
	nameValue := derSequence(
		derBMPString("File"),
		derInteger(0),
		derOctet(utf16LE(name+"\x00")),
	)
	nameAttribute := derSequence(derOID(oidCatalogNameValue), derSet(nameValue))
	indirect := derSequence(
		derSequence(derOID("1.3.6.1.4.1.311.2.1.15"), derSequence()),
		derSequence(derAlgorithm(digestOID), derOctet(digest)),
	)
	digestAttribute := derSequence(derOID(oidSPCIndirectData), derSet(indirect))
	return derSequence(derOctet(bytes.Repeat([]byte{0x33}, sha1.Size)), derSet(nameAttribute, digestAttribute))
}

func fixtureSigner(certificate *x509.Certificate) []byte {
	var identifier []byte
	if certificate != nil {
		identifier = derSequence(certificate.RawIssuer, derBigInteger(certificate.SerialNumber))
	} else {
		identifier = derContextPrimitive(0, bytes.Repeat([]byte{0x44}, 20))
	}
	contentTypeAttribute := derSequence(
		derOID("1.2.840.113549.1.9.3"),
		derSet(derOID(oidMicrosoftCTL)),
	)
	return derSequence(
		derInteger(1),
		identifier,
		derAlgorithm("2.16.840.1.101.3.4.2.1"),
		derContext(0, contentTypeAttribute),
		derAlgorithm("1.3.101.112"),
		derOctet(bytes.Repeat([]byte{0x55}, ed25519.SignatureSize)),
	)
}

func fixtureCertificate(t *testing.T) ([]byte, *x509.Certificate) {
	t.Helper()
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject: pkix.Name{
			CommonName:   "RufusArm64 FFU Catalog Test",
			Organization: []string{"RufusArm64 Tests"},
		},
		Issuer:                pkix.Name{CommonName: "RufusArm64 FFU Catalog Test"},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    x509.PureEd25519,
	}
	certificateDER, err := x509.CreateCertificate(nil, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatal(err)
	}
	return certificateDER, certificate
}

func derSequence(parts ...[]byte) []byte { return derWrap(0x30, bytes.Join(parts, nil)) }
func derSet(parts ...[]byte) []byte      { return derWrap(0x31, bytes.Join(parts, nil)) }
func derContext(tag byte, parts ...[]byte) []byte {
	return derWrap(0xa0|tag, bytes.Join(parts, nil))
}
func derContextPrimitive(tag byte, content []byte) []byte { return derWrap(0x80|tag, content) }
func derOctet(content []byte) []byte                      { return derWrap(0x04, content) }
func derNull() []byte                                     { return []byte{0x05, 0x00} }

func derOID(value string) []byte {
	var oid asn1.ObjectIdentifier
	for _, component := range strings.Split(value, ".") {
		integer, ok := new(big.Int).SetString(component, 10)
		if !ok || !integer.IsInt64() {
			panic("invalid test OID " + value)
		}
		oid = append(oid, int(integer.Int64()))
	}
	encoded, err := asn1.Marshal(oid)
	if err != nil {
		panic(err)
	}
	return encoded
}

func derInteger(value int64) []byte {
	encoded, err := asn1.Marshal(value)
	if err != nil {
		panic(err)
	}
	return encoded
}

func derBigInteger(value *big.Int) []byte {
	encoded, err := asn1.Marshal(value)
	if err != nil {
		panic(err)
	}
	return encoded
}

func derAlgorithm(oid string) []byte { return derSequence(derOID(oid), derNull()) }

func derUTCTime(value time.Time) []byte {
	encoded, err := asn1.Marshal(value)
	if err != nil {
		panic(err)
	}
	return encoded
}

func derBMPString(value string) []byte {
	content := make([]byte, 0, len(value)*2)
	for _, current := range []byte(value) {
		content = append(content, 0, current)
	}
	return derWrap(0x1e, content)
}

func utf16LE(value string) []byte {
	content := make([]byte, 0, len(value)*2)
	for _, current := range []byte(value) {
		content = append(content, current, 0)
	}
	return content
}

func derWrap(identifier byte, content []byte) []byte {
	result := []byte{identifier}
	length := len(content)
	switch {
	case length < 128:
		result = append(result, byte(length))
	case length <= 0xff:
		result = append(result, 0x81, byte(length))
	case length <= 0xffff:
		result = append(result, 0x82, byte(length>>8), byte(length))
	case length <= 0xffffff:
		result = append(result, 0x83, byte(length>>16), byte(length>>8), byte(length))
	default:
		result = append(result, 0x84, byte(length>>24), byte(length>>16), byte(length>>8), byte(length))
	}
	return append(result, content...)
}
