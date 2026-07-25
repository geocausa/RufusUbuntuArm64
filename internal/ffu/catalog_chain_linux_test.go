//go:build linux

package ffu

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- fixture preserves the legacy catalog member digest field.
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"sort"
	"strings"
	"testing"
	"time"
)

var catalogChainEvaluationTime = time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)

type catalogChainFixtureOptions struct {
	leafKeyUsage          x509.KeyUsage
	leafExtendedKeyUsages []x509.ExtKeyUsage
	leafNotBefore         time.Time
	leafNotAfter          time.Time
	intermediateIsCA      *bool
	intermediateKeyUsage  x509.KeyUsage
	rootMaxPathLen        int
	rootMaxPathLenZero    bool
	duplicateLeaf         bool
	distrustIntermediate  bool
	attackerRoot          bool
	ambiguousCrossSigned  bool
}

type catalogChainFixture struct {
	data                    []byte
	activation              TrustBundleActivation
	leaf                    *x509.Certificate
	intermediate            *x509.Certificate
	root                    *x509.Certificate
	intermediateFingerprint string
}

func TestBuildCatalogCertificateChainWithExplicitActivatedRoot(t *testing.T) {
	fixture := newCatalogChainFixture(t, catalogChainFixtureOptions{})
	inspection, hashPlan, memberPlan, signaturePlan, chainPlan, err := BuildCatalogCertificateChain(
		context.Background(), bytes.NewReader(fixture.data), uint64(len(fixture.data)), fixture.activation, catalogChainEvaluationTime,
	)
	if err != nil {
		t.Fatal(err)
	}
	if inspection.ImageHeaderOffset != 4096 || hashPlan.HashEntryCount != 6 || !memberPlan.HashTableMemberMatches {
		t.Fatalf("unexpected prerequisite state: inspection=%#v hash=%#v member=%#v", inspection, hashPlan, memberPlan)
	}
	if !signaturePlan.CryptographicSignatureVerified || !signaturePlan.CertificateChainBuilt || signaturePlan.PublisherTrusted || signaturePlan.HashTableCatalogAuthenticated {
		t.Fatalf("signature/chain gates crossed incorrectly: %#v", signaturePlan)
	}
	if !chainPlan.ExplicitTrustAnchorsUsed || !chainPlan.DigitalSignatureUsageVerified || !chainPlan.CodeSigningEKUVerified || !chainPlan.CertificateValidityVerified || !chainPlan.DistrustPolicyChecked || !chainPlan.CertificateChainBuilt {
		t.Fatalf("chain policy did not complete: %#v", chainPlan)
	}
	if chainPlan.HostTLSStoreConsulted || chainPlan.RevocationChecked || chainPlan.TimestampVerified || chainPlan.PublisherTrusted || chainPlan.HashTableCatalogAuthenticated {
		t.Fatalf("chain planning crossed a later policy boundary: %#v", chainPlan)
	}
	if chainPlan.SelectedRootID != "test.authenticode.root" || chainPlan.SelectedRootSHA256 != certificateFingerprint(fixture.root) {
		t.Fatalf("unexpected selected root: %#v", chainPlan)
	}
	if len(chainPlan.Chain) != 3 || chainPlan.Chain[0].Role != "signer" || chainPlan.Chain[1].Role != "intermediate" || chainPlan.Chain[2].Role != "root" {
		t.Fatalf("unexpected selected path: %#v", chainPlan.Chain)
	}
	if chainPlan.Chain[0].EmbeddedIndex != 0 || chainPlan.Chain[1].EmbeddedIndex != 1 || chainPlan.Chain[2].EmbeddedIndex != -1 {
		t.Fatalf("unexpected embedded certificate binding: %#v", chainPlan.Chain)
	}
	if len(chainPlan.PlanSHA256) != sha256.Size*2 || chainPlan.CatalogSignaturePlanSHA256 != signaturePlan.PlanSHA256 {
		t.Fatalf("unexpected deterministic binding: %#v", chainPlan)
	}

	_, _, _, secondSignature, secondChain, err := BuildCatalogCertificateChain(
		context.Background(), bytes.NewReader(fixture.data), uint64(len(fixture.data)), fixture.activation, catalogChainEvaluationTime,
	)
	if err != nil {
		t.Fatal(err)
	}
	if secondSignature.PlanSHA256 != signaturePlan.PlanSHA256 || secondChain.PlanSHA256 != chainPlan.PlanSHA256 {
		t.Fatalf("chain plan changed across identical runs: signature=%s/%s chain=%s/%s", signaturePlan.PlanSHA256, secondSignature.PlanSHA256, chainPlan.PlanSHA256, secondChain.PlanSHA256)
	}
}

func TestBuildCatalogCertificateChainRejectsPolicyViolations(t *testing.T) {
	falseValue := false
	tests := []struct {
		name    string
		options catalogChainFixtureOptions
		want    string
	}{
		{name: "missing digital signature usage", options: catalogChainFixtureOptions{leafKeyUsage: x509.KeyUsageKeyEncipherment}, want: "lacks digital-signature"},
		{name: "missing code signing eku", options: catalogChainFixtureOptions{leafExtendedKeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, want: "lacks an explicit code-signing"},
		{name: "expired signer", options: catalogChainFixtureOptions{leafNotAfter: catalogChainEvaluationTime.Add(-time.Hour)}, want: "outside its validity"},
		{name: "not yet valid signer", options: catalogChainFixtureOptions{leafNotBefore: catalogChainEvaluationTime.Add(time.Hour)}, want: "outside its validity"},
		{name: "non ca intermediate", options: catalogChainFixtureOptions{intermediateIsCA: &falseValue}, want: "certificate signed by unknown authority"},
		{name: "intermediate without cert sign", options: catalogChainFixtureOptions{intermediateKeyUsage: x509.KeyUsageDigitalSignature}, want: "certificate signed by unknown authority"},
		{name: "root path length", options: catalogChainFixtureOptions{rootMaxPathLen: 0, rootMaxPathLenZero: true}, want: "too many intermediates"},
		{name: "distrusted intermediate", options: catalogChainFixtureOptions{distrustIntermediate: true}, want: "no certificate path satisfying"},
		{name: "duplicate certificate", options: catalogChainFixtureOptions{duplicateLeaf: true}, want: "matches multiple embedded certificates"},
		{name: "attacker root", options: catalogChainFixtureOptions{attackerRoot: true}, want: "certificate signed by unknown authority"},
		{name: "ambiguous cross signed path", options: catalogChainFixtureOptions{ambiguousCrossSigned: true}, want: "ambiguous"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCatalogChainFixture(t, test.options)
			_, _, _, signaturePlan, chainPlan, err := BuildCatalogCertificateChain(
				context.Background(), bytes.NewReader(fixture.data), uint64(len(fixture.data)), fixture.activation, catalogChainEvaluationTime,
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want substring %q", err, test.want)
			}
			if signaturePlan.CertificateChainBuilt || chainPlan.CertificateChainBuilt || signaturePlan.PublisherTrusted || chainPlan.PublisherTrusted {
				t.Fatalf("failed policy path crossed trust boundary: signature=%#v chain=%#v", signaturePlan, chainPlan)
			}
		})
	}
}

func TestBuildCatalogCertificateChainRejectsTamperedActivation(t *testing.T) {
	fixture := newCatalogChainFixture(t, catalogChainFixtureOptions{})
	tests := []struct {
		name   string
		mutate func(*TrustBundleActivation)
		want   string
	}{
		{name: "digest", mutate: func(value *TrustBundleActivation) { value.ActivationSHA256 = strings.Repeat("0", 64) }, want: "is not sealed by the verified activation boundary"},
		{name: "root bytes", mutate: func(value *TrustBundleActivation) {
			value.Roots[0].CertificateDER[0] ^= 0xff
			value.ActivationSHA256 = trustBundleActivationDigest(*value)
			value.capability = &trustBundleActivationCapability{activationSHA256: value.ActivationSHA256}
		}, want: "fingerprint does not match DER"},
		{name: "root count", mutate: func(value *TrustBundleActivation) { value.RootCount++ }, want: "invalid root count"},
		{name: "activated plan", mutate: func(value *TrustBundleActivation) { value.Plan.CertificateChainBuilt = true }, want: "crossed a later"},
		{name: "authentication", mutate: func(value *TrustBundleActivation) { value.Authentication.SigningKeyIDs[0] = "other" }, want: "authentication does not match"},
		{name: "fabricated capability", mutate: func(value *TrustBundleActivation) { value.capability = nil }, want: "is not sealed by the verified activation boundary"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			activation := cloneCatalogChainActivation(fixture.activation)
			test.mutate(&activation)
			_, _, _, _, _, err := BuildCatalogCertificateChain(
				context.Background(), bytes.NewReader(fixture.data), uint64(len(fixture.data)), activation, catalogChainEvaluationTime,
			)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want substring %q", err, test.want)
			}
		})
	}
}

func TestCatalogChainActivationSealRejectsSerializedAndRedigestedCopies(t *testing.T) {
	fixture := newCatalogChainFixture(t, catalogChainFixtureOptions{})

	encoded, err := json.Marshal(fixture.activation)
	if err != nil {
		t.Fatal(err)
	}
	var replayed TrustBundleActivation
	if err := json.Unmarshal(encoded, &replayed); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := validateCatalogChainActivation(replayed); err == nil || !strings.Contains(err.Error(), "is not sealed by the verified activation boundary") {
		t.Fatalf("serialized activation replay error=%v", err)
	}

	modified := cloneCatalogChainActivation(fixture.activation)
	modified.Generation += "-modified"
	modified.ActivationSHA256 = trustBundleActivationDigest(modified)
	if _, _, _, err := validateCatalogChainActivation(modified); err == nil || !strings.Contains(err.Error(), "is not sealed by the verified activation boundary") {
		t.Fatalf("re-digested activation mutation error=%v", err)
	}
}

func TestActivateAuthenticatedTrustBundleProducesCatalogChainCapability(t *testing.T) {
	root, fixture, _ := publishedTrustStoreTestFixture(t)
	evaluationTime := trustMetadataEvaluationTime.Add(2 * time.Hour)
	activation, err := ActivateAuthenticatedTrustBundle(context.Background(), root, fixture.policy, evaluationTime, TrustActivationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if activation.capability == nil || activation.capability.activationSHA256 != activation.ActivationSHA256 {
		t.Fatal("verified activation did not produce the sealed catalog-chain capability")
	}
}

func TestBuildCatalogCertificateChainRejectsNilAndCancelledContext(t *testing.T) {
	fixture := newCatalogChainFixture(t, catalogChainFixtureOptions{})
	var nilContext context.Context
	if _, _, _, _, _, err := BuildCatalogCertificateChain(nilContext, bytes.NewReader(fixture.data), uint64(len(fixture.data)), fixture.activation, catalogChainEvaluationTime); err == nil || !strings.Contains(err.Error(), "context is nil") {
		t.Fatalf("nil context error=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, _, _, err := BuildCatalogCertificateChain(ctx, bytes.NewReader(fixture.data), uint64(len(fixture.data)), fixture.activation, catalogChainEvaluationTime); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context error=%v", err)
	}
	if _, _, _, _, _, err := BuildCatalogCertificateChain(context.Background(), bytes.NewReader(fixture.data), uint64(len(fixture.data)), fixture.activation, time.Time{}); err == nil || !strings.Contains(err.Error(), "evaluation time is zero") {
		t.Fatalf("zero evaluation time error=%v", err)
	}
}

func TestCatalogCertificateAlgorithmPolicyRejectsWeakAlgorithmsAndKeys(t *testing.T) {
	strongRSA := new(big.Int).Lsh(big.NewInt(1), 2047)
	strongRSA.Add(strongRSA, big.NewInt(1))
	weakRSA := new(big.Int).Lsh(big.NewInt(1), 1023)
	weakRSA.Add(weakRSA, big.NewInt(1))
	for _, test := range []struct {
		name        string
		certificate *x509.Certificate
		want        string
	}{
		{name: "sha1", certificate: &x509.Certificate{SignatureAlgorithm: x509.SHA1WithRSA, PublicKey: &rsa.PublicKey{N: strongRSA, E: 65537}}, want: "unsupported certificate signature"},
		{name: "rsa 1024", certificate: &x509.Certificate{SignatureAlgorithm: x509.SHA256WithRSA, PublicKey: &rsa.PublicKey{N: weakRSA, E: 65537}}, want: "smaller than 2048"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateCatalogCertificateAlgorithms(test.certificate); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want substring %q", err, test.want)
			}
		})
	}
}

func FuzzBuildCatalogCertificateChainDoesNotPanic(f *testing.F) {
	fixture := newCatalogChainFixture(f, catalogChainFixtureOptions{})
	f.Add(fixture.data)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 || len(data) > 1<<20 {
			return
		}
		_, _, _, _, _, _ = BuildCatalogCertificateChain(
			context.Background(), bytes.NewReader(data), uint64(len(data)), fixture.activation, catalogChainEvaluationTime,
		)
	})
}

func newCatalogChainFixture(t testing.TB, options catalogChainFixtureOptions) catalogChainFixture {
	t.Helper()
	rootDER, root, rootKey := createCatalogChainCertificate(t, catalogChainCertificateSpec{
		seed: 0x61, serial: 610, commonName: "RufusArm64 Authenticode Root", isCA: true,
		keyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, maxPathLen: options.rootMaxPathLen, maxPathLenZero: options.rootMaxPathLenZero,
	})
	intermediateIsCA := true
	if options.intermediateIsCA != nil {
		intermediateIsCA = *options.intermediateIsCA
	}
	intermediateUsage := options.intermediateKeyUsage
	if intermediateUsage == 0 {
		intermediateUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	intermediateDER, intermediate, intermediateKey := createCatalogChainCertificate(t, catalogChainCertificateSpec{
		seed: 0x62, serial: 620, commonName: "RufusArm64 Authenticode Intermediate", isCA: intermediateIsCA,
		keyUsage: intermediateUsage, maxPathLen: 0, maxPathLenZero: true, parent: root, parentKey: rootKey,
	})
	leafUsage := options.leafKeyUsage
	if leafUsage == 0 {
		leafUsage = x509.KeyUsageDigitalSignature
	}
	leafEKU := options.leafExtendedKeyUsages
	if leafEKU == nil {
		leafEKU = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	}
	leafNotBefore := options.leafNotBefore
	if leafNotBefore.IsZero() {
		leafNotBefore = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	leafNotAfter := options.leafNotAfter
	if leafNotAfter.IsZero() {
		leafNotAfter = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	leafDER, leaf, leafKey := createCatalogChainCertificate(t, catalogChainCertificateSpec{
		seed: 0x63, serial: 630, commonName: "RufusArm64 FFU Catalog Publisher", isCA: false,
		keyUsage: leafUsage, extendedKeyUsages: leafEKU, notBefore: leafNotBefore, notAfter: leafNotAfter,
		parent: intermediate, parentKey: intermediateKey,
	})

	certificateDERs := [][]byte{leafDER, intermediateDER}
	activationRoots := []catalogChainRoot{{id: "test.authenticode.root", der: rootDER, certificate: root}}
	if options.duplicateLeaf {
		certificateDERs = append(certificateDERs, append([]byte(nil), leafDER...))
	}
	if options.attackerRoot {
		attackerDER, attacker, attackerKey := createCatalogChainCertificate(t, catalogChainCertificateSpec{
			seed: 0x64, serial: 640, commonName: "Attacker Root", isCA: true,
			keyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, maxPathLen: 1,
		})
		leafDER, leaf, leafKey = createCatalogChainCertificate(t, catalogChainCertificateSpec{
			seed: 0x63, serial: 630, commonName: "RufusArm64 FFU Catalog Publisher", isCA: false,
			keyUsage: leafUsage, extendedKeyUsages: leafEKU, notBefore: leafNotBefore, notAfter: leafNotAfter,
			parent: attacker, parentKey: attackerKey,
		})
		certificateDERs = [][]byte{leafDER, attackerDER}
	}
	if options.ambiguousCrossSigned {
		secondRootDER, secondRoot, secondRootKey := createCatalogChainCertificate(t, catalogChainCertificateSpec{
			seed: 0x65, serial: 650, commonName: "RufusArm64 Authenticode Root Two", isCA: true,
			keyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, maxPathLen: 1,
		})
		crossDER, _, _ := createCatalogChainCertificate(t, catalogChainCertificateSpec{
			seed: 0x62, serial: 621, commonName: "RufusArm64 Authenticode Intermediate", isCA: true,
			keyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, maxPathLen: 0, maxPathLenZero: true,
			parent: secondRoot, parentKey: secondRootKey, publicKeyOverride: intermediateKey.Public().(ed25519.PublicKey), privateKeyOverride: intermediateKey,
		})
		certificateDERs = [][]byte{leafDER, intermediateDER, crossDER}
		activationRoots = append(activationRoots, catalogChainRoot{id: "test.authenticode.root.two", der: secondRootDER, certificate: secondRoot})
	}

	data := signedCatalogFixtureWithCertificates(t, certificateDERs, leaf, leafKey)
	distrusted := []string(nil)
	intermediateFingerprint := certificateFingerprint(intermediate)
	if options.distrustIntermediate {
		distrusted = []string{intermediateFingerprint}
	}
	activation := catalogChainActivationFixture(t, activationRoots, distrusted)
	return catalogChainFixture{
		data: data, activation: activation, leaf: leaf, intermediate: intermediate, root: root,
		intermediateFingerprint: intermediateFingerprint,
	}
}

type catalogChainCertificateSpec struct {
	seed               byte
	serial             int64
	commonName         string
	isCA               bool
	keyUsage           x509.KeyUsage
	extendedKeyUsages  []x509.ExtKeyUsage
	maxPathLen         int
	maxPathLenZero     bool
	notBefore          time.Time
	notAfter           time.Time
	parent             *x509.Certificate
	parentKey          ed25519.PrivateKey
	publicKeyOverride  ed25519.PublicKey
	privateKeyOverride ed25519.PrivateKey
}

func createCatalogChainCertificate(t testing.TB, spec catalogChainCertificateSpec) ([]byte, *x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	privateKey := spec.privateKeyOverride
	if len(privateKey) == 0 {
		privateKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{spec.seed}, ed25519.SeedSize))
	}
	publicKey := spec.publicKeyOverride
	if len(publicKey) == 0 {
		publicKey = privateKey.Public().(ed25519.PublicKey)
	}
	notBefore := spec.notBefore
	if notBefore.IsZero() {
		notBefore = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	notAfter := spec.notAfter
	if notAfter.IsZero() {
		notAfter = time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(spec.serial),
		Subject:               pkix.Name{CommonName: spec.commonName, Organization: []string{"RufusArm64 Chain Tests"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              spec.keyUsage,
		ExtKeyUsage:           append([]x509.ExtKeyUsage(nil), spec.extendedKeyUsages...),
		BasicConstraintsValid: true,
		IsCA:                  spec.isCA,
		SignatureAlgorithm:    x509.PureEd25519,
		SubjectKeyId:          []byte{spec.seed, byte(spec.serial)},
	}
	if spec.isCA {
		template.MaxPathLen = spec.maxPathLen
		template.MaxPathLenZero = spec.maxPathLenZero
	}
	parent := spec.parent
	signerKey := spec.parentKey
	if parent == nil {
		parent = template
		signerKey = privateKey
	}
	der, err := x509.CreateCertificate(bytes.NewReader(bytes.Repeat([]byte{0x27}, 256)), template, parent, publicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return der, certificate, privateKey
}

func signedCatalogFixtureWithCertificates(t testing.TB, certificateDERs [][]byte, signer *x509.Certificate, signerKey ed25519.PrivateKey) []byte {
	t.Helper()
	data := validV1PlanFixture()
	table := fixtureHashTable(data)
	catalog := buildSignedCatalogDERWithCertificates(table, certificateDERs, signer, signerKey)
	if 32+len(catalog)+len(table) >= 4096 {
		t.Fatalf("chain catalog fixture security area is too large: catalog=%d table=%d", len(catalog), len(table))
	}
	binary.LittleEndian.PutUint32(data[24:28], uint32(len(catalog)))
	binary.LittleEndian.PutUint32(data[28:32], uint32(len(table)))
	copy(data[32:32+len(catalog)], catalog)
	copy(data[32+len(catalog):32+len(catalog)+len(table)], table)
	return data
}

func buildSignedCatalogDERWithCertificates(table []byte, certificateDERs [][]byte, signer *x509.Certificate, signerKey ed25519.PrivateKey) []byte {
	memberDigest := sha1.Sum(table) // #nosec G401 -- fixture represents the legacy catalog member digest field.
	member := fixtureCatalogMember(catalogHashTableMember, oidSHA1, memberDigest[:])
	ctl := derSequence(
		derSequence(derOID("1.3.6.1.4.1.311.12.1.1")),
		derOctet([]byte("RufusArm64.Chain.Test")),
		derUTCTime(time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)),
		derSequence(derOID("1.3.6.1.4.1.311.12.1.2")),
		derSequence(member),
	)
	contentDigest := sha256.Sum256(ctl)
	attributes := [][]byte{
		derSequence(derOID(oidPKCS9ContentType), derSet(derOID(oidMicrosoftCTL))),
		derSequence(derOID(oidPKCS9MessageDigest), derSet(derOctet(contentDigest[:]))),
	}
	sort.Slice(attributes, func(left, right int) bool { return bytes.Compare(attributes[left], attributes[right]) < 0 })
	signature := ed25519.Sign(signerKey, derSet(attributes...))
	identifier := derSequence(signer.RawIssuer, derBigInteger(signer.SerialNumber))
	signerInfo := derSequence(
		derInteger(1), identifier, derAlgorithm(oidSHA256), derContext(0, attributes...),
		derSequence(derOID(oidEd25519)), derOctet(signature),
	)
	signedData := derSequence(
		derInteger(1),
		derSet(derAlgorithm(oidSHA256)),
		derSequence(derOID(oidMicrosoftCTL), derContext(0, derOctet(ctl))),
		derContext(0, certificateDERs...),
		derSet(signerInfo),
	)
	return derSequence(derOID(oidPKCS7SignedData), derContext(0, signedData))
}

type catalogChainRoot struct {
	id          string
	der         []byte
	certificate *x509.Certificate
}

func catalogChainActivationFixture(t testing.TB, rootFixtures []catalogChainRoot, distrusted []string) TrustBundleActivation {
	t.Helper()
	roots := make([]ActivatedTrustAnchor, 0, len(rootFixtures))
	plannedRoots := make([]TrustAnchor, 0, len(rootFixtures))
	for index, fixture := range rootFixtures {
		fingerprint := certificateFingerprint(fixture.certificate)
		anchor, err := parseTrustAnchor(TrustAnchorDocument{
			ID: fixture.id, CertificateDERBase64: encodeTestBase64(fixture.der), CertificateSHA256: fingerprint,
		}, index)
		if err != nil {
			t.Fatal(err)
		}
		roots = append(roots, ActivatedTrustAnchor{Anchor: anchor, CertificateDER: append([]byte(nil), fixture.der...)})
		plannedRoots = append(plannedRoots, anchor)
	}
	sort.Slice(roots, func(left, right int) bool { return roots[left].Anchor.ID < roots[right].Anchor.ID })
	sort.Slice(plannedRoots, func(left, right int) bool { return plannedRoots[left].ID < plannedRoots[right].ID })
	distrusted = append([]string(nil), distrusted...)
	sort.Strings(distrusted)
	bundleDigest := sha256.Sum256([]byte("catalog-chain-test-bundle"))
	bundleSHA256 := hex.EncodeToString(bundleDigest[:])
	auth := &TrustBundleAuthentication{
		Schema: 1, Purpose: "ffu-trust-metadata-authentication", Sequence: 7, KeySetVersion: 1,
		KeySetSHA256: strings.Repeat("1", 64), Threshold: 1, SigningKeyIDs: []string{"test-key"},
		GeneratedAt: "2026-07-01T00:00:00Z", ExpiresAt: "2027-07-01T00:00:00Z", EvaluationTime: catalogChainEvaluationTime.Format(time.RFC3339),
		BundleSize: 1234, BundleSHA256: bundleSHA256, MetadataSHA256: strings.Repeat("2", 64),
	}
	plan := TrustBundlePlan{
		Schema: ffuTrustBundleSchema, Purpose: ffuTrustBundlePurpose, Sequence: 7, MinimumAcceptedSequence: 7,
		GeneratedAt: auth.GeneratedAt, ExpiresAt: auth.ExpiresAt, EvaluationTime: catalogChainEvaluationTime.Format(time.RFC3339),
		RootCount: len(plannedRoots), DistrustedCount: len(distrusted), Roots: plannedRoots, DistrustedSHA256: append([]string(nil), distrusted...),
		BundleSHA256: bundleSHA256, BundleStructureValidated: true, BundleSignatureAuthenticated: true, TrustAnchorsActivated: true,
		HostTLSStoreConsulted: false, CertificateChainBuilt: false, PublisherTrusted: false, Authentication: cloneTrustBundleAuthentication(auth),
	}
	plan.PlanSHA256 = trustBundlePlanDigest(plan)
	activation := TrustBundleActivation{
		Schema: trustActivationSchema, Purpose: trustActivationPurpose, Root: "/test/ffu-trust", Generation: "generation-0000000000000007-test",
		Sequence: 7, BundleSHA256: bundleSHA256, PublicationPlanSHA256: strings.Repeat("3", 64), PreActivationPlanSHA256: strings.Repeat("4", 64),
		ActivatedPlanSHA256: plan.PlanSHA256, ActivationEvaluationTime: catalogChainEvaluationTime.Format(time.RFC3339),
		RootCount: len(roots), DistrustedCount: len(distrusted), Roots: roots, DistrustedSHA256: append([]string(nil), distrusted...),
		Authentication: cloneTrustBundleAuthentication(auth), Plan: plan,
	}
	activation.ActivationSHA256 = trustBundleActivationDigest(activation)
	activation.capability = &trustBundleActivationCapability{activationSHA256: activation.ActivationSHA256}
	return activation
}

func encodeTestBase64(data []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var output strings.Builder
	for index := 0; index < len(data); index += 3 {
		remaining := len(data) - index
		value := uint32(data[index]) << 16
		if remaining > 1 {
			value |= uint32(data[index+1]) << 8
		}
		if remaining > 2 {
			value |= uint32(data[index+2])
		}
		output.WriteByte(alphabet[(value>>18)&63])
		output.WriteByte(alphabet[(value>>12)&63])
		if remaining > 1 {
			output.WriteByte(alphabet[(value>>6)&63])
		} else {
			output.WriteByte('=')
		}
		if remaining > 2 {
			output.WriteByte(alphabet[value&63])
		} else {
			output.WriteByte('=')
		}
	}
	return output.String()
}

func cloneCatalogChainActivation(source TrustBundleActivation) TrustBundleActivation {
	clone := source
	clone.Roots = make([]ActivatedTrustAnchor, len(source.Roots))
	for index, root := range source.Roots {
		clone.Roots[index] = root
		clone.Roots[index].CertificateDER = append([]byte(nil), root.CertificateDER...)
	}
	clone.DistrustedSHA256 = append([]string(nil), source.DistrustedSHA256...)
	clone.Authentication = cloneTrustBundleAuthentication(source.Authentication)
	clone.Plan = source.Plan
	clone.Plan.Roots = append([]TrustAnchor(nil), source.Plan.Roots...)
	clone.Plan.DistrustedSHA256 = append([]string(nil), source.Plan.DistrustedSHA256...)
	clone.Plan.Authentication = cloneTrustBundleAuthentication(source.Plan.Authentication)
	clone.Plan.Limitations = append([]string(nil), source.Plan.Limitations...)
	return clone
}
