package acquisition

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"
)

type testTrustSigner struct {
	id      string
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

func trustSigner(seedByte byte) testTrustSigner {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = seedByte + byte(index)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return testTrustSigner{id: PublicKeyID(publicKey), public: publicKey, private: privateKey}
}

func canonicalPayload(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func signedEnvelope(t *testing.T, payload any, signers ...testTrustSigner) []byte {
	t.Helper()
	canonical := canonicalPayload(t, payload)
	signatures := make([]MetadataSignature, 0, len(signers))
	for _, signer := range signers {
		signatures = append(signatures, MetadataSignature{
			KeyID: signer.id,
			Sig:   base64.StdEncoding.EncodeToString(ed25519.Sign(signer.private, canonical)),
		})
	}
	sort.Slice(signatures, func(i, j int) bool { return signatures[i].KeyID < signatures[j].KeyID })
	envelope := struct {
		Signed     json.RawMessage     `json:"signed"`
		Signatures []MetadataSignature `json:"signatures"`
	}{Signed: canonical, Signatures: signatures}
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func rootMetadata(version int, generated, expires time.Time, rootSigners, catalogSigners []testTrustSigner) RootMetadata {
	all := make(map[string]testTrustSigner)
	for _, signer := range append(append([]testTrustSigner{}, rootSigners...), catalogSigners...) {
		all[signer.id] = signer
	}
	ids := make([]string, 0, len(all))
	for id := range all {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	keys := make([]TrustKey, 0, len(ids))
	for _, id := range ids {
		keys = append(keys, TrustKey{ID: id, Type: "ed25519", Public: base64.StdEncoding.EncodeToString(all[id].public)})
	}
	rootIDs := make([]string, 0, len(rootSigners))
	for _, signer := range rootSigners {
		rootIDs = append(rootIDs, signer.id)
	}
	sort.Strings(rootIDs)
	catalogIDs := make([]string, 0, len(catalogSigners))
	for _, signer := range catalogSigners {
		catalogIDs = append(catalogIDs, signer.id)
	}
	sort.Strings(catalogIDs)
	return RootMetadata{
		Type:      "root",
		Schema:    TrustSchemaVersion,
		Version:   version,
		Generated: generated.UTC().Format(time.RFC3339),
		Expires:   expires.UTC().Format(time.RFC3339),
		Keys:      keys,
		Roles: RootRoles{
			Root:    TrustRole{KeyIDs: rootIDs, Threshold: 2},
			Catalog: TrustRole{KeyIDs: catalogIDs, Threshold: 1},
		},
	}
}

func channelCatalogMetadata(version int, generated, expires time.Time) CatalogMetadata {
	return CatalogMetadata{
		Type:      "catalog",
		Schema:    TrustSchemaVersion,
		Version:   version,
		Generated: generated.UTC().Format(time.RFC3339),
		Expires:   expires.UTC().Format(time.RFC3339),
		Images: []Image{{
			ID:           "ubuntu-24.04-arm64",
			Name:         "Ubuntu Desktop",
			Version:      "24.04 LTS",
			Architecture: "arm64",
			Filename:     "ubuntu-24.04-arm64.iso",
			URL:          "https://downloads.example.com/ubuntu.iso",
			SHA256:       strings.Repeat("ab", 32),
			Size:         4 * 1024 * 1024 * 1024,
		}},
	}
}

func TestBootstrapRootAndCatalogThresholds(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	rootA, rootB := trustSigner(1), trustSigner(33)
	catalogA := trustSigner(65)
	root := rootMetadata(1, now.Add(-time.Hour), now.Add(180*24*time.Hour), []testTrustSigner{rootA, rootB}, []testTrustSigner{catalogA})
	verifiedRoot, err := VerifyBootstrapRoot(signedEnvelope(t, root, rootA, rootB), now)
	if err != nil {
		t.Fatal(err)
	}
	if verifiedRoot.Metadata.Version != 1 || verifiedRoot.SHA256 == "" {
		t.Fatalf("unexpected verified root: %+v", verifiedRoot)
	}
	catalog := channelCatalogMetadata(1, now.Add(-time.Minute), now.Add(7*24*time.Hour))
	verifiedCatalog, err := VerifyChannelCatalog(verifiedRoot, signedEnvelope(t, catalog, catalogA), now)
	if err != nil {
		t.Fatal(err)
	}
	if verifiedCatalog.Metadata.Version != 1 || len(verifiedCatalog.SigningKeyIDs) != 1 {
		t.Fatalf("unexpected catalog: %+v", verifiedCatalog)
	}
	if _, err := VerifyBootstrapRoot(signedEnvelope(t, root, rootA), now); err == nil || !strings.Contains(err.Error(), "threshold") {
		t.Fatalf("single root signature error = %v", err)
	}
}

func TestRootRotationRequiresOldAndNewThresholds(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	oldA, oldB := trustSigner(1), trustSigner(33)
	newA, newB := trustSigner(65), trustSigner(97)
	catalog := trustSigner(129)
	oldMetadata := rootMetadata(1, now.Add(-2*time.Hour), now.Add(180*24*time.Hour), []testTrustSigner{oldA, oldB}, []testTrustSigner{catalog})
	oldRoot, err := VerifyBootstrapRoot(signedEnvelope(t, oldMetadata, oldA, oldB), now)
	if err != nil {
		t.Fatal(err)
	}
	newMetadata := rootMetadata(2, now.Add(-time.Hour), now.Add(365*24*time.Hour), []testTrustSigner{newA, newB}, []testTrustSigner{catalog})
	rotated, err := VerifyRootUpdate(oldRoot, signedEnvelope(t, newMetadata, oldA, oldB, newA, newB), now)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Metadata.Version != 2 {
		t.Fatalf("rotation version = %d", rotated.Metadata.Version)
	}
	if _, err := VerifyRootUpdate(oldRoot, signedEnvelope(t, newMetadata, oldA, oldB), now); err == nil || !strings.Contains(err.Error(), "replacement root") {
		t.Fatalf("missing new threshold error = %v", err)
	}
	if _, err := VerifyRootUpdate(oldRoot, signedEnvelope(t, newMetadata, newA, newB), now); err == nil || !strings.Contains(err.Error(), "current root") {
		t.Fatalf("missing old threshold error = %v", err)
	}
	versionFour := newMetadata
	versionFour.Version = 4
	if _, err := VerifyRootUpdate(oldRoot, signedEnvelope(t, versionFour, oldA, oldB, newA, newB), now); err == nil || !strings.Contains(err.Error(), "advance exactly") {
		t.Fatalf("skipped root version error = %v", err)
	}
}

func TestTrustMetadataRejectsNonCanonicalAndDuplicateSignatures(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	rootA, rootB := trustSigner(1), trustSigner(33)
	catalog := trustSigner(65)
	metadata := rootMetadata(1, now.Add(-time.Hour), now.Add(24*time.Hour), []testTrustSigner{rootA, rootB}, []testTrustSigner{catalog})
	nonCanonical, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if canonical, err := canonicalJSON(nonCanonical); err != nil || string(canonical) == string(nonCanonical) {
		t.Fatalf("test root unexpectedly canonical: %v", err)
	}
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(rootA.private, nonCanonical))
	envelope := []byte(`{"signed":` + string(nonCanonical) + `,"signatures":[{"keyid":"` + rootA.id + `","sig":"` + signature + `"},{"keyid":"` + rootB.id + `","sig":"` + base64.StdEncoding.EncodeToString(ed25519.Sign(rootB.private, nonCanonical)) + `"}]}`)
	if _, err := VerifyBootstrapRoot(envelope, now); err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("non-canonical root error = %v", err)
	}
	valid := signedEnvelope(t, metadata, rootA, rootB)
	var parsed MetadataEnvelope
	if err := json.Unmarshal(valid, &parsed); err != nil {
		t.Fatal(err)
	}
	parsed.Signatures = append(parsed.Signatures, parsed.Signatures[0])
	duplicate, _ := json.Marshal(parsed)
	if _, err := VerifyBootstrapRoot(duplicate, now); err == nil || !strings.Contains(err.Error(), "duplicate metadata signature") {
		t.Fatalf("duplicate signature error = %v", err)
	}
}

func TestTrustMetadataRejectsMalformedUnknownSignature(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	rootA, rootB := trustSigner(1), trustSigner(33)
	catalog := trustSigner(65)
	unknown := trustSigner(97)
	metadata := rootMetadata(1, now.Add(-time.Hour), now.Add(24*time.Hour), []testTrustSigner{rootA, rootB}, []testTrustSigner{catalog})
	var envelope MetadataEnvelope
	if err := json.Unmarshal(signedEnvelope(t, metadata, rootA, rootB), &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Signatures = append(envelope.Signatures, MetadataSignature{KeyID: unknown.id, Sig: "not-standard-base64"})
	sort.Slice(envelope.Signatures, func(i, j int) bool { return envelope.Signatures[i].KeyID < envelope.Signatures[j].KeyID })
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBootstrapRoot(data, now); err == nil || !strings.Contains(err.Error(), "standard base64") {
		t.Fatalf("malformed unknown signature error = %v", err)
	}
}

func TestCatalogRejectsUnsortedImagesAndExpiredRoot(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	rootA, rootB := trustSigner(1), trustSigner(33)
	catalogSigner := trustSigner(65)
	expiredRootMetadata := rootMetadata(1, now.Add(-48*time.Hour), now.Add(-time.Hour), []testTrustSigner{rootA, rootB}, []testTrustSigner{catalogSigner})
	// Bootstrap validation uses a time before expiry so the cached root can be tested later.
	root, err := VerifyBootstrapRoot(signedEnvelope(t, expiredRootMetadata, rootA, rootB), now.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	catalog := channelCatalogMetadata(1, now.Add(-time.Hour), now.Add(24*time.Hour))
	if _, err := VerifyChannelCatalog(root, signedEnvelope(t, catalog, catalogSigner), now); err == nil || !strings.Contains(err.Error(), "trusted root") {
		t.Fatalf("expired root error = %v", err)
	}
	freshRootMetadata := rootMetadata(1, now.Add(-time.Hour), now.Add(24*time.Hour), []testTrustSigner{rootA, rootB}, []testTrustSigner{catalogSigner})
	freshRoot, err := VerifyBootstrapRoot(signedEnvelope(t, freshRootMetadata, rootA, rootB), now)
	if err != nil {
		t.Fatal(err)
	}
	catalog.Images = append([]Image{{
		ID: "z-last", Name: "Last", Version: "1", Architecture: "arm64", Filename: "last.iso",
		URL: "https://downloads.example.com/last.iso", SHA256: strings.Repeat("cd", 32), Size: 1,
	}}, catalog.Images...)
	if _, err := VerifyChannelCatalog(freshRoot, signedEnvelope(t, catalog, catalogSigner), now); err == nil || !strings.Contains(err.Error(), "sorted") {
		t.Fatalf("unsorted catalog error = %v", err)
	}
}
