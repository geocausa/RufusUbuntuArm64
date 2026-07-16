package acquisition

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDescribePublicKeyAndCanonicalRootDraft(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	rootA, rootB := trustSigner(1), trustSigner(33)
	catalog := trustSigner(65)
	summary, err := DescribePublicKey([]byte(base64.StdEncoding.EncodeToString(rootA.public) + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if summary.KeyID != rootA.id || summary.Type != "ed25519" || summary.PublicKey != base64.StdEncoding.EncodeToString(rootA.public) {
		t.Fatalf("unexpected public key summary: %+v", summary)
	}
	metadata := rootMetadata(1, now.Add(-time.Hour), now.Add(180*24*time.Hour), []testTrustSigner{rootA, rootB}, []testTrustSigner{catalog})
	pretty, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	canonical, manifest, err := CanonicalizeRootDraft(pretty, now)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(canonical, []byte("\n")) {
		t.Fatalf("canonical root contains whitespace: %q", canonical)
	}
	if manifest.MetadataType != "root" || manifest.Version != 1 || manifest.Threshold != 2 || len(manifest.AuthorizedKeyIDs) != 2 {
		t.Fatalf("unexpected root manifest: %+v", manifest)
	}
	if manifest.PayloadBytes != len(canonical) || len(manifest.PayloadSHA256) != 64 {
		t.Fatalf("manifest payload binding is incomplete: %+v", manifest)
	}
}

func TestAssembleEnvelopeDeterministicAndVerifiable(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	rootA, rootB := trustSigner(1), trustSigner(33)
	catalog := trustSigner(65)
	metadata := rootMetadata(1, now.Add(-time.Hour), now.Add(180*24*time.Hour), []testTrustSigner{rootA, rootB}, []testTrustSigner{catalog})
	draft, _ := json.MarshalIndent(metadata, "", "  ")
	payload, _, err := CanonicalizeRootDraft(draft, now)
	if err != nil {
		t.Fatal(err)
	}
	detached := []DetachedMetadataSignature{
		{KeyID: rootB.id, Signature: ed25519.Sign(rootB.private, payload)},
		{KeyID: strings.ToUpper(rootA.id), Signature: []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(rootA.private, payload)))},
	}
	first, err := AssembleMetadataEnvelope(payload, detached)
	if err != nil {
		t.Fatal(err)
	}
	second, err := AssembleMetadataEnvelope(payload, []DetachedMetadataSignature{detached[1], detached[0]})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("envelope assembly is not deterministic\n%s\n%s", first, second)
	}
	verified, err := VerifyBootstrapRoot(first, now)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Metadata.Version != 1 {
		t.Fatalf("verified root version = %d", verified.Metadata.Version)
	}
	if _, err := AssembleMetadataEnvelope(payload, append(detached, detached[0])); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate detached signature error = %v", err)
	}
}

func TestCanonicalCatalogDraftAndChainVerification(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	oldA, oldB := trustSigner(1), trustSigner(33)
	newA, newB := trustSigner(65), trustSigner(97)
	catalogSigner := trustSigner(129)
	rootOne := rootMetadata(1, now.Add(-2*time.Hour), now.Add(180*24*time.Hour), []testTrustSigner{oldA, oldB}, []testTrustSigner{catalogSigner})
	rootTwo := rootMetadata(2, now.Add(-time.Hour), now.Add(365*24*time.Hour), []testTrustSigner{newA, newB}, []testTrustSigner{catalogSigner})
	chain := [][]byte{
		signedEnvelope(t, rootOne, oldA, oldB),
		signedEnvelope(t, rootTwo, oldA, oldB, newA, newB),
	}
	root, err := VerifyRootChain(chain, now)
	if err != nil {
		t.Fatal(err)
	}
	catalog := channelCatalogMetadata(3, now.Add(-time.Minute), now.Add(7*24*time.Hour))
	pretty, _ := json.MarshalIndent(catalog, "", "  ")
	payload, manifest, err := CanonicalizeCatalogDraft(root, pretty, now)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Role != "catalog" || manifest.Threshold != 1 || manifest.AuthorizedKeyIDs[0] != catalogSigner.id {
		t.Fatalf("unexpected catalog manifest: %+v", manifest)
	}
	envelope, err := AssembleMetadataEnvelope(payload, []DetachedMetadataSignature{{
		KeyID: catalogSigner.id, Signature: ed25519.Sign(catalogSigner.private, payload),
	}})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyChannelCatalog(root, envelope, now)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Metadata.Version != 3 {
		t.Fatalf("catalog version = %d", verified.Metadata.Version)
	}
	if _, err := VerifyRootChain([][]byte{chain[0], signedEnvelope(t, func() RootMetadata { bad := rootTwo; bad.Version = 3; return bad }(), oldA, oldB, newA, newB)}, now); err == nil || !strings.Contains(err.Error(), "advance exactly") {
		t.Fatalf("skipped root chain error = %v", err)
	}
}

func TestAdminDraftsRejectUnknownDuplicateAndWrongPayload(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	rootA, rootB := trustSigner(1), trustSigner(33)
	catalog := trustSigner(65)
	metadata := rootMetadata(1, now.Add(-time.Hour), now.Add(24*time.Hour), []testTrustSigner{rootA, rootB}, []testTrustSigner{catalog})
	raw, _ := json.Marshal(metadata)
	unknown := append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"unexpected":true}`)...)
	if _, _, err := CanonicalizeRootDraft(unknown, now); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown root field error = %v", err)
	}
	duplicate := []byte(`{"_type":"root","_type":"root"}`)
	if _, _, err := CanonicalizeRootDraft(duplicate, now); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate root key error = %v", err)
	}
	payload, _, err := CanonicalizeRootDraft(raw, now)
	if err != nil {
		t.Fatal(err)
	}
	badSignature := ed25519.Sign(rootA.private, append([]byte(nil), payload[:len(payload)-1]...))
	envelope, err := AssembleMetadataEnvelope(payload, []DetachedMetadataSignature{
		{KeyID: rootA.id, Signature: badSignature},
		{KeyID: rootB.id, Signature: ed25519.Sign(rootB.private, payload)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBootstrapRoot(envelope, now); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("wrong payload signature error = %v", err)
	}
}

func TestAdminCanonicalizationNormalizesMutableFields(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	rootA, rootB := trustSigner(1), trustSigner(33)
	catalogSigner := trustSigner(65)
	metadata := rootMetadata(1, now.Add(-time.Hour), now.Add(24*time.Hour), []testTrustSigner{rootA, rootB}, []testTrustSigner{catalogSigner})
	root, err := VerifyBootstrapRoot(signedEnvelope(t, metadata, rootA, rootB), now)
	if err != nil {
		t.Fatal(err)
	}
	catalog := channelCatalogMetadata(1, now.Add(-time.Minute), now.Add(24*time.Hour))
	catalog.Generated = now.Add(-time.Minute).Format("2006-01-02T15:04:05+00:00")
	catalog.Images[0].ID = "Ubuntu-24.04-ARM64"
	catalog.Images[0].Architecture = "ARM64"
	catalog.Images[0].RedirectHosts = []string{"z.example.com", "A.EXAMPLE.COM"}
	payload, _, err := CanonicalizeCatalogDraft(root, mustMarshal(t, catalog), now)
	if err != nil {
		t.Fatal(err)
	}
	var normalized CatalogMetadata
	if err := json.Unmarshal(payload, &normalized); err != nil {
		t.Fatal(err)
	}
	image := normalized.Images[0]
	if image.ID != "ubuntu-24.04-arm64" || image.Architecture != "arm64" {
		t.Fatalf("catalog fields were not normalized: %+v", image)
	}
	if strings.Join(image.RedirectHosts, ",") != "a.example.com,z.example.com" {
		t.Fatalf("redirect hosts were not normalized and sorted: %v", image.RedirectHosts)
	}
	if normalized.Generated != now.Add(-time.Minute).UTC().Format(time.RFC3339) {
		t.Fatalf("generation time was not normalized: %s", normalized.Generated)
	}
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestCanonicalizeChannelConfig(t *testing.T) {
	config := ChannelConfig{
		Schema:        ChannelConfigSchema,
		Enabled:       true,
		BootstrapRoot: " 1.root.json ",
		RootURL:       " https://updates.example.com/roots/{version}.json ",
		CatalogURL:    " https://updates.example.com/catalog.json ",
		AllowedHosts:  []string{"updates.example.com"},
	}
	first, err := CanonicalizeChannelConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	second, err := CanonicalizeChannelConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) || bytes.Contains(first, []byte("\n")) {
		t.Fatalf("channel config is not deterministic: %q", first)
	}
	if bytes.Contains(first, []byte(" 1.root.json ")) || bytes.Contains(first, []byte(" https://")) {
		t.Fatalf("channel config whitespace was not normalized: %q", first)
	}
	config.CatalogURL = "https://127.0.0.1/catalog.json"
	if _, err := CanonicalizeChannelConfig(config); err == nil {
		t.Fatal("private/loopback production URL was accepted")
	}
}

func TestAdministrativeEnvelopeRejectsUnknownAndInsufficientSignatures(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	rootA, rootB := trustSigner(1), trustSigner(33)
	catalogSigner := trustSigner(65)
	metadata := rootMetadata(1, now.Add(-time.Hour), now.Add(24*time.Hour), []testTrustSigner{rootA, rootB}, []testTrustSigner{catalogSigner})
	payload, _, err := CanonicalizeRootDraft(mustMarshal(t, metadata), now)
	if err != nil {
		t.Fatal(err)
	}
	insufficient, err := AssembleMetadataEnvelope(payload, []DetachedMetadataSignature{{
		KeyID: rootA.id, Signature: ed25519.Sign(rootA.private, payload),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAdministrativeEnvelope(nil, insufficient, now); err == nil || !strings.Contains(err.Error(), "threshold") {
		t.Fatalf("insufficient signature error = %v", err)
	}
	withUnknown, err := AssembleMetadataEnvelope(payload, []DetachedMetadataSignature{
		{KeyID: rootA.id, Signature: ed25519.Sign(rootA.private, payload)},
		{KeyID: rootB.id, Signature: ed25519.Sign(rootB.private, payload)},
		{KeyID: catalogSigner.id, Signature: ed25519.Sign(catalogSigner.private, payload)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAdministrativeEnvelope(nil, withUnknown, now); err == nil || !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("unknown signature error = %v", err)
	}
}

func TestAdministrativeCatalogEnvelopeRequiresRootAndRejectsExtraRootSignature(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	rootA, rootB := trustSigner(1), trustSigner(33)
	catalogSigner := trustSigner(65)
	metadata := rootMetadata(1, now.Add(-time.Hour), now.Add(24*time.Hour), []testTrustSigner{rootA, rootB}, []testTrustSigner{catalogSigner})
	root, err := VerifyBootstrapRoot(signedEnvelope(t, metadata, rootA, rootB), now)
	if err != nil {
		t.Fatal(err)
	}
	catalog := channelCatalogMetadata(1, now.Add(-time.Minute), now.Add(12*time.Hour))
	payload, _, err := CanonicalizeCatalogDraft(root, mustMarshal(t, catalog), now)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := AssembleMetadataEnvelope(payload, []DetachedMetadataSignature{{
		KeyID: catalogSigner.id, Signature: ed25519.Sign(catalogSigner.private, payload),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAdministrativeEnvelope(nil, valid, now); err == nil || !strings.Contains(err.Error(), "root chain") {
		t.Fatalf("missing root chain error = %v", err)
	}
	if _, err := VerifyAdministrativeEnvelope(root, valid, now); err != nil {
		t.Fatal(err)
	}
	withExtra, err := AssembleMetadataEnvelope(payload, []DetachedMetadataSignature{
		{KeyID: catalogSigner.id, Signature: ed25519.Sign(catalogSigner.private, payload)},
		{KeyID: rootA.id, Signature: ed25519.Sign(rootA.private, payload)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAdministrativeEnvelope(root, withExtra, now); err == nil || !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("extra root signature error = %v", err)
	}
}
