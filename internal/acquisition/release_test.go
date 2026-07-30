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

func releaseRootMetadata(version int, generated, expires time.Time, rootSigners, catalogSigners, releaseSigners []testTrustSigner, releaseThreshold int) RootMetadata {
	metadata := rootMetadata(version, generated, expires, rootSigners, catalogSigners)
	known := make(map[string]TrustKey, len(metadata.Keys)+len(releaseSigners))
	for _, key := range metadata.Keys {
		known[key.ID] = key
	}
	releaseIDs := make([]string, 0, len(releaseSigners))
	for _, signer := range releaseSigners {
		releaseIDs = append(releaseIDs, signer.id)
		known[signer.id] = TrustKey{ID: signer.id, Type: "ed25519", Public: base64.StdEncoding.EncodeToString(signer.public)}
	}
	sort.Strings(releaseIDs)
	ids := make([]string, 0, len(known))
	for id := range known {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	metadata.Keys = metadata.Keys[:0]
	for _, id := range ids {
		metadata.Keys = append(metadata.Keys, known[id])
	}
	metadata.Roles.Release = &TrustRole{KeyIDs: releaseIDs, Threshold: releaseThreshold}
	return metadata
}

func testReleaseMetadata(version int, releaseVersion string, now time.Time) ReleaseMetadata {
	packageName := "rufusarm64_" + releaseVersion + "_arm64.deb"
	sourceName := "RufusArm64-" + releaseVersion + "-source.zip"
	assets := []ReleaseAsset{
		{Name: sourceName, Size: 2048, SHA256: strings.Repeat("ab", 32), URL: "https://github.com/geocausa/RufusUbuntuArm64/releases/download/v" + releaseVersion + "/" + sourceName},
		{Name: packageName, Size: 4096, SHA256: strings.Repeat("cd", 32), URL: "https://github.com/geocausa/RufusUbuntuArm64/releases/download/v" + releaseVersion + "/" + packageName, RedirectHosts: []string{"objects.githubusercontent.com"}},
	}
	sort.Slice(assets, func(i, j int) bool { return assets[i].Name < assets[j].Name })
	return ReleaseMetadata{
		Type: "release", Schema: TrustSchemaVersion, Version: version,
		Generated: now.Add(-time.Minute).Format(time.RFC3339), Expires: now.Add(7 * 24 * time.Hour).Format(time.RFC3339),
		Product: "RufusArm64", Repository: "geocausa/RufusUbuntuArm64",
		ReleaseVersion: releaseVersion, Tag: "v" + releaseVersion,
		Commit: strings.Repeat("a", 40), Channel: "stable", Assets: assets,
	}
}

func TestVerifyReleaseMetadataAndEvaluateUpdate(t *testing.T) {
	now := time.Date(2026, 7, 30, 14, 0, 0, 0, time.UTC)
	rootA, rootB := trustSigner(1), trustSigner(33)
	catalogSigner := trustSigner(65)
	releaseA, releaseB := trustSigner(97), trustSigner(129)
	rootMetadata := releaseRootMetadata(1, now.Add(-time.Hour), now.Add(180*24*time.Hour), []testTrustSigner{rootA, rootB}, []testTrustSigner{catalogSigner}, []testTrustSigner{releaseA, releaseB}, 2)
	root, err := VerifyBootstrapRoot(signedEnvelope(t, rootMetadata, rootA, rootB), now)
	if err != nil {
		t.Fatal(err)
	}
	metadata := testReleaseMetadata(7, "0.16.0", now)
	envelope := signedEnvelope(t, metadata, releaseA, releaseB)
	verified, err := VerifyReleaseMetadata(root, envelope, now)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Metadata.Version != 7 || len(verified.SigningKeyIDs) != 2 || verified.SHA256 == "" {
		t.Fatalf("unexpected verified release: %+v", verified)
	}
	decision, err := EvaluateRelease("0.15.0", 6, verified)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.UpdateAvailable || decision.ReleaseVersion != "0.16.0" || decision.Package.Name != "rufusarm64_0.16.0_arm64.deb" {
		t.Fatalf("unexpected update decision: %+v", decision)
	}
	current, err := EvaluateRelease("0.16.0", 7, verified)
	if err != nil || current.UpdateAvailable {
		t.Fatalf("current release decision = %+v, %v", current, err)
	}
}

func TestReleaseThresholdTamperExpiryAndMissingRoleRefusals(t *testing.T) {
	now := time.Date(2026, 7, 30, 14, 0, 0, 0, time.UTC)
	rootA, rootB := trustSigner(1), trustSigner(33)
	catalogSigner := trustSigner(65)
	releaseA, releaseB := trustSigner(97), trustSigner(129)
	withRelease := releaseRootMetadata(1, now.Add(-time.Hour), now.Add(180*24*time.Hour), []testTrustSigner{rootA, rootB}, []testTrustSigner{catalogSigner}, []testTrustSigner{releaseA, releaseB}, 2)
	root, err := VerifyBootstrapRoot(signedEnvelope(t, withRelease, rootA, rootB), now)
	if err != nil {
		t.Fatal(err)
	}
	metadata := testReleaseMetadata(1, "0.16.0", now)
	if _, err := VerifyReleaseMetadata(root, signedEnvelope(t, metadata, releaseA), now); err == nil || !strings.Contains(err.Error(), "threshold") {
		t.Fatalf("single release signature error = %v", err)
	}
	valid := signedEnvelope(t, metadata, releaseA, releaseB)
	var envelope MetadataEnvelope
	if err := json.Unmarshal(valid, &envelope); err != nil {
		t.Fatal(err)
	}
	tampered := metadata
	tampered.Commit = strings.Repeat("b", 40)
	envelope.Signed = canonicalPayload(t, tampered)
	tamperedEnvelope, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyReleaseMetadata(root, tamperedEnvelope, now); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("tampered release error = %v", err)
	}
	expired := metadata
	expired.Generated = now.Add(-48 * time.Hour).Format(time.RFC3339)
	expired.Expires = now.Add(-time.Hour).Format(time.RFC3339)
	if _, err := VerifyReleaseMetadata(root, signedEnvelope(t, expired, releaseA, releaseB), now); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired release error = %v", err)
	}
	withoutRelease := rootMetadata(1, now.Add(-time.Hour), now.Add(180*24*time.Hour), []testTrustSigner{rootA, rootB}, []testTrustSigner{catalogSigner})
	plainRoot, err := VerifyBootstrapRoot(signedEnvelope(t, withoutRelease, rootA, rootB), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyReleaseMetadata(plainRoot, valid, now); err == nil || !strings.Contains(err.Error(), "does not authorize") {
		t.Fatalf("missing release role error = %v", err)
	}
}

func TestReleaseMetadataValidationAndRollbackRefusals(t *testing.T) {
	now := time.Date(2026, 7, 30, 14, 0, 0, 0, time.UTC)
	rootA, rootB := trustSigner(1), trustSigner(33)
	catalogSigner, releaseSigner := trustSigner(65), trustSigner(97)
	rootMetadata := releaseRootMetadata(1, now.Add(-time.Hour), now.Add(180*24*time.Hour), []testTrustSigner{rootA, rootB}, []testTrustSigner{catalogSigner}, []testTrustSigner{releaseSigner}, 1)
	root, err := VerifyBootstrapRoot(signedEnvelope(t, rootMetadata, rootA, rootB), now)
	if err != nil {
		t.Fatal(err)
	}
	base := testReleaseMetadata(5, "0.16.0", now)
	cases := []struct {
		name string
		edit func(*ReleaseMetadata)
		want string
	}{
		{"tag mismatch", func(value *ReleaseMetadata) { value.Tag = "v0.16.1" }, "tag"},
		{"bad commit", func(value *ReleaseMetadata) { value.Commit = strings.Repeat("A", 40) }, "commit"},
		{"bad URL", func(value *ReleaseMetadata) { value.Assets[0].URL = "https://example.com/substituted" }, "URL"},
		{"explicit port", func(value *ReleaseMetadata) {
			value.Assets[0].URL = strings.Replace(value.Assets[0].URL, "https://github.com/", "https://github.com:443/", 1)
		}, "URL"},
		{"empty query", func(value *ReleaseMetadata) { value.Assets[0].URL += "?" }, "URL"},
		{"missing package", func(value *ReleaseMetadata) { value.Assets = value.Assets[:1] }, "exactly one ARM64 package"},
		{"unsorted assets", func(value *ReleaseMetadata) { value.Assets[0], value.Assets[1] = value.Assets[1], value.Assets[0] }, "sorted"},
		{"bad digest", func(value *ReleaseMetadata) { value.Assets[0].SHA256 = strings.Repeat("A", 64) }, "SHA-256"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			candidate := base
			candidate.Assets = append([]ReleaseAsset(nil), base.Assets...)
			test.edit(&candidate)
			if _, _, err := CanonicalizeReleaseDraft(root, mustMarshal(t, candidate), now); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want %q", err, test.want)
			}
		})
	}
	verified, err := VerifyReleaseMetadata(root, signedEnvelope(t, base, releaseSigner), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EvaluateRelease("0.15.0", 6, verified); err == nil || !strings.Contains(err.Error(), "metadata rollback") {
		t.Fatalf("metadata rollback error = %v", err)
	}
	if _, err := EvaluateRelease("0.17.0", 5, verified); err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Fatalf("release downgrade error = %v", err)
	}
	if _, err := EvaluateRelease("development", 5, verified); err == nil || !strings.Contains(err.Error(), "current version") {
		t.Fatalf("invalid current version error = %v", err)
	}
}

func TestCanonicalReleaseDraftAndAdministrativeEnvelope(t *testing.T) {
	now := time.Date(2026, 7, 30, 14, 0, 0, 0, time.UTC)
	rootA, rootB := trustSigner(1), trustSigner(33)
	catalogSigner, releaseSigner := trustSigner(65), trustSigner(97)
	rootMetadata := releaseRootMetadata(1, now.Add(-time.Hour), now.Add(180*24*time.Hour), []testTrustSigner{rootA, rootB}, []testTrustSigner{catalogSigner}, []testTrustSigner{releaseSigner}, 1)
	root, err := VerifyBootstrapRoot(signedEnvelope(t, rootMetadata, rootA, rootB), now)
	if err != nil {
		t.Fatal(err)
	}
	metadata := testReleaseMetadata(2, "0.16.0", now)
	payload, manifest, err := CanonicalizeReleaseDraft(root, mustMarshal(t, metadata), now)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.MetadataType != "release" || manifest.Role != "release" || manifest.Threshold != 1 || manifest.AuthorizedKeyIDs[0] != releaseSigner.id {
		t.Fatalf("unexpected release manifest: %+v", manifest)
	}
	envelope, err := AssembleMetadataEnvelope(payload, []DetachedMetadataSignature{{KeyID: releaseSigner.id, Signature: ed25519.Sign(releaseSigner.private, payload)}})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyAdministrativeEnvelope(root, envelope, now)
	if err != nil {
		t.Fatal(err)
	}
	if verified.MetadataType != "release" || verified.Version != 2 {
		t.Fatalf("unexpected administrative result: %+v", verified)
	}
}
