package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/geocausa/RufusArm64/internal/acquisition"
)

type operatorSigner struct {
	id      string
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

func newOperatorSigner(seedByte byte) operatorSigner {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = seedByte + byte(index)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return operatorSigner{id: acquisition.PublicKeyID(publicKey), public: publicKey, private: privateKey}
}

func operatorRootMetadata(now time.Time, signers []operatorSigner, catalog operatorSigner) acquisition.RootMetadata {
	all := append(append([]operatorSigner(nil), signers...), catalog)
	sort.Slice(all, func(i, j int) bool { return all[i].id < all[j].id })
	keys := make([]acquisition.TrustKey, 0, len(all))
	for _, signer := range all {
		keys = append(keys, acquisition.TrustKey{
			ID: signer.id, Type: "ed25519", Public: base64.StdEncoding.EncodeToString(signer.public),
		})
	}
	rootIDs := []string{signers[0].id, signers[1].id}
	sort.Strings(rootIDs)
	return acquisition.RootMetadata{
		Type: "root", Schema: acquisition.TrustSchemaVersion, Version: 1,
		Generated: now.Add(-time.Hour).Format(time.RFC3339), Expires: now.Add(180 * 24 * time.Hour).Format(time.RFC3339),
		Keys: keys,
		Roles: acquisition.RootRoles{
			Root:    acquisition.TrustRole{KeyIDs: rootIDs, Threshold: 2},
			Catalog: acquisition.TrustRole{KeyIDs: []string{catalog.id}, Threshold: 1},
		},
	}
}

func TestOfflineRootWorkflow(t *testing.T) {
	now := time.Date(2026, 7, 16, 20, 0, 0, 0, time.UTC)
	rootA, rootB, catalog := newOperatorSigner(1), newOperatorSigner(33), newOperatorSigner(65)
	directory := t.TempDir()
	draftPath := filepath.Join(directory, "root-draft.json")
	payloadPath := filepath.Join(directory, "root.payload.json")
	manifestPath := filepath.Join(directory, "root.manifest.json")
	envelopePath := filepath.Join(directory, "1.root.json")
	metadata := operatorRootMetadata(now, []operatorSigner{rootA, rootB}, catalog)
	draft, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(draftPath, draft, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{
		"payload", "root", "--input", draftPath, "--output", payloadPath,
		"--manifest", manifestPath, "--now", now.Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(payloadPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest acquisition.SigningManifest
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.PayloadBytes != len(payload) || manifest.Threshold != 2 {
		t.Fatalf("unexpected signing manifest: %+v", manifest)
	}
	signatureA := filepath.Join(directory, "root-a.sig")
	signatureB := filepath.Join(directory, "root-b.sig")
	if err := os.WriteFile(signatureA, ed25519.Sign(rootA.private, payload), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(signatureB, []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(rootB.private, payload))), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{
		"envelope", "assemble", "--payload", payloadPath,
		"--signature", rootB.id + "=" + signatureB,
		"--signature", rootA.id + "=" + signatureA,
		"--output", envelopePath,
	}); err != nil {
		t.Fatal(err)
	}
	envelope, err := os.ReadFile(envelopePath)
	if err != nil {
		t.Fatal(err)
	}
	root, err := acquisition.VerifyBootstrapRoot(envelope, now)
	if err != nil {
		t.Fatal(err)
	}
	if root.Metadata.Version != 1 {
		t.Fatalf("root version = %d", root.Metadata.Version)
	}
	secretMaterial := filepath.Join(directory, "must-not-be-accepted.key")
	if err := os.WriteFile(secretMaterial, rootA.private, 0o600); err != nil {
		t.Fatal(err)
	}
	forbiddenOutput := filepath.Join(directory, "forbidden-envelope.json")
	if err := run([]string{
		"envelope", "assemble", "--payload", payloadPath,
		"--signature", rootA.id + "=" + secretMaterial,
		"--signature", rootB.id + "=" + signatureB,
		"--output", forbiddenOutput, "--now", now.Format(time.RFC3339),
	}); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("private-key material used as a detached signature was not refused: %v", err)
	}
	if _, err := os.Stat(forbiddenOutput); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("forbidden envelope was created: %v", err)
	}
	if err := run([]string{"verify", "root", "--root", envelopePath, "--now", now.Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
}

func TestKeyIDAndEnabledConfigWorkflow(t *testing.T) {
	now := time.Date(2026, 7, 16, 20, 0, 0, 0, time.UTC)
	rootA, rootB, catalog := newOperatorSigner(1), newOperatorSigner(33), newOperatorSigner(65)
	directory := t.TempDir()
	publicPath := filepath.Join(directory, "root-a.pub")
	if err := os.WriteFile(publicPath, []byte(base64.StdEncoding.EncodeToString(rootA.public)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"key-id", "--public-key", publicPath}); err != nil {
		t.Fatal(err)
	}
	metadata := operatorRootMetadata(now, []operatorSigner{rootA, rootB}, catalog)
	canonical, _, err := acquisition.CanonicalizeRootDraft(mustJSON(t, metadata), now)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := acquisition.AssembleMetadataEnvelope(canonical, []acquisition.DetachedMetadataSignature{
		{KeyID: rootA.id, Signature: ed25519.Sign(rootA.private, canonical)},
		{KeyID: rootB.id, Signature: ed25519.Sign(rootB.private, canonical)},
	})
	if err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(directory, "1.root.json")
	if err := os.WriteFile(rootPath, envelope, 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "channel.json")
	if err := run([]string{
		"channel-config", "--bootstrap-root", rootPath,
		"--root-url", "https://updates.example.com/roots/{version}.json",
		"--catalog-url", "https://updates.example.com/catalog.json",
		"--host", "updates.example.com", "--output", configPath,
		"--now", now.Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}
	configData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var config acquisition.ChannelConfig
	if err := json.Unmarshal(configData, &config); err != nil {
		t.Fatal(err)
	}
	if !config.Enabled || config.BootstrapRoot != "1.root.json" {
		t.Fatalf("unexpected channel config: %+v", config)
	}
}

func TestExecutableHasNoSecretKeyInterface(t *testing.T) {
	if err := run([]string{"key-id", "--private-key", "forbidden"}); err == nil {
		t.Fatal("a private-key option was unexpectedly accepted")
	}
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not resolve test source path")
	}
	mainSource, err := os.ReadFile(filepath.Join(filepath.Dir(currentFile), "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"ed25519.PrivateKey", "ed25519.Sign(", "--private-key"} {
		if strings.Contains(string(mainSource), forbidden) {
			t.Fatalf("operator executable contains forbidden secret-key interface %q", forbidden)
		}
	}
}

func TestAtomicOutputRefusesSymlinkAndExistingFile(t *testing.T) {
	directory := t.TempDir()
	outside := filepath.Join(directory, "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "output")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicOutput(link, []byte("new"), false); err == nil {
		t.Fatal("symlink output was accepted")
	}
	contents, _ := os.ReadFile(outside)
	if string(contents) != "outside" {
		t.Fatalf("outside file changed: %q", contents)
	}
	regular := filepath.Join(directory, "regular")
	if err := os.WriteFile(regular, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicOutput(regular, []byte("new"), false); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing output error = %v", err)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestPublicationDirectoryDeterministic(t *testing.T) {
	now := time.Date(2026, 7, 16, 20, 0, 0, 0, time.UTC)
	rootA, rootB, catalogSigner := newOperatorSigner(1), newOperatorSigner(33), newOperatorSigner(65)
	directory := t.TempDir()
	rootMetadata := operatorRootMetadata(now, []operatorSigner{rootA, rootB}, catalogSigner)
	rootPayload, _, err := acquisition.CanonicalizeRootDraft(mustJSON(t, rootMetadata), now)
	if err != nil {
		t.Fatal(err)
	}
	rootEnvelope, err := acquisition.AssembleMetadataEnvelope(rootPayload, []acquisition.DetachedMetadataSignature{
		{KeyID: rootA.id, Signature: ed25519.Sign(rootA.private, rootPayload)},
		{KeyID: rootB.id, Signature: ed25519.Sign(rootB.private, rootPayload)},
	})
	if err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(directory, "1.root.json")
	if err := os.WriteFile(rootPath, rootEnvelope, 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := acquisition.VerifyBootstrapRoot(rootEnvelope, now)
	if err != nil {
		t.Fatal(err)
	}
	catalogMetadata := acquisition.CatalogMetadata{
		Type: "catalog", Schema: acquisition.TrustSchemaVersion, Version: 1,
		Generated: now.Add(-time.Minute).Format(time.RFC3339), Expires: now.Add(7 * 24 * time.Hour).Format(time.RFC3339),
		Images: []acquisition.Image{{
			ID: "ubuntu-24.04-arm64", Name: "Ubuntu Desktop", Version: "24.04 LTS",
			Architecture: "arm64", Filename: "ubuntu.iso",
			URL: "https://downloads.example.com/ubuntu.iso", SHA256: strings.Repeat("ab", 32), Size: 1024,
		}},
	}
	catalogPayload, _, err := acquisition.CanonicalizeCatalogDraft(root, mustJSON(t, catalogMetadata), now)
	if err != nil {
		t.Fatal(err)
	}
	catalogEnvelope, err := acquisition.AssembleMetadataEnvelope(catalogPayload, []acquisition.DetachedMetadataSignature{{
		KeyID: catalogSigner.id, Signature: ed25519.Sign(catalogSigner.private, catalogPayload),
	}})
	if err != nil {
		t.Fatal(err)
	}
	catalogPath := filepath.Join(directory, "catalog-envelope.json")
	if err := os.WriteFile(catalogPath, catalogEnvelope, 0o600); err != nil {
		t.Fatal(err)
	}
	configData, err := acquisition.CanonicalizeChannelConfig(acquisition.ChannelConfig{
		Schema: acquisition.ChannelConfigSchema, Enabled: true, BootstrapRoot: "1.root.json",
		RootURL:      "https://updates.example.com/{version}.root.json",
		CatalogURL:   "https://updates.example.com/catalog.json",
		AllowedHosts: []string{"updates.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "channel-input.json")
	if err := os.WriteFile(configPath, configData, 0o600); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(directory, "publication-one")
	second := filepath.Join(directory, "publication-two")
	arguments := func(output string) []string {
		return []string{
			"publish", "--root", rootPath, "--catalog", catalogPath, "--config", configPath,
			"--directory", output, "--now", now.Format(time.RFC3339),
		}
	}
	if err := run(arguments(first)); err != nil {
		t.Fatal(err)
	}
	if err := run(arguments(second)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"1.root.json", "catalog.json", "channel.json", "publication.json", "SHA256SUMS"} {
		firstData, err := os.ReadFile(filepath.Join(first, name))
		if err != nil {
			t.Fatal(err)
		}
		secondData, err := os.ReadFile(filepath.Join(second, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(firstData, secondData) {
			t.Fatalf("publication file %s is not deterministic", name)
		}
	}
	if err := run(arguments(first)); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing publication directory error = %v", err)
	}
	checksums, err := os.ReadFile(filepath.Join(first, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"1.root.json", "catalog.json", "channel.json", "publication.json"} {
		if !strings.Contains(string(checksums), "  "+name+"\n") {
			t.Fatalf("SHA256SUMS does not include %s", name)
		}
	}
}
