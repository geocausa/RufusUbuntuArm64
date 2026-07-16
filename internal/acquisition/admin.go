package acquisition

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SigningManifest describes the exact immutable payload that external offline
// signers must approve. It never contains secret key material.
type SigningManifest struct {
	MetadataType     string   `json:"metadata_type"`
	Version          int      `json:"version"`
	Generated        string   `json:"generated"`
	Expires          string   `json:"expires"`
	PayloadBytes     int      `json:"payload_bytes"`
	PayloadSHA256    string   `json:"payload_sha256"`
	Role             string   `json:"role"`
	Threshold        int      `json:"threshold"`
	AuthorizedKeyIDs []string `json:"authorized_key_ids"`
}

// PublicKeySummary is safe to display or publish alongside an offline key.
type PublicKeySummary struct {
	KeyID     string `json:"keyid"`
	Type      string `json:"type"`
	PublicKey string `json:"public"`
}

// DetachedMetadataSignature represents a signature produced by an external
// signer. Signature may contain raw, hexadecimal, or base64 Ed25519 bytes.
type DetachedMetadataSignature struct {
	KeyID     string
	Signature []byte
}

// DescribePublicKey validates a public Ed25519 key and derives the key ID used
// in RufusArm64 root metadata.
func DescribePublicKey(data []byte) (PublicKeySummary, error) {
	publicKey, err := DecodePublicKey(data)
	if err != nil {
		return PublicKeySummary{}, err
	}
	return PublicKeySummary{
		KeyID:     PublicKeyID(publicKey),
		Type:      "ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(publicKey),
	}, nil
}

// CanonicalizeRootDraft validates an unsigned root metadata draft and returns
// the exact canonical bytes that external root operators must sign.
func CanonicalizeRootDraft(data []byte, now time.Time) ([]byte, SigningManifest, error) {
	canonical, err := canonicalizeDraft(data, MaxRootMetadataBytes, "root metadata")
	if err != nil {
		return nil, SigningManifest{}, err
	}
	var metadata RootMetadata
	if err := decodeStrictJSON(canonical, &metadata, "root metadata"); err != nil {
		return nil, SigningManifest{}, err
	}
	verified, err := prepareRootPayload(metadata, canonical, now)
	if err != nil {
		return nil, SigningManifest{}, err
	}
	normalized := verified.Metadata
	normalized.Generated = verified.GeneratedAt.Format(time.RFC3339)
	normalized.Expires = verified.ExpiresAt.Format(time.RFC3339)
	canonical, verified, err = canonicalRootPayload(normalized, now)
	if err != nil {
		return nil, SigningManifest{}, err
	}
	return canonical, signingManifest(
		"root",
		verified.Metadata.Version,
		verified.Metadata.Generated,
		verified.Metadata.Expires,
		canonical,
		"root",
		verified.Metadata.Roles.Root,
	), nil
}

// CanonicalizeCatalogDraft validates an unsigned catalog draft against the
// currently trusted root and returns the exact bytes catalog operators sign.
func CanonicalizeCatalogDraft(root *VerifiedRoot, data []byte, now time.Time) ([]byte, SigningManifest, error) {
	if root == nil {
		return nil, SigningManifest{}, errors.New("trusted root is required")
	}
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	if !root.ExpiresAt.After(now) {
		return nil, SigningManifest{}, fmt.Errorf("trusted root version %d has expired", root.Metadata.Version)
	}
	canonical, err := canonicalizeDraft(data, MaxChannelCatalogBytes, "catalog metadata")
	if err != nil {
		return nil, SigningManifest{}, err
	}
	var metadata CatalogMetadata
	if err := decodeStrictJSON(canonical, &metadata, "catalog metadata"); err != nil {
		return nil, SigningManifest{}, err
	}
	verified, err := prepareCatalogPayload(metadata, canonical, now)
	if err != nil {
		return nil, SigningManifest{}, err
	}
	normalized := verified.Metadata
	normalized.Generated = verified.GeneratedAt.Format(time.RFC3339)
	normalized.Expires = verified.ExpiresAt.Format(time.RFC3339)
	for index := range normalized.Images {
		sort.Strings(normalized.Images[index].RedirectHosts)
	}
	canonical, verified, err = canonicalCatalogPayload(normalized, now)
	if err != nil {
		return nil, SigningManifest{}, err
	}
	return canonical, signingManifest(
		"catalog",
		verified.Metadata.Version,
		verified.Metadata.Generated,
		verified.Metadata.Expires,
		canonical,
		"catalog",
		root.Metadata.Roles.Catalog,
	), nil
}

// AssembleMetadataEnvelope combines a canonical payload with externally
// produced detached signatures. The returned envelope is deterministic.
func AssembleMetadataEnvelope(canonicalPayload []byte, detached []DetachedMetadataSignature) ([]byte, error) {
	if len(canonicalPayload) == 0 {
		return nil, errors.New("canonical payload is empty")
	}
	canonical, err := canonicalJSON(canonicalPayload)
	if err != nil {
		return nil, fmt.Errorf("canonicalize payload: %w", err)
	}
	if !bytes.Equal(bytes.TrimSpace(canonicalPayload), canonical) {
		return nil, errors.New("payload is not canonical JSON")
	}
	if len(detached) == 0 || len(detached) > maximumMetadataSignatures {
		return nil, errors.New("detached signature list is empty or too large")
	}
	signatures := make([]MetadataSignature, 0, len(detached))
	for index, item := range detached {
		keyID, err := normalizeKeyID(item.KeyID)
		if err != nil {
			return nil, fmt.Errorf("signature %d: %w", index+1, err)
		}
		signature, err := DecodeSignature(item.Signature)
		if err != nil {
			return nil, fmt.Errorf("signature %d from %s: %w", index+1, keyID, err)
		}
		signatures = append(signatures, MetadataSignature{
			KeyID: keyID,
			Sig:   base64.StdEncoding.EncodeToString(signature),
		})
	}
	sort.Slice(signatures, func(i, j int) bool { return signatures[i].KeyID < signatures[j].KeyID })
	if err := validateMetadataSignatures(signatures); err != nil {
		return nil, err
	}
	envelope := MetadataEnvelope{Signed: append(json.RawMessage(nil), canonical...), Signatures: signatures}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	return canonicalJSON(raw)
}

// VerifiedAdministrativeEnvelope summarizes a fully authorized envelope
// assembled by offline operators.
type VerifiedAdministrativeEnvelope struct {
	MetadataType string `json:"metadata_type"`
	Version      int    `json:"version"`
	SHA256       string `json:"sha256"`
}

// VerifyAdministrativeEnvelope applies stricter operator rules than the
// runtime parser: every supplied signature must belong to the role(s) needed
// for this exact metadata transition. Unknown extra signatures are refused.
func VerifyAdministrativeEnvelope(current *VerifiedRoot, data []byte, now time.Time) (VerifiedAdministrativeEnvelope, error) {
	envelope, canonical, err := parseMetadataEnvelope(data, MaxChannelCatalogBytes)
	if err != nil {
		return VerifiedAdministrativeEnvelope{}, err
	}
	var header struct {
		Type    string `json:"_type"`
		Version int    `json:"version"`
	}
	if err := decodeStrictHeader(canonical, &header); err != nil {
		return VerifiedAdministrativeEnvelope{}, err
	}
	switch header.Type {
	case "root":
		var verified *VerifiedRoot
		if header.Version == 1 {
			if current != nil {
				return VerifiedAdministrativeEnvelope{}, errors.New("bootstrap root assembly must not supply a previous root chain")
			}
			verified, err = VerifyBootstrapRoot(data, now)
		} else {
			if current == nil {
				return VerifiedAdministrativeEnvelope{}, errors.New("root rotation assembly requires the complete previous root chain")
			}
			verified, err = VerifyRootUpdate(current, data, now)
		}
		if err != nil {
			return VerifiedAdministrativeEnvelope{}, err
		}
		allowed := make(map[string]struct{})
		for _, keyID := range verified.Metadata.Roles.Root.KeyIDs {
			allowed[keyID] = struct{}{}
		}
		if current != nil {
			for _, keyID := range current.Metadata.Roles.Root.KeyIDs {
				allowed[keyID] = struct{}{}
			}
		}
		if err := rejectUnauthorizedAdministrativeSignatures(envelope.Signatures, allowed); err != nil {
			return VerifiedAdministrativeEnvelope{}, err
		}
		return VerifiedAdministrativeEnvelope{MetadataType: "root", Version: verified.Metadata.Version, SHA256: verified.SHA256}, nil
	case "catalog":
		if current == nil {
			return VerifiedAdministrativeEnvelope{}, errors.New("catalog assembly requires the complete trusted root chain")
		}
		verified, err := VerifyChannelCatalog(current, data, now)
		if err != nil {
			return VerifiedAdministrativeEnvelope{}, err
		}
		allowed := make(map[string]struct{}, len(current.Metadata.Roles.Catalog.KeyIDs))
		for _, keyID := range current.Metadata.Roles.Catalog.KeyIDs {
			allowed[keyID] = struct{}{}
		}
		if err := rejectUnauthorizedAdministrativeSignatures(envelope.Signatures, allowed); err != nil {
			return VerifiedAdministrativeEnvelope{}, err
		}
		return VerifiedAdministrativeEnvelope{MetadataType: "catalog", Version: verified.Metadata.Version, SHA256: verified.SHA256}, nil
	default:
		return VerifiedAdministrativeEnvelope{}, fmt.Errorf("unsupported signed metadata type %q", header.Type)
	}
}

func rejectUnauthorizedAdministrativeSignatures(signatures []MetadataSignature, allowed map[string]struct{}) error {
	for _, signature := range signatures {
		if _, ok := allowed[signature.KeyID]; !ok {
			return fmt.Errorf("signature from key %s is not authorized for this metadata transition", signature.KeyID)
		}
	}
	return nil
}

func decodeStrictHeader(data []byte, header any) error {
	var value map[string]json.RawMessage
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	selected := make(map[string]json.RawMessage, 2)
	for _, name := range []string{"_type", "version"} {
		raw, ok := value[name]
		if !ok {
			return fmt.Errorf("signed metadata is missing %s", name)
		}
		selected[name] = raw
	}
	raw, err := json.Marshal(selected)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, header)
}

// CanonicalizeSignedEnvelope validates the generic envelope structure and
// returns deterministic bytes. Callers still verify root or catalog semantics
// with the role-specific verification functions.
func CanonicalizeSignedEnvelope(data []byte) ([]byte, error) {
	if _, _, err := parseMetadataEnvelope(data, MaxChannelCatalogBytes); err != nil {
		return nil, err
	}
	return canonicalJSON(data)
}

// VerifyRootChain verifies a bootstrap root followed by every sequential root
// rotation in order and returns the final current root.
func VerifyRootChain(envelopes [][]byte, now time.Time) (*VerifiedRoot, error) {
	sequence, err := VerifyRootChainSequence(envelopes, now)
	if err != nil {
		return nil, err
	}
	return sequence[len(sequence)-1], nil
}

// VerifyRootChainSequence returns every verified root in publication order.
func VerifyRootChainSequence(envelopes [][]byte, now time.Time) ([]*VerifiedRoot, error) {
	if len(envelopes) == 0 {
		return nil, errors.New("root chain is empty")
	}
	root, err := VerifyBootstrapRoot(envelopes[0], now)
	if err != nil {
		return nil, fmt.Errorf("verify bootstrap root: %w", err)
	}
	sequence := []*VerifiedRoot{root}
	for index, data := range envelopes[1:] {
		root, err = VerifyRootUpdate(root, data, now)
		if err != nil {
			return nil, fmt.Errorf("verify root chain item %d: %w", index+2, err)
		}
		sequence = append(sequence, root)
	}
	if now.IsZero() {
		now = time.Now()
	}
	if !root.ExpiresAt.After(now.UTC()) {
		return nil, fmt.Errorf("final root version %d has expired", root.Metadata.Version)
	}
	return sequence, nil
}

// CanonicalizeChannelConfig validates a public enabled channel configuration
// and returns deterministic JSON. The bootstrap root itself is verified by the
// caller and remains a sibling file named by BootstrapRoot.
func CanonicalizeChannelConfig(config ChannelConfig) ([]byte, error) {
	validated, err := validateChannelConfig(config, false)
	if err != nil {
		return nil, err
	}
	if !validated.Enabled {
		return nil, errors.New("administration output must be an enabled channel configuration")
	}
	raw, err := json.Marshal(validated)
	if err != nil {
		return nil, err
	}
	return canonicalJSON(raw)
}

// CanonicalizeChannelConfigDraft strictly parses a public configuration draft,
// validates production URL restrictions, and returns deterministic bytes.
func CanonicalizeChannelConfigDraft(data []byte) (ChannelConfig, []byte, error) {
	canonical, err := canonicalizeDraft(data, MaxChannelConfigBytes, "channel configuration")
	if err != nil {
		return ChannelConfig{}, nil, err
	}
	var config ChannelConfig
	if err := decodeStrictJSON(canonical, &config, "channel configuration"); err != nil {
		return ChannelConfig{}, nil, err
	}
	validated, err := validateChannelConfig(config, false)
	if err != nil {
		return ChannelConfig{}, nil, err
	}
	if !validated.Enabled {
		return ChannelConfig{}, nil, errors.New("publication configuration must be enabled")
	}
	normalized, err := CanonicalizeChannelConfig(validated)
	if err != nil {
		return ChannelConfig{}, nil, err
	}
	return validated, normalized, nil
}

func canonicalRootPayload(metadata RootMetadata, now time.Time) ([]byte, *VerifiedRoot, error) {
	raw, err := json.Marshal(metadata)
	if err != nil {
		return nil, nil, err
	}
	canonical, err := canonicalJSON(raw)
	if err != nil {
		return nil, nil, err
	}
	verified, err := prepareRootPayload(metadata, canonical, now)
	if err != nil {
		return nil, nil, err
	}
	return canonical, verified, nil
}

func canonicalCatalogPayload(metadata CatalogMetadata, now time.Time) ([]byte, *VerifiedChannelCatalog, error) {
	raw, err := json.Marshal(metadata)
	if err != nil {
		return nil, nil, err
	}
	canonical, err := canonicalJSON(raw)
	if err != nil {
		return nil, nil, err
	}
	verified, err := prepareCatalogPayload(metadata, canonical, now)
	if err != nil {
		return nil, nil, err
	}
	return canonical, verified, nil
}

func canonicalizeDraft(data []byte, limit int, label string) ([]byte, error) {
	if len(data) == 0 || len(data) > limit {
		return nil, fmt.Errorf("%s size must be between 1 and %d bytes", label, limit)
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return nil, err
	}
	canonical, err := canonicalJSON(data)
	if err != nil {
		return nil, fmt.Errorf("canonicalize %s: %w", label, err)
	}
	return canonical, nil
}

func signingManifest(metadataType string, version int, generated, expires string, payload []byte, roleName string, role TrustRole) SigningManifest {
	digest := sha256.Sum256(payload)
	return SigningManifest{
		MetadataType:     metadataType,
		Version:          version,
		Generated:        generated,
		Expires:          expires,
		PayloadBytes:     len(payload),
		PayloadSHA256:    hex.EncodeToString(digest[:]),
		Role:             roleName,
		Threshold:        role.Threshold,
		AuthorizedKeyIDs: append([]string(nil), role.KeyIDs...),
	}
}

func normalizeKeyID(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) != sha256.Size*2 {
		return "", errors.New("key id must be a 64-character SHA-256 hexadecimal value")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", errors.New("key id must be hexadecimal")
	}
	return value, nil
}

// Compile-time assertion documents that administration only accepts public
// keys. No API in this file accepts ed25519.PrivateKey.
var _ ed25519.PublicKey
