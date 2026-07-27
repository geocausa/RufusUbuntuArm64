//go:build linux

package ffu

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"time"
)

const (
	trustActivationSchema  = 1
	trustActivationPurpose = "ffu-trust-bundle-activation"
)

// TrustActivationOptions exposes only a package-private deterministic test hook.
// Production callers cannot weaken or skip any activation prerequisite.
type TrustActivationOptions struct {
	hook func(stage string) error
}

// ActivatedTrustAnchor is an independently owned copy of one exact root DER
// certificate together with the normalized metadata authenticated by the plan.
type ActivatedTrustAnchor struct {
	Anchor         TrustAnchor `json:"anchor"`
	CertificateDER []byte      `json:"certificate_der"`
}

type trustBundleActivationCapability struct {
	activationSHA256 string
}

// TrustBundleActivation is a read-only capability derived from the currently
// active, descriptor-verified trust-store generation. It deliberately provides
// no certificate pool, chain builder, publisher decision, network operation,
// target binding, or executor.
type TrustBundleActivation struct {
	Schema                   int                        `json:"schema"`
	Purpose                  string                     `json:"purpose"`
	Root                     string                     `json:"root"`
	Generation               string                     `json:"generation"`
	Sequence                 uint64                     `json:"sequence"`
	BundleSHA256             string                     `json:"bundle_sha256"`
	PublicationPlanSHA256    string                     `json:"publication_plan_sha256"`
	PreActivationPlanSHA256  string                     `json:"pre_activation_plan_sha256"`
	ActivatedPlanSHA256      string                     `json:"activated_plan_sha256"`
	ActivationEvaluationTime string                     `json:"activation_evaluation_time"`
	RootCount                int                        `json:"root_count"`
	DistrustedCount          int                        `json:"distrusted_count"`
	Roots                    []ActivatedTrustAnchor     `json:"roots"`
	DistrustedSHA256         []string                   `json:"distrusted_sha256"`
	Authentication           *TrustBundleAuthentication `json:"authentication"`
	Plan                     TrustBundlePlan            `json:"plan"`
	ActivationSHA256         string                     `json:"activation_sha256"`
	capability               *trustBundleActivationCapability
}

// ActivateAuthenticatedTrustBundle crosses only the trust-anchor activation
// boundary. It revalidates the exact durable active generation under open
// descriptors, copies its root DER material, and returns an activated plan.
// The active record, immutable generation, rollback state, and host trust store
// are not rewritten or consulted.
func ActivateAuthenticatedTrustBundle(ctx context.Context, root string, policy TrustMetadataPolicy, evaluationTime time.Time, opts TrustActivationOptions) (TrustBundleActivation, error) {
	if ctx == nil {
		return TrustBundleActivation{}, errors.New("FFU trust activation context is nil")
	}
	if err := trustStoreContext(ctx); err != nil {
		return TrustBundleActivation{}, err
	}
	if evaluationTime.IsZero() {
		return TrustBundleActivation{}, errors.New("FFU trust activation evaluation time is zero")
	}

	resolved, rootFile, rootIdentity, err := openTrustStoreRoot(root)
	if err != nil {
		return TrustBundleActivation{}, err
	}
	defer rootFile.Close()
	generations, err := openTrustStoreDirectory(rootFile, trustStoreGenerationsName)
	if err != nil {
		return TrustBundleActivation{}, err
	}
	defer generations.Close()
	generationsIdentity, err := trustStoreIdentityFromOpenFile(generations)
	if err != nil {
		return TrustBundleActivation{}, err
	}
	if err := validateTrustStoreNames(rootFile, generations); err != nil {
		return TrustBundleActivation{}, err
	}

	active, plan, err := readCurrentTrustStoreState(ctx, rootFile, generations, policy, evaluationTime)
	if err != nil {
		return TrustBundleActivation{}, err
	}
	if !active.exists {
		return TrustBundleActivation{}, os.ErrNotExist
	}
	if err := requireInactiveAuthenticatedTrustPlan(plan); err != nil {
		return TrustBundleActivation{}, fmt.Errorf("activate FFU trust bundle: %w", err)
	}
	// Recovery may remove only known private temporary names. It never rewrites
	// the active record, a published generation, or rollback evidence.
	if err := cleanTrustStoreTemporaries(rootFile, generations); err != nil {
		return TrustBundleActivation{}, err
	}
	if err := validateTrustStoreNames(rootFile, generations); err != nil {
		return TrustBundleActivation{}, err
	}
	if err := trustActivationStage(ctx, opts, "recovered"); err != nil {
		return TrustBundleActivation{}, err
	}

	roots, distrusted, err := loadActivatedTrustMaterial(ctx, generations, active.record, plan)
	if err != nil {
		return TrustBundleActivation{}, err
	}
	if err := trustActivationStage(ctx, opts, "material-loaded"); err != nil {
		return TrustBundleActivation{}, err
	}

	preActivationPlanSHA256 := plan.PlanSHA256
	plan.TrustAnchorsActivated = true
	plan.HostTLSStoreConsulted = false
	plan.CertificateChainBuilt = false
	plan.PublisherTrusted = false
	plan.Limitations = []string{
		"the exact durably published bundle is threshold-authenticated and its explicit roots are activated for a later Authenticode policy gate",
		"activation does not create a certificate pool or build, select, or validate any certificate chain",
		"the host TLS certificate store is never treated as an Authenticode policy source",
		"publisher trust, revocation, timestamp, target binding, network retrieval, and execution remain separate and incomplete",
	}
	plan.PlanSHA256 = trustBundlePlanDigest(plan)
	if err := requireActivatedTrustPlan(plan); err != nil {
		return TrustBundleActivation{}, err
	}

	activation := TrustBundleActivation{
		Schema:                   trustActivationSchema,
		Purpose:                  trustActivationPurpose,
		Root:                     resolved,
		Generation:               active.record.Generation,
		Sequence:                 active.record.Sequence,
		BundleSHA256:             active.record.BundleSHA256,
		PublicationPlanSHA256:    active.record.PlanSHA256,
		PreActivationPlanSHA256:  preActivationPlanSHA256,
		ActivatedPlanSHA256:      plan.PlanSHA256,
		ActivationEvaluationTime: evaluationTime.UTC().Format(time.RFC3339),
		RootCount:                len(roots),
		DistrustedCount:          len(distrusted),
		Roots:                    roots,
		DistrustedSHA256:         append([]string(nil), distrusted...),
		Authentication:           cloneTrustBundleAuthentication(plan.Authentication),
		Plan:                     plan,
	}
	activation.ActivationSHA256 = trustBundleActivationDigest(activation)
	if err := trustActivationStage(ctx, opts, "activation-planned"); err != nil {
		return TrustBundleActivation{}, err
	}

	if err := ensureTrustStoreDirectoryEntryIdentity(rootFile, trustStoreGenerationsName, generationsIdentity); err != nil {
		return TrustBundleActivation{}, err
	}
	if err := ensureTrustStoreRootIdentity(resolved, rootFile, rootIdentity); err != nil {
		return TrustBundleActivation{}, err
	}
	if err := verifyTrustStoreActiveSnapshot(rootFile, active); err != nil {
		return TrustBundleActivation{}, err
	}
	if err := trustActivationStage(ctx, opts, "verified"); err != nil {
		return TrustBundleActivation{}, err
	}
	activation.capability = &trustBundleActivationCapability{activationSHA256: activation.ActivationSHA256}
	return activation, nil
}

func loadActivatedTrustMaterial(ctx context.Context, generations *os.File, active TrustStoreActiveRecord, plan TrustBundlePlan) ([]ActivatedTrustAnchor, []string, error) {
	if err := trustStoreContext(ctx); err != nil {
		return nil, nil, err
	}
	generation, err := openTrustStoreDirectory(generations, active.Generation)
	if err != nil {
		return nil, nil, err
	}
	defer generation.Close()
	generationIdentity, err := trustStoreIdentityFromOpenFile(generation)
	if err != nil {
		return nil, nil, err
	}
	if os.FileMode(generationIdentity.mode).Perm() != 0o500 {
		return nil, nil, errors.New("FFU trust activation requires a sealed 0500 generation")
	}
	if err := validateTrustStoreGenerationEntries(generation); err != nil {
		return nil, nil, err
	}
	bundleData, bundleIdentity, err := readTrustStoreRegular(generation, trustStoreBundleName, int(maxFFUTrustBundleBytes), 0o400)
	if err != nil {
		return nil, nil, err
	}
	bundleDigest := sha256.Sum256(bundleData)
	bundleSHA256 := hex.EncodeToString(bundleDigest[:])
	if bundleSHA256 != active.BundleSHA256 || bundleSHA256 != plan.BundleSHA256 {
		return nil, nil, errors.New("FFU trust activation bundle digest does not match durable state")
	}
	roots, distrusted, err := decodeActivatedTrustMaterial(bundleData, plan)
	if err != nil {
		return nil, nil, err
	}
	if err := verifyTrustStoreRegularSnapshot(generation, trustStoreBundleName, bundleIdentity, int(maxFFUTrustBundleBytes), 0o400); err != nil {
		return nil, nil, err
	}
	if err := ensureTrustStoreDirectoryEntryIdentity(generations, active.Generation, generationIdentity); err != nil {
		return nil, nil, err
	}
	return roots, distrusted, nil
}

func decodeActivatedTrustMaterial(bundleData []byte, plan TrustBundlePlan) ([]ActivatedTrustAnchor, []string, error) {
	if err := rejectDuplicateTrustMetadataJSONMembers(bundleData); err != nil {
		return nil, nil, fmt.Errorf("validate FFU activation bundle JSON members: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(bundleData))
	decoder.DisallowUnknownFields()
	var document TrustBundleDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, nil, fmt.Errorf("decode FFU activation bundle: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, nil, errors.New("FFU activation bundle contains multiple JSON values")
	}
	if document.Schema != plan.Schema || document.Purpose != plan.Purpose || document.Sequence != plan.Sequence {
		return nil, nil, errors.New("FFU activation bundle identity does not match the authenticated plan")
	}
	if len(document.Roots) != len(plan.Roots) || len(document.DistrustedSHA256) != len(plan.DistrustedSHA256) {
		return nil, nil, errors.New("FFU activation bundle counts do not match the authenticated plan")
	}

	material := make(map[string]ActivatedTrustAnchor, len(document.Roots))
	for index, rootDocument := range document.Roots {
		anchor, err := parseTrustAnchor(rootDocument, index)
		if err != nil {
			return nil, nil, err
		}
		der, err := decodeCanonicalActivatedRootDER(rootDocument.CertificateDERBase64, anchor.ID)
		if err != nil {
			return nil, nil, err
		}
		key := anchor.ID + "\x00" + anchor.CertificateSHA256
		if _, exists := material[key]; exists {
			return nil, nil, errors.New("FFU activation bundle repeats root material")
		}
		material[key] = ActivatedTrustAnchor{Anchor: anchor, CertificateDER: der}
	}
	roots := make([]ActivatedTrustAnchor, 0, len(plan.Roots))
	for _, planned := range plan.Roots {
		key := planned.ID + "\x00" + planned.CertificateSHA256
		current, ok := material[key]
		if !ok || current.Anchor != planned {
			return nil, nil, fmt.Errorf("FFU activation root %q does not match the authenticated plan", planned.ID)
		}
		roots = append(roots, current)
		delete(material, key)
	}
	if len(material) != 0 {
		return nil, nil, errors.New("FFU activation bundle contains unplanned root material")
	}

	distrusted := make([]string, 0, len(document.DistrustedSHA256))
	for index, value := range document.DistrustedSHA256 {
		fingerprint, err := canonicalSHA256Fingerprint(value, fmt.Sprintf("activation.distrusted_sha256[%d]", index))
		if err != nil {
			return nil, nil, err
		}
		distrusted = append(distrusted, fingerprint)
	}
	sort.Strings(distrusted)
	if !equalTrustStoreStrings(distrusted, plan.DistrustedSHA256) {
		return nil, nil, errors.New("FFU activation distrust policy does not match the authenticated plan")
	}
	return roots, distrusted, nil
}

func decodeCanonicalActivatedRootDER(value, id string) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) == 0 || len(decoded) > maxFFUTrustCertificateDER {
		return nil, fmt.Errorf("decode FFU activation root %q DER", id)
	}
	if base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("FFU activation root %q DER must use canonical padded base64", id)
	}
	return append([]byte(nil), decoded...), nil
}

func requireActivatedTrustPlan(plan TrustBundlePlan) error {
	if !plan.BundleStructureValidated || !plan.BundleSignatureAuthenticated || plan.Authentication == nil || !plan.TrustAnchorsActivated {
		return errors.New("FFU trust activation did not satisfy the authenticated activation contract")
	}
	if plan.HostTLSStoreConsulted || plan.CertificateChainBuilt || plan.PublisherTrusted {
		return errors.New("FFU trust activation crossed a later Authenticode policy boundary")
	}
	return nil
}

func cloneTrustBundleAuthentication(authentication *TrustBundleAuthentication) *TrustBundleAuthentication {
	if authentication == nil {
		return nil
	}
	clone := *authentication
	clone.SigningKeyIDs = append([]string(nil), authentication.SigningKeyIDs...)
	return &clone
}

func trustActivationStage(ctx context.Context, opts TrustActivationOptions, stage string) error {
	if err := trustStoreContext(ctx); err != nil {
		return err
	}
	if opts.hook != nil {
		if err := opts.hook(stage); err != nil {
			return fmt.Errorf("injected FFU trust activation failure at %s: %w", stage, err)
		}
	}
	return trustStoreContext(ctx)
}

func trustBundleActivationDigest(activation TrustBundleActivation) string {
	digest := sha256.New()
	writeTrustUint64(digest, uint64(activation.Schema))
	writeTrustString(digest, activation.Purpose)
	writeTrustString(digest, activation.Generation)
	writeTrustUint64(digest, activation.Sequence)
	writeTrustString(digest, activation.BundleSHA256)
	writeTrustString(digest, activation.PublicationPlanSHA256)
	writeTrustString(digest, activation.PreActivationPlanSHA256)
	writeTrustString(digest, activation.ActivatedPlanSHA256)
	writeTrustString(digest, activation.ActivationEvaluationTime)
	writeTrustUint64(digest, uint64(len(activation.Roots)))
	for _, root := range activation.Roots {
		writeTrustString(digest, root.Anchor.ID)
		writeTrustString(digest, root.Anchor.CertificateSHA256)
		writeTrustUint64(digest, uint64(len(root.CertificateDER)))
		_, _ = digest.Write(root.CertificateDER)
	}
	writeTrustUint64(digest, uint64(len(activation.DistrustedSHA256)))
	for _, fingerprint := range activation.DistrustedSHA256 {
		writeTrustString(digest, fingerprint)
	}
	if activation.Authentication == nil {
		writeTrustBool(digest, false)
	} else {
		writeTrustBool(digest, true)
		writeTrustString(digest, activation.Authentication.MetadataSHA256)
		writeTrustString(digest, activation.Authentication.KeySetSHA256)
		writeTrustUint64(digest, activation.Authentication.KeySetVersion)
		writeTrustUint64(digest, uint64(activation.Authentication.Threshold))
		for _, keyID := range activation.Authentication.SigningKeyIDs {
			writeTrustString(digest, keyID)
		}
	}
	return hex.EncodeToString(digest.Sum(nil))
}
