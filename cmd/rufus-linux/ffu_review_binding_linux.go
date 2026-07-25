//go:build linux

package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/geocausa/RufusArm64/internal/ffu"
	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

const (
	ffuCLIReviewBindingSchema  = 1
	ffuCLIReviewBindingPurpose = "ffu-cli-reviewed-input-binding"
)

// ffuCLIReviewBinding contains only stable facts that must survive the gap
// between a read-only review and a later privileged restore. Evaluation-time
// dependent plan digests are deliberately excluded.
type ffuCLIReviewBinding struct {
	Schema                      int                 `json:"schema"`
	Purpose                     string              `json:"purpose"`
	SourcePath                  string              `json:"source_path"`
	SourceIdentity              sourcefile.Identity `json:"source_identity"`
	SourceFileSize              uint64              `json:"source_file_size"`
	DescriptorPlanSHA256        string              `json:"descriptor_plan_sha256"`
	CatalogSHA256               string              `json:"catalog_sha256"`
	HashTableSHA256             string              `json:"hash_table_sha256"`
	TrustStoreRoot              string              `json:"trust_store_root"`
	TrustGeneration             string              `json:"trust_generation"`
	TrustSequence               uint64              `json:"trust_sequence"`
	TrustBundleSHA256           string              `json:"trust_bundle_sha256"`
	TrustMetadataPolicyPath     string              `json:"trust_metadata_policy_path"`
	TrustMetadataPolicyIdentity sourcefile.Identity `json:"trust_metadata_policy_identity"`
	PublisherPolicyPath         string              `json:"publisher_policy_path"`
	PublisherPolicyIdentity     sourcefile.Identity `json:"publisher_policy_identity"`
	DevicePath                  string              `json:"device_path"`
	ExpectedTargetIdentity      string              `json:"expected_target_identity"`
	TargetSizeBytes             uint64              `json:"target_size_bytes"`
	LogicalSectorSizeBytes      uint64              `json:"logical_sector_size_bytes"`
	PhysicalSectorSizeBytes     uint64              `json:"physical_sector_size_bytes"`
	KernelDeviceID              uint64              `json:"kernel_device_id"`
	MajorMinor                  string              `json:"major_minor"`
	ExactConfirmationPhrase     string              `json:"exact_confirmation_phrase"`
}

func buildFFUCLIReviewBinding(
	sourcePath string,
	sourceIdentity sourcefile.Identity,
	descriptor ffu.DescriptorPlan,
	target ffu.RestoreTargetPlan,
	preflight ffu.FullFlashTargetPreflightPlan,
	activation ffu.TrustBundleActivation,
	metadataPolicyPath string,
	metadataPolicyIdentity sourcefile.Identity,
	publisherPolicyPath string,
	publisherPolicyIdentity sourcefile.Identity,
	phrase string,
) (ffuCLIReviewBinding, string, error) {
	binding := ffuCLIReviewBinding{
		Schema:                      ffuCLIReviewBindingSchema,
		Purpose:                     ffuCLIReviewBindingPurpose,
		SourcePath:                  sourcePath,
		SourceIdentity:              sourceIdentity,
		SourceFileSize:              uint64(sourceIdentity.Size),
		DescriptorPlanSHA256:        descriptor.PlanSHA256,
		CatalogSHA256:               target.CatalogSHA256,
		HashTableSHA256:             target.HashTableSHA256,
		TrustStoreRoot:              activation.Root,
		TrustGeneration:             activation.Generation,
		TrustSequence:               activation.Sequence,
		TrustBundleSHA256:           activation.BundleSHA256,
		TrustMetadataPolicyPath:     metadataPolicyPath,
		TrustMetadataPolicyIdentity: metadataPolicyIdentity,
		PublisherPolicyPath:         publisherPolicyPath,
		PublisherPolicyIdentity:     publisherPolicyIdentity,
		DevicePath:                  target.DevicePath,
		ExpectedTargetIdentity:      target.ExpectedTargetIdentity,
		TargetSizeBytes:             target.TargetSizeBytes,
		LogicalSectorSizeBytes:      target.LogicalSectorSizeBytes,
		PhysicalSectorSizeBytes:     target.PhysicalSectorSizeBytes,
		KernelDeviceID:              preflight.KernelDeviceID,
		MajorMinor:                  preflight.MajorMinor,
		ExactConfirmationPhrase:     phrase,
	}
	if err := validateFFUCLIReviewBinding(binding); err != nil {
		return ffuCLIReviewBinding{}, "", err
	}
	data, err := json.Marshal(binding)
	if err != nil {
		return ffuCLIReviewBinding{}, "", fmt.Errorf("encode FFU reviewed-input binding: %w", err)
	}
	digest := sha256.Sum256(data)
	return binding, hex.EncodeToString(digest[:]), nil
}

func validateFFUCLIReviewBinding(binding ffuCLIReviewBinding) error {
	if binding.Schema != ffuCLIReviewBindingSchema || binding.Purpose != ffuCLIReviewBindingPurpose {
		return errors.New("invalid FFU reviewed-input binding envelope")
	}
	for label, path := range map[string]string{
		"source":               binding.SourcePath,
		"trust store":          binding.TrustStoreRoot,
		"trust metadata policy": binding.TrustMetadataPolicyPath,
		"publisher policy":      binding.PublisherPolicyPath,
	} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("FFU reviewed-input %s path is not canonical and absolute", label)
		}
	}
	if !filepath.IsAbs(binding.DevicePath) || filepath.Clean(binding.DevicePath) != binding.DevicePath || !strings.HasPrefix(binding.DevicePath, "/dev/") {
		return errors.New("FFU reviewed-input target path is not canonical beneath /dev")
	}
	for label, identity := range map[string]sourcefile.Identity{
		"source":                binding.SourceIdentity,
		"trust metadata policy": binding.TrustMetadataPolicyIdentity,
		"publisher policy":      binding.PublisherPolicyIdentity,
	} {
		if identity.Device == 0 || identity.Inode == 0 || identity.Size <= 0 || identity.ModifiedNS < 0 || identity.ChangedNS < 0 {
			return fmt.Errorf("FFU reviewed-input %s identity is invalid", label)
		}
	}
	if binding.SourceFileSize == 0 || binding.SourceFileSize != uint64(binding.SourceIdentity.Size) {
		return errors.New("FFU reviewed-input source size is inconsistent")
	}
	for label, value := range map[string]string{
		"descriptor plan": binding.DescriptorPlanSHA256,
		"catalog":         binding.CatalogSHA256,
		"hash table":      binding.HashTableSHA256,
		"trust bundle":    binding.TrustBundleSHA256,
		"target identity": binding.ExpectedTargetIdentity,
	} {
		if !isCanonicalFFUCLISHA256(value) {
			return fmt.Errorf("FFU reviewed-input %s SHA-256 is invalid", label)
		}
	}
	if strings.TrimSpace(binding.TrustGeneration) == "" || binding.TrustSequence == 0 {
		return errors.New("FFU reviewed-input trust generation is incomplete")
	}
	if binding.TargetSizeBytes == 0 || binding.LogicalSectorSizeBytes == 0 || binding.PhysicalSectorSizeBytes == 0 || binding.PhysicalSectorSizeBytes < binding.LogicalSectorSizeBytes || binding.PhysicalSectorSizeBytes%binding.LogicalSectorSizeBytes != 0 {
		return errors.New("FFU reviewed-input target geometry is invalid")
	}
	if binding.KernelDeviceID == 0 || strings.TrimSpace(binding.MajorMinor) == "" {
		return errors.New("FFU reviewed-input kernel target identity is incomplete")
	}
	expectedPhrase := fmt.Sprintf("RESTORE AUTHENTICATED FFU TO %s SIZE %d BYTES", binding.DevicePath, binding.TargetSizeBytes)
	if binding.ExactConfirmationPhrase != expectedPhrase {
		return errors.New("FFU reviewed-input confirmation phrase is inconsistent")
	}
	return nil
}

func isCanonicalFFUCLISHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func requireExpectedFFUCLIReviewBinding(expected, actual string) error {
	if !isCanonicalFFUCLISHA256(expected) {
		return errors.New("--expected-review-binding must be one lowercase SHA-256")
	}
	if !isCanonicalFFUCLISHA256(actual) {
		return errors.New("the reproduced FFU review binding is invalid")
	}
	expectedBytes, _ := hex.DecodeString(expected)
	actualBytes, _ := hex.DecodeString(actual)
	if subtle.ConstantTimeCompare(expectedBytes, actualBytes) != 1 {
		return errors.New("the FFU source, trust policy, or target changed after review; review it again")
	}
	return nil
}
