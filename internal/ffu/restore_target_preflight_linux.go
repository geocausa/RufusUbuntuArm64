//go:build linux

package ffu

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/geocausa/RufusArm64/internal/device"
	"github.com/geocausa/RufusArm64/internal/safety"
)

const (
	fullFlashTargetPreflightSchema = 1
	ffuSysClassBlockRoot           = "/sys/class/block"
	maxFFUSysfsGeometryBytes       = 64
)

// FullFlashTargetMount records one currently mounted target component. Only
// conventional desktop removable-media mount roots survive target policy and
// therefore appear here for a later guarded unmount transaction.
type FullFlashTargetMount struct {
	DevicePath string `json:"device_path"`
	Mountpoint string `json:"mountpoint"`
}

// FullFlashTargetPreflightPlan binds an authenticated full-flash plan to one
// freshly rediscovered normal removable whole disk. It is read-only evidence,
// not an authorization to open the target for writing.
type FullFlashTargetPreflightPlan struct {
	Schema                         int                    `json:"schema"`
	Mode                           string                 `json:"mode"`
	Destructive                    bool                   `json:"destructive"`
	FullFlashValidationPlanSHA256  string                 `json:"full_flash_validation_plan_sha256"`
	RestoreTargetPlanSHA256        string                 `json:"restore_target_plan_sha256"`
	AuthenticatedIntegritySHA256   string                 `json:"authenticated_integrity_sha256"`
	DevicePath                     string                 `json:"device_path"`
	ExpectedTargetIdentity         string                 `json:"expected_target_identity"`
	RediscoveredTargetIdentity     string                 `json:"rediscovered_target_identity"`
	TargetSizeBytes                uint64                 `json:"target_size_bytes"`
	LogicalSectorSizeBytes         uint64                 `json:"logical_sector_size_bytes"`
	PhysicalSectorSizeBytes        uint64                 `json:"physical_sector_size_bytes"`
	StoreBlockSizeBytes            uint64                 `json:"store_block_size_bytes"`
	KernelDeviceID                 uint64                 `json:"kernel_device_id"`
	MajorMinor                     string                 `json:"major_minor"`
	Vendor                         string                 `json:"vendor,omitempty"`
	Model                          string                 `json:"model,omitempty"`
	Transport                      string                 `json:"transport,omitempty"`
	Removable                      bool                   `json:"removable"`
	Hotplug                        bool                   `json:"hotplug"`
	MutationBytes                  uint64                 `json:"mutation_bytes"`
	MountedTargets                 []FullFlashTargetMount `json:"mounted_targets"`
	UnmountRequired                bool                   `json:"unmount_required"`
	TargetDiscoveryCompleted       bool                   `json:"target_discovery_completed"`
	WholeDiskConfirmed             bool                   `json:"whole_disk_confirmed"`
	NormalRemovableTargetConfirmed bool                   `json:"normal_removable_target_confirmed"`
	RunningSystemDiskExcluded      bool                   `json:"running_system_disk_excluded"`
	ProtectedMountsExcluded        bool                   `json:"protected_mounts_excluded"`
	TargetIdentityRevalidated      bool                   `json:"target_identity_revalidated"`
	TargetCapacityRevalidated      bool                   `json:"target_capacity_revalidated"`
	TargetGeometryRevalidated      bool                   `json:"target_geometry_revalidated"`
	FixedDiskOverrideAllowed       bool                   `json:"fixed_disk_override_allowed"`
	PrivilegedOpenRequired         bool                   `json:"privileged_open_required"`
	ExecutionSupported             bool                   `json:"execution_supported"`
	PlanSHA256                     string                 `json:"plan_sha256"`
	Warnings                       []string               `json:"warnings"`
	Limitations                    []string               `json:"limitations"`
}

// PreflightAuthenticatedSingleStoreV1FullFlashTarget re-runs the complete
// authenticated full-flash and target-plan chain, then performs current Linux
// target discovery and policy checks without opening the target. A future
// privileged provider must repeat these checks against a held descriptor.
func PreflightAuthenticatedSingleStoreV1FullFlashTarget(
	ctx context.Context,
	reader io.ReaderAt,
	sourceSize uint64,
	activation TrustBundleActivation,
	evaluationTime time.Time,
	sourcePolicy CatalogPublisherPolicy,
	request RestoreTargetRequest,
) (FullFlashValidationPlan, FullFlashTargetPreflightPlan, error) {
	if ctx == nil {
		return FullFlashValidationPlan{}, FullFlashTargetPreflightPlan{}, errors.New("FFU target preflight context is nil")
	}
	if err := ctx.Err(); err != nil {
		return FullFlashValidationPlan{}, FullFlashTargetPreflightPlan{}, err
	}
	_, validation, err := ResolveAuthenticatedSingleStoreV1FullFlash(
		ctx, reader, sourceSize, activation, evaluationTime, sourcePolicy, request,
	)
	if err != nil {
		return validation, FullFlashTargetPreflightPlan{}, err
	}
	preflight, err := DiscoverFullFlashTargetPreflight(ctx, validation)
	return validation, preflight, err
}

// DiscoverFullFlashTargetPreflight validates one existing full-flash plan
// against the current Linux device snapshot. It performs lsblk/findmnt/sysfs
// reads and block-device stat only; it never opens the target.
func DiscoverFullFlashTargetPreflight(ctx context.Context, validation FullFlashValidationPlan) (FullFlashTargetPreflightPlan, error) {
	if ctx == nil {
		return FullFlashTargetPreflightPlan{}, errors.New("FFU target discovery context is nil")
	}
	if err := ctx.Err(); err != nil {
		return FullFlashTargetPreflightPlan{}, err
	}
	if err := validateFullFlashValidationPlan(validation); err != nil {
		return FullFlashTargetPreflightPlan{}, fmt.Errorf("validate FFU full-flash prerequisite: %w", err)
	}

	resolved, err := safety.ResolveDevice(validation.DevicePath)
	if err != nil {
		return FullFlashTargetPreflightPlan{}, err
	}
	if resolved != validation.DevicePath {
		return FullFlashTargetPreflightPlan{}, fmt.Errorf("FFU target path resolved from %s to %s after review", validation.DevicePath, resolved)
	}
	dev, err := device.Find(resolved)
	if err != nil {
		return FullFlashTargetPreflightPlan{}, err
	}
	if err := safety.ValidateExpectedIdentity(dev, validation.ExpectedTargetIdentity); err != nil {
		return FullFlashTargetPreflightPlan{}, err
	}
	// No fixed-disk override exists for the initial FFU path.
	if err := safety.ValidateTarget(resolved, dev, false); err != nil {
		return FullFlashTargetPreflightPlan{}, err
	}
	if err := ctx.Err(); err != nil {
		return FullFlashTargetPreflightPlan{}, err
	}
	kernelID, err := safety.KernelDeviceID(resolved)
	if err != nil {
		return FullFlashTargetPreflightPlan{}, err
	}
	logical, physical, err := readFFUTargetSectorGeometryAt(ffuSysClassBlockRoot, dev.Name)
	if err != nil {
		return FullFlashTargetPreflightPlan{}, err
	}
	return buildFullFlashTargetPreflight(validation, dev, kernelID, logical, physical, true)
}

func buildFullFlashTargetPreflight(
	validation FullFlashValidationPlan,
	dev device.BlockDevice,
	kernelID uint64,
	logicalSector uint64,
	physicalSector uint64,
	runningSystemDiskExcluded bool,
) (FullFlashTargetPreflightPlan, error) {
	if err := validateFullFlashValidationPlan(validation); err != nil {
		return FullFlashTargetPreflightPlan{}, err
	}
	if !runningSystemDiskExcluded {
		return FullFlashTargetPreflightPlan{}, errors.New("FFU target preflight has not excluded the running system disk")
	}
	if err := safety.ValidateTargetMetadata(validation.DevicePath, dev, false); err != nil {
		return FullFlashTargetPreflightPlan{}, err
	}
	if dev.Size != validation.TargetSizeBytes {
		return FullFlashTargetPreflightPlan{}, fmt.Errorf("FFU target capacity changed from %d to %d bytes", validation.TargetSizeBytes, dev.Size)
	}
	actualIdentity := device.IdentityToken(dev)
	if validation.ExpectedTargetIdentity != actualIdentity {
		return FullFlashTargetPreflightPlan{}, errors.New("FFU target identity differs from the authenticated restore plan")
	}
	if logicalSector != validation.LogicalSectorSizeBytes || physicalSector != validation.PhysicalSectorSizeBytes {
		return FullFlashTargetPreflightPlan{}, fmt.Errorf("FFU target sector geometry changed from %d/%d to %d/%d bytes", validation.LogicalSectorSizeBytes, validation.PhysicalSectorSizeBytes, logicalSector, physicalSector)
	}
	if !validFFUTargetSectorSize(logicalSector) || !validFFUTargetSectorSize(physicalSector) || physicalSector < logicalSector || physicalSector%logicalSector != 0 {
		return FullFlashTargetPreflightPlan{}, errors.New("rediscovered FFU target sector geometry is invalid")
	}
	if validation.StoreBlockSizeBytes%logicalSector != 0 || validation.StoreBlockSizeBytes%physicalSector != 0 {
		return FullFlashTargetPreflightPlan{}, errors.New("rediscovered FFU target sector geometry is incompatible with the store block size")
	}
	if kernelID == 0 {
		return FullFlashTargetPreflightPlan{}, errors.New("FFU target kernel device identity is zero")
	}
	if strings.TrimSpace(dev.MajorMinor) == "" {
		return FullFlashTargetPreflightPlan{}, errors.New("FFU target is missing a kernel major:minor identity")
	}

	mounts, err := collectFullFlashTargetMounts(dev)
	if err != nil {
		return FullFlashTargetPreflightPlan{}, err
	}
	plan := FullFlashTargetPreflightPlan{
		Schema:                         fullFlashTargetPreflightSchema,
		Mode:                           "ffu-full-flash-target-preflight",
		Destructive:                    true,
		FullFlashValidationPlanSHA256:  validation.PlanSHA256,
		RestoreTargetPlanSHA256:        validation.RestoreTargetPlanSHA256,
		AuthenticatedIntegritySHA256:   validation.AuthenticatedIntegrityPlanSHA256,
		DevicePath:                     validation.DevicePath,
		ExpectedTargetIdentity:         validation.ExpectedTargetIdentity,
		RediscoveredTargetIdentity:     actualIdentity,
		TargetSizeBytes:                dev.Size,
		LogicalSectorSizeBytes:         logicalSector,
		PhysicalSectorSizeBytes:        physicalSector,
		StoreBlockSizeBytes:            validation.StoreBlockSizeBytes,
		KernelDeviceID:                 kernelID,
		MajorMinor:                     dev.MajorMinor,
		Vendor:                         dev.Vendor,
		Model:                          dev.Model,
		Transport:                      dev.Transport,
		Removable:                      dev.Removable,
		Hotplug:                        dev.Hotplug,
		MutationBytes:                  validation.MutationBytes,
		MountedTargets:                 mounts,
		UnmountRequired:                len(mounts) != 0,
		TargetDiscoveryCompleted:       true,
		WholeDiskConfirmed:             true,
		NormalRemovableTargetConfirmed: true,
		RunningSystemDiskExcluded:      true,
		ProtectedMountsExcluded:        true,
		TargetIdentityRevalidated:      true,
		TargetCapacityRevalidated:      true,
		TargetGeometryRevalidated:      true,
		FixedDiskOverrideAllowed:       false,
		PrivilegedOpenRequired:         true,
		ExecutionSupported:             false,
		Warnings:                       fullFlashTargetPreflightWarnings(),
		Limitations:                    fullFlashTargetPreflightLimitations(),
	}
	plan.PlanSHA256 = fullFlashTargetPreflightDigest(plan)
	if err := validateFullFlashTargetPreflightPlan(plan); err != nil {
		return FullFlashTargetPreflightPlan{}, err
	}
	return plan, nil
}

func readFFUTargetSectorGeometryAt(root, deviceName string) (uint64, uint64, error) {
	name := strings.TrimSpace(deviceName)
	if name == "" || filepath.Base(name) != name || name == "." || name == string(filepath.Separator) {
		return 0, 0, fmt.Errorf("invalid FFU target kernel name %q", deviceName)
	}
	readValue := func(filename string) (uint64, error) {
		path := filepath.Join(root, name, "queue", filename)
		data, err := os.ReadFile(path)
		if err != nil {
			return 0, fmt.Errorf("read FFU target %s: %w", filename, err)
		}
		if len(data) == 0 || len(data) > maxFFUSysfsGeometryBytes {
			return 0, fmt.Errorf("FFU target %s has an invalid sysfs value length", filename)
		}
		value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse FFU target %s: %w", filename, err)
		}
		return value, nil
	}
	logical, err := readValue("logical_block_size")
	if err != nil {
		return 0, 0, err
	}
	physical, err := readValue("physical_block_size")
	if err != nil {
		return 0, 0, err
	}
	return logical, physical, nil
}

func collectFullFlashTargetMounts(dev device.BlockDevice) ([]FullFlashTargetMount, error) {
	mounts := make([]FullFlashTargetMount, 0)
	seen := make(map[string]struct{})
	for _, node := range device.Flatten(dev) {
		for _, raw := range node.Mountpoints {
			mountpoint := filepath.Clean(strings.TrimSpace(raw))
			if mountpoint == "." || !eligibleFFURemovableMountpoint(mountpoint) {
				return nil, fmt.Errorf("FFU target component %s has an unsafe mountpoint %q", node.Path, raw)
			}
			key := node.Path + "\x00" + mountpoint
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			mounts = append(mounts, FullFlashTargetMount{DevicePath: node.Path, Mountpoint: mountpoint})
		}
	}
	sort.Slice(mounts, func(left, right int) bool {
		if mounts[left].DevicePath != mounts[right].DevicePath {
			return mounts[left].DevicePath < mounts[right].DevicePath
		}
		return mounts[left].Mountpoint < mounts[right].Mountpoint
	})
	return mounts, nil
}

func eligibleFFURemovableMountpoint(path string) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	for _, root := range []string{"/media", "/run/media", "/mnt"} {
		if path == root || strings.HasPrefix(path, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func validateFullFlashTargetPreflightPlan(plan FullFlashTargetPreflightPlan) error {
	if plan.Schema != fullFlashTargetPreflightSchema || plan.Mode != "ffu-full-flash-target-preflight" || !plan.Destructive || !plan.TargetDiscoveryCompleted || !plan.WholeDiskConfirmed || !plan.NormalRemovableTargetConfirmed || !plan.RunningSystemDiskExcluded || !plan.ProtectedMountsExcluded || !plan.TargetIdentityRevalidated || !plan.TargetCapacityRevalidated || !plan.TargetGeometryRevalidated || plan.FixedDiskOverrideAllowed || !plan.PrivilegedOpenRequired || plan.ExecutionSupported {
		return errors.New("invalid FFU target-preflight envelope")
	}
	request := RestoreTargetRequest{
		DevicePath:              plan.DevicePath,
		ExpectedTargetIdentity:  plan.ExpectedTargetIdentity,
		TargetSizeBytes:         plan.TargetSizeBytes,
		LogicalSectorSizeBytes:  plan.LogicalSectorSizeBytes,
		PhysicalSectorSizeBytes: plan.PhysicalSectorSizeBytes,
	}
	if _, err := validateRestoreTargetRequest(request); err != nil {
		return err
	}
	for _, value := range []string{plan.FullFlashValidationPlanSHA256, plan.RestoreTargetPlanSHA256, plan.AuthenticatedIntegritySHA256, plan.ExpectedTargetIdentity, plan.RediscoveredTargetIdentity} {
		if !validFullFlashPlanSHA256(value) {
			return errors.New("FFU target-preflight contains an invalid SHA-256 evidence identifier")
		}
	}
	if plan.ExpectedTargetIdentity != plan.RediscoveredTargetIdentity || plan.TargetSizeBytes == 0 || plan.MutationBytes == 0 || plan.MutationBytes > plan.TargetSizeBytes || plan.StoreBlockSizeBytes == 0 || plan.KernelDeviceID == 0 || strings.TrimSpace(plan.MajorMinor) == "" {
		return errors.New("FFU target-preflight identity or geometry evidence is inconsistent")
	}
	if plan.StoreBlockSizeBytes%plan.LogicalSectorSizeBytes != 0 || plan.StoreBlockSizeBytes%plan.PhysicalSectorSizeBytes != 0 || plan.UnmountRequired != (len(plan.MountedTargets) != 0) {
		return errors.New("FFU target-preflight sector or mount accounting is inconsistent")
	}
	previous := FullFlashTargetMount{}
	for index, mount := range plan.MountedTargets {
		if strings.TrimSpace(mount.DevicePath) == "" || !strings.HasPrefix(mount.DevicePath, "/dev/") || filepath.Clean(mount.DevicePath) != mount.DevicePath || !eligibleFFURemovableMountpoint(mount.Mountpoint) {
			return fmt.Errorf("FFU target-preflight mount %d is invalid", index)
		}
		if index != 0 && (mount.DevicePath < previous.DevicePath || mount.DevicePath == previous.DevicePath && mount.Mountpoint <= previous.Mountpoint) {
			return errors.New("FFU target-preflight mounts are not strictly sorted")
		}
		previous = mount
	}
	if !equalRestoreStrings(plan.Warnings, fullFlashTargetPreflightWarnings()) || !equalRestoreStrings(plan.Limitations, fullFlashTargetPreflightLimitations()) || plan.PlanSHA256 != fullFlashTargetPreflightDigest(plan) {
		return errors.New("FFU target-preflight evidence, warnings, or limitations were altered")
	}
	return nil
}

func fullFlashTargetPreflightWarnings() []string {
	return []string{
		"The selected full-flash target is a destructive whole-disk operation and all existing data may be replaced.",
		"Only a normal removable or USB whole disk is accepted; fixed, internal, partition, read-only, protected-mount, and running-system targets are refused.",
		"Any eligible desktop-mounted target components must be guardedly unmounted and the complete target identity revalidated before a future write.",
		"Read-only preflight does not prove that a later privileged open will succeed or that the restored device will boot.",
	}
}

func fullFlashTargetPreflightLimitations() []string {
	return []string{
		"the target is rediscovered through current Linux metadata but is not opened",
		"the source is not yet held across administrator authentication and target opening",
		"exclusive locking, guarded unmount, descriptor-bound revalidation, write ordering, cancellation, flush, and readback remain outside this boundary",
		"execution remains disabled and no fixed-disk override exists",
	}
}

func fullFlashTargetPreflightDigest(plan FullFlashTargetPreflightPlan) string {
	digest := sha256.New()
	writePreflightUint64(digest, uint64(plan.Schema))
	writePreflightString(digest, plan.Mode)
	writePreflightBool(digest, plan.Destructive)
	writePreflightString(digest, plan.FullFlashValidationPlanSHA256)
	writePreflightString(digest, plan.RestoreTargetPlanSHA256)
	writePreflightString(digest, plan.AuthenticatedIntegritySHA256)
	writePreflightString(digest, plan.DevicePath)
	writePreflightString(digest, plan.ExpectedTargetIdentity)
	writePreflightString(digest, plan.RediscoveredTargetIdentity)
	writePreflightUint64(digest, plan.TargetSizeBytes)
	writePreflightUint64(digest, plan.LogicalSectorSizeBytes)
	writePreflightUint64(digest, plan.PhysicalSectorSizeBytes)
	writePreflightUint64(digest, plan.StoreBlockSizeBytes)
	writePreflightUint64(digest, plan.KernelDeviceID)
	writePreflightString(digest, plan.MajorMinor)
	writePreflightString(digest, plan.Vendor)
	writePreflightString(digest, plan.Model)
	writePreflightString(digest, plan.Transport)
	writePreflightBool(digest, plan.Removable)
	writePreflightBool(digest, plan.Hotplug)
	writePreflightUint64(digest, plan.MutationBytes)
	for _, mount := range plan.MountedTargets {
		writePreflightString(digest, mount.DevicePath)
		writePreflightString(digest, mount.Mountpoint)
	}
	writePreflightBool(digest, plan.UnmountRequired)
	writePreflightBool(digest, plan.TargetDiscoveryCompleted)
	writePreflightBool(digest, plan.WholeDiskConfirmed)
	writePreflightBool(digest, plan.NormalRemovableTargetConfirmed)
	writePreflightBool(digest, plan.RunningSystemDiskExcluded)
	writePreflightBool(digest, plan.ProtectedMountsExcluded)
	writePreflightBool(digest, plan.TargetIdentityRevalidated)
	writePreflightBool(digest, plan.TargetCapacityRevalidated)
	writePreflightBool(digest, plan.TargetGeometryRevalidated)
	writePreflightBool(digest, plan.FixedDiskOverrideAllowed)
	writePreflightBool(digest, plan.PrivilegedOpenRequired)
	writePreflightBool(digest, plan.ExecutionSupported)
	for _, warning := range plan.Warnings {
		writePreflightString(digest, warning)
	}
	for _, limitation := range plan.Limitations {
		writePreflightString(digest, limitation)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func writePreflightUint64(digest hash.Hash, value uint64) { writeFullFlashUint64(digest, value) }
func writePreflightString(digest hash.Hash, value string) { writeFullFlashString(digest, value) }
func writePreflightBool(digest hash.Hash, value bool)     { writeFullFlashBool(digest, value) }
