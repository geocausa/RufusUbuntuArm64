package freedos

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type releaseContract struct {
	Schema       int    `json:"schema"`
	Scope        string `json:"scope"`
	Distribution string `json:"distribution"`
	UpdatePolicy struct {
		AutomaticUpdates     bool     `json:"automatic_updates"`
		RuntimeNetworkAccess bool     `json:"runtime_network_access"`
		Cadence              string   `json:"cadence"`
		RequiredInput        string   `json:"required_input"`
		RequiredChecks       []string `json:"required_checks"`
	} `json:"update_policy"`
	FuturePackage struct {
		PrivateCommandPath              string   `json:"private_command_path"`
		SourceRoot                      string   `json:"source_root"`
		MetadataRoot                    string   `json:"metadata_root"`
		PayloadInstalledAsSeparateFiles bool     `json:"payload_installed_as_separate_files"`
		NewRuntimeDependencies          []string `json:"new_runtime_dependencies"`
		NetworkAccessAtRuntime          bool     `json:"network_access_at_runtime"`
	} `json:"future_package"`
	EmbeddedAssets      []releaseContractFile `json:"embedded_assets"`
	CorrespondingSource []releaseContractFile `json:"corresponding_source"`
	LicenseMetadata     []releaseContractFile `json:"license_metadata"`
	Totals              struct {
		MediaPayloadBytes               uint64 `json:"media_payload_bytes"`
		EmbeddedAssetBytes              uint64 `json:"embedded_asset_bytes"`
		CorrespondingSourceBytes        uint64 `json:"corresponding_source_bytes"`
		LicenseMetadataBytes            uint64 `json:"license_metadata_bytes"`
		MinimumUncompressedPackageBytes uint64 `json:"minimum_uncompressed_package_material_bytes"`
	} `json:"totals"`
}

type releaseContractFile struct {
	Path        string `json:"path"`
	InstallPath string `json:"install_path,omitempty"`
	Role        string `json:"role,omitempty"`
	Size        uint64 `json:"size"`
	SHA256      string `json:"sha256"`
}

func TestReleaseMaintenanceContract(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	path := filepath.Join(root, "vendor", "freedos", "RELEASE-CONTRACT.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var contract releaseContract
	if err := json.Unmarshal(data, &contract); err != nil {
		t.Fatalf("parse release contract: %v", err)
	}
	if contract.Schema != 1 || contract.Distribution != "FreeDOS 1.4" {
		t.Fatalf("unsupported release contract: schema=%d distribution=%q", contract.Schema, contract.Distribution)
	}
	if contract.Scope != "release planning only; no FreeDOS command, runtime installation, device operation, or GTK exposure is authorized" {
		t.Fatalf("release boundary was altered: %q", contract.Scope)
	}
	if contract.UpdatePolicy.AutomaticUpdates || contract.UpdatePolicy.RuntimeNetworkAccess || contract.FuturePackage.NetworkAccessAtRuntime {
		t.Fatal("FreeDOS release maintenance must not authorize automatic or runtime-network updates")
	}
	if contract.FuturePackage.PayloadInstalledAsSeparateFiles {
		t.Fatal("future packaging must not publish executable FreeDOS payload files separately from the package-private helper")
	}
	if len(contract.FuturePackage.NewRuntimeDependencies) != 0 {
		t.Fatalf("release contract unexpectedly adds runtime dependencies: %v", contract.FuturePackage.NewRuntimeDependencies)
	}
	if contract.FuturePackage.PrivateCommandPath != "/usr/lib/rufusarm64/rufusarm64-freedos-format" {
		t.Fatalf("unexpected future command path %q", contract.FuturePackage.PrivateCommandPath)
	}
	if contract.FuturePackage.SourceRoot != "/usr/share/doc/rufusarm64/freedos/source" ||
		contract.FuturePackage.MetadataRoot != "/usr/share/doc/rufusarm64/freedos/metadata" {
		t.Fatal("future source or metadata installation root was altered")
	}
	if !strings.Contains(contract.UpdatePolicy.Cadence, "manual review only") ||
		contract.UpdatePolicy.RequiredInput != "official checksum-pinned FreeDOS FullUSB archive" {
		t.Fatal("release update procedure is not pinned to an intentional official-archive review")
	}
	wantChecks := []string{
		"published archive SHA-256",
		"nested package SHA-256 and exact members",
		"source-backed FORCELBA derivation",
		"Rufus Git blob identity",
		"complete corresponding source archives",
		"exact GPLv2 and package metadata",
		"ordinary-file media verification",
		"read-only loop-device qualification",
		"reproducible Debian package",
	}
	if !reflect.DeepEqual(contract.UpdatePolicy.RequiredChecks, wantChecks) {
		t.Fatalf("release update checks differ from the reviewed sequence: %v", contract.UpdatePolicy.RequiredChecks)
	}

	embeddedTotal := verifyReleaseContractFiles(t, root, contract.EmbeddedAssets, "", false)
	sourceTotal := verifyReleaseContractFiles(t, root, contract.CorrespondingSource, contract.FuturePackage.SourceRoot, true)
	metadataTotal := verifyReleaseContractFiles(t, root, contract.LicenseMetadata, contract.FuturePackage.MetadataRoot, true)
	if embeddedTotal != contract.Totals.EmbeddedAssetBytes || sourceTotal != contract.Totals.CorrespondingSourceBytes || metadataTotal != contract.Totals.LicenseMetadataBytes {
		t.Fatalf("release material totals differ: embedded=%d source=%d metadata=%d", embeddedTotal, sourceTotal, metadataTotal)
	}
	minimum := embeddedTotal + sourceTotal + metadataTotal
	if minimum != contract.Totals.MinimumUncompressedPackageBytes {
		t.Fatalf("minimum package material = %d; contract says %d", minimum, contract.Totals.MinimumUncompressedPackageBytes)
	}
	if contract.Totals.EmbeddedAssetBytes != 182181 || contract.Totals.CorrespondingSourceBytes != 1776157 ||
		contract.Totals.LicenseMetadataBytes != 19885 || contract.Totals.MinimumUncompressedPackageBytes != 1978223 {
		t.Fatalf("reviewed release impact changed: %+v", contract.Totals)
	}

	mediaPayload := uint64(0)
	for _, file := range contract.EmbeddedAssets {
		base := filepath.Base(file.Path)
		if base == "COMMAND.COM" || base == "KERNEL.SYS" {
			mediaPayload += file.Size
		}
	}
	if mediaPayload != contract.Totals.MediaPayloadBytes || mediaPayload != 134028 {
		t.Fatalf("minimal media payload = %d; want 134028", mediaPayload)
	}
}

func verifyReleaseContractFiles(t *testing.T, root string, files []releaseContractFile, installRoot string, requireInstallPath bool) uint64 {
	t.Helper()
	if len(files) == 0 {
		t.Fatal("release contract file group is empty")
	}
	seenSource := make(map[string]bool)
	seenInstall := make(map[string]bool)
	var total uint64
	for _, file := range files {
		if file.Path == "" || filepath.IsAbs(file.Path) || filepath.Clean(file.Path) != file.Path || strings.HasPrefix(file.Path, "..") {
			t.Fatalf("invalid release source path %q", file.Path)
		}
		if seenSource[file.Path] {
			t.Fatalf("duplicate release source path %q", file.Path)
		}
		seenSource[file.Path] = true
		if requireInstallPath {
			if file.InstallPath == "" || !strings.HasPrefix(file.InstallPath, installRoot+"/") || filepath.Clean(file.InstallPath) != file.InstallPath {
				t.Fatalf("invalid install path %q for %q", file.InstallPath, file.Path)
			}
			if seenInstall[file.InstallPath] {
				t.Fatalf("duplicate release install path %q", file.InstallPath)
			}
			seenInstall[file.InstallPath] = true
		} else if file.InstallPath != "" {
			t.Fatalf("embedded asset %q must not be assigned a separately installed executable path", file.Path)
		}
		if file.Size == 0 || len(file.SHA256) != 64 || strings.ToLower(file.SHA256) != file.SHA256 {
			t.Fatalf("invalid size or SHA-256 for %q", file.Path)
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(file.Path)))
		if err != nil {
			t.Fatalf("read %s: %v", file.Path, err)
		}
		if uint64(len(data)) != file.Size {
			t.Fatalf("%s has size %d; contract says %d", file.Path, len(data), file.Size)
		}
		digest := fmt.Sprintf("%x", sha256.Sum256(data))
		if digest != file.SHA256 {
			t.Fatalf("%s failed its release-contract SHA-256", file.Path)
		}
		total += file.Size
	}
	return total
}
