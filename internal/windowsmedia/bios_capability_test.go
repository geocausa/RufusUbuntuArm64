//go:build linux

package windowsmedia

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geocausa/RufusArm64/internal/windowsconfig"
)

func TestInspectMountedISOAllowsBootmgrCandidateWithoutUEFI(t *testing.T) {
	root := biosOnlyFixture(t)
	plan, err := inspectMountedISO(root)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.HasBootmgr || plan.HasARM64 || plan.HasX64 || plan.HasX86 || plan.HasBIOS {
		t.Fatalf("unexpected pre-metadata plan: %#v", plan)
	}
	if plan.BootWIMPath == "" || !strings.Contains(plan.Architecture, "pending") {
		t.Fatalf("candidate was not retained for bounded metadata inspection: %#v", plan)
	}
}

func TestBindBIOSMetadataAcceptsOnlyX86Families(t *testing.T) {
	for _, tc := range []struct {
		arch             string
		wantArchitecture string
	}{
		{"amd64", "x86-64 legacy BIOS"},
		{"x86", "x86 legacy BIOS"},
	} {
		plan := mediaPlan{HasBootmgr: true}
		if err := bindBIOSMetadata(&plan, windowsconfig.MediaMetadata{Architecture: tc.arch}); err != nil {
			t.Fatalf("%s: %v", tc.arch, err)
		}
		if !plan.HasBIOS || plan.BIOSArchitecture != tc.arch || plan.Architecture != tc.wantArchitecture {
			t.Fatalf("%s produced %#v", tc.arch, plan)
		}
	}
	for _, arch := range []string{"arm64", "", "mixed"} {
		plan := mediaPlan{HasBootmgr: true}
		if err := bindBIOSMetadata(&plan, windowsconfig.MediaMetadata{Architecture: arch}); err == nil {
			t.Fatalf("unsupported architecture %q was accepted", arch)
		}
	}
	if err := bindBIOSMetadata(&mediaPlan{}, windowsconfig.MediaMetadata{Architecture: "amd64"}); err == nil {
		t.Fatal("BIOS capability was accepted without root bootmgr")
	}
}

func TestBindBootCapabilitiesUsesBoundedBootWIMMetadata(t *testing.T) {
	root := biosOnlyFixture(t)
	plan, err := inspectMountedISO(root)
	if err != nil {
		t.Fatal(err)
	}
	installFakeWIMInfo(t, "amd64")
	if err := bindBootCapabilities(context.Background(), &plan); err != nil {
		t.Fatal(err)
	}
	if !plan.HasBIOS || plan.BIOSArchitecture != "amd64" {
		t.Fatalf("BIOS capability was not bound: %#v", plan)
	}
	scheme, target, err := resolveWindowsLayout(plan, "auto", "auto")
	if err != nil || scheme != "mbr" || target != "bios" {
		t.Fatalf("automatic layout=%s/%s err=%v", scheme, target, err)
	}
	if _, _, err := resolveWindowsLayout(plan, "gpt", "auto"); err == nil {
		t.Fatal("BIOS-only media accepted GPT automatic layout")
	}
	if _, _, err := resolveWindowsLayout(plan, "mbr", "uefi"); err == nil {
		t.Fatal("BIOS-only media accepted explicit UEFI")
	}
}

func TestBindBootCapabilitiesRejectsARM64BIOSOnlyMedia(t *testing.T) {
	root := biosOnlyFixture(t)
	plan, err := inspectMountedISO(root)
	if err != nil {
		t.Fatal(err)
	}
	installFakeWIMInfo(t, "arm64")
	if err := bindBootCapabilities(context.Background(), &plan); err == nil || !strings.Contains(err.Error(), "ARM64") {
		t.Fatalf("ARM64 BIOS-only media error=%v", err)
	}
}

func TestAutomaticLayoutStillPrefersUEFIWhenAvailable(t *testing.T) {
	plan := mediaPlan{HasX64: true, HasBootmgr: true, HasBIOS: true, BIOSArchitecture: "amd64"}
	scheme, target, err := resolveWindowsLayout(plan, "auto", "auto")
	if err != nil || scheme != "gpt" || target != "uefi" {
		t.Fatalf("dual-capable default=%s/%s err=%v", scheme, target, err)
	}
	scheme, target, err = resolveWindowsLayout(plan, "auto", "bios")
	if err != nil || scheme != "mbr" || target != "bios" {
		t.Fatalf("explicit BIOS default=%s/%s err=%v", scheme, target, err)
	}
}

func biosOnlyFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "sources", "boot.wim"), []byte("boot metadata fixture"))
	writeTestFile(t, filepath.Join(root, "sources", "install.wim"), []byte("install"))
	writeTestFile(t, filepath.Join(root, "bootmgr"), []byte("bootmgr"))
	writeTestFile(t, filepath.Join(root, "setup.exe"), []byte("setup"))
	return root
}

func installFakeWIMInfo(t *testing.T, architecture string) {
	t.Helper()
	fakeBin := t.TempDir()
	xml := `<WIM><IMAGE INDEX="1"><NAME>Windows Setup</NAME><WINDOWS><ARCH>` + architecture + `</ARCH><PRODUCTNAME>Windows 10 Setup</PRODUCTNAME><INSTALLATIONTYPE>Client</INSTALLATIONTYPE><VERSION><MAJOR>10</MAJOR><MINOR>0</MINOR><BUILD>19045</BUILD></VERSION></WINDOWS></IMAGE></WIM>`
	script := "#!/bin/sh\nprintf '%s' '" + xml + "'\n"
	path := filepath.Join(fakeBin, "wimlib-imagex")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
}
