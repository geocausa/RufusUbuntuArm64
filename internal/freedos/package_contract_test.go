package freedos

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPackagedFreeDOSCommandContract(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	build := readFreeDOSContractFile(t, filepath.Join(root, "scripts", "build-deb.sh"))
	for _, required := range []string{
		`"${ROOT_DIR}/cmd/rufus-freedos-format"`,
		`"${PACKAGE_DIR}/usr/lib/rufusarm64/rufusarm64-freedos-format"`,
		`"${PACKAGE_DIR}/usr/bin/rufusarm64-freedos-format"`,
		`../lib/rufusarm64/rufusarm64-freedos-format`,
		`vendor/freedos/source/${file}`,
		`usr/share/doc/rufusarm64/freedos/source/${file}`,
		`vendor/freedos/metadata/${file}`,
		`usr/share/doc/rufusarm64/freedos/metadata/${file}`,
		`PAYLOADS.json RELEASE-CONTRACT.json`,
		`rufusarm64-freedos-format; do`,
		`creates verified x86 BIOS/Legacy FreeDOS 1.4 media`,
	} {
		if !strings.Contains(build, required) {
			t.Fatalf("Debian package builder is missing FreeDOS contract %q", required)
		}
	}
	if strings.Contains(build, "curl ") || strings.Contains(build, "wget ") {
		t.Fatal("FreeDOS package build must not acquire payloads from the network")
	}

	policy := readFreeDOSContractFile(t, filepath.Join(root, "packaging", "io.github.geocausa.RufusArm64.policy"))
	for _, required := range []string{
		`<action id="io.github.geocausa.RufusArm64.format-freedos">`,
		`<allow_any>no</allow_any>`,
		`<allow_inactive>no</allow_inactive>`,
		`<allow_active>auth_admin</allow_active>`,
		`<annotate key="org.freedesktop.policykit.exec.path">/usr/lib/rufusarm64/rufusarm64-freedos-format</annotate>`,
	} {
		if !strings.Contains(policy, required) {
			t.Fatalf("FreeDOS Polkit action is missing %q", required)
		}
	}
	if strings.Contains(policy, "auth_admin_keep") {
		t.Fatal("FreeDOS Polkit authorization must not be retained")
	}

	manual := readFreeDOSContractFile(t, filepath.Join(root, "docs", "rufusarm64-freedos-format.1"))
	for _, required := range []string{
		"WRITE FREEDOS 1.4 TO /dev/DEVICE FOR X86 BIOS LEGACY",
		"There is no fixed-disk override",
		"media_changed=true",
		"reusable=false",
		"/usr/share/doc/rufusarm64/freedos/",
	} {
		if !strings.Contains(manual, required) {
			t.Fatalf("FreeDOS manual is missing %q", required)
		}
	}

	copyright := readFreeDOSContractFile(t, filepath.Join(root, "packaging", "copyright"))
	for _, required := range []string{
		"internal/freedos/payload/* vendor/freedos/*",
		"complete corresponding FreeCOM and kernel source archives",
		"/usr/share/doc/rufusarm64/freedos/",
		"internal/freedos/bootassets/*",
	} {
		if !strings.Contains(copyright, required) {
			t.Fatalf("Debian copyright record is missing %q", required)
		}
	}
}

func readFreeDOSContractFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}
