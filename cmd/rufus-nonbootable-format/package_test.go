//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNonBootableFormatterPackageContract(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	checks := []struct {
		path  string
		parts []string
	}{
		{
			path: filepath.Join(root, "scripts", "build-deb.sh"),
			parts: []string{
				`-o "${PACKAGE_DIR}/usr/lib/rufusarm64/rufusarm64-nonbootable-format"`,
				`"${ROOT_DIR}/cmd/rufus-nonbootable-format"`,
				`ln -s ../lib/rufusarm64/rufusarm64-nonbootable-format`,
				`"${PACKAGE_DIR}/usr/bin/rufusarm64-nonbootable-format"`,
				`rufusarm64-device-backup rufusarm64-nonbootable-format`,
				`fdisk, dosfstools, exfatprogs, e2fsprogs, ntfs-3g`,
			},
		},
		{
			path: filepath.Join(root, "packaging", "io.github.geocausa.RufusArm64.policy"),
			parts: []string{
				`id="io.github.geocausa.RufusArm64.format-data"`,
				`/usr/lib/rufusarm64/rufusarm64-nonbootable-format`,
				`<allow_any>no</allow_any>`,
				`<allow_inactive>no</allow_inactive>`,
				`<allow_active>auth_admin</allow_active>`,
			},
		},
		{
			path: filepath.Join(root, "docs", "rufusarm64-nonbootable-format.1"),
			parts: []string{
				`.TH RUFUSARM64-NONBOOTABLE-FORMAT 1`,
				`data-only media`,
				`not claimed bootable`,
				`--expected-identity`,
				`--cancel-file`,
				`io.github.geocausa.RufusArm64.format-data`,
				`media may have changed and is not reusable`,
			},
		},
		{
			path: filepath.Join(root, ".github", "workflows", "nonbootable-format.yml"),
			parts: []string{
				`GPT/MBR filesystem loop qualification`,
				`util-linux dosfstools exfatprogs ntfs-3g e2fsprogs`,
				`RUFUS_REAL_BLOCK_TEST`,
				`TestExecuteDeviceFormatsRealLoopDevices`,
			},
		},
		{
			path: filepath.Join(root, "internal", "nonbootable", "backend_linux.go"),
			parts: []string{
				`safety.OpenReopenableDevice(plan.DevicePath)`,
				`safety.AcquireExclusiveFlock(ctx, file)`,
				`safety.VerifyOpenDevice(file, backend.options.ExpectedDeviceID, plan.DeviceSizeBytes)`,
				`backend.options.BeforeDestructive(file)`,
				`validateSfdiskDocument`,
				`verifyKernelPartition`,
				`filesystemCheck`,
			},
		},
	}
	for _, check := range checks {
		t.Run(check.path, func(t *testing.T) {
			content, err := os.ReadFile(check.path)
			if err != nil {
				t.Fatal(err)
			}
			text := string(content)
			for _, part := range check.parts {
				if !strings.Contains(text, part) {
					t.Fatalf("%s is missing %q", check.path, part)
				}
			}
		})
	}
}

func TestNoFormatterPackageApplicatorRemains(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	for _, path := range []string{
		filepath.Join(root, ".github", "workflows", "apply-nonbootable-package.yml"),
		filepath.Join(root, ".github", "scripts", "apply_nonbootable_package.py"),
	} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("temporary package applicator remains at %s", path)
		}
	}
}

func TestGraphicalFormatterArgumentsStayNarrow(t *testing.T) {
	value := validArguments()
	if err := validateArguments(value, true); err != nil {
		t.Fatalf("canonical graphical invocation was rejected: %v", err)
	}
	for _, mutate := range []func(*arguments){
		func(options *arguments) { options.allowFixed = true },
		func(options *arguments) { options.noUnmount = true },
		func(options *arguments) { options.cancelFile = "" },
		func(options *arguments) { options.expectedIdentity = "" },
		func(options *arguments) { options.asJSON = false },
		func(options *arguments) { options.yes = false },
	} {
		options := validArguments()
		mutate(&options)
		if err := validateArguments(options, true); err == nil {
			t.Fatal("widened graphical formatter invocation was accepted")
		}
	}
}
