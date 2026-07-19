package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBackupCommandPackageContract(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	checks := []struct {
		path  string
		parts []string
	}{
		{
			path: filepath.Join(root, "scripts", "build-deb.sh"),
			parts: []string{
				`-o "${PACKAGE_DIR}/usr/lib/rufusarm64/rufusarm64-device-backup"`,
				`"${ROOT_DIR}/cmd/rufus-device-backup"`,
				`"${PACKAGE_DIR}/usr/bin/rufusarm64-device-backup"`,
				`rufusarm64-device-qualify rufusarm64-device-backup`,
			},
		},
		{
			path: filepath.Join(root, "packaging", "io.github.geocausa.RufusArm64.policy"),
			parts: []string{
				`id="io.github.geocausa.RufusArm64.backup"`,
				`/usr/lib/rufusarm64/rufusarm64-device-backup`,
				`<allow_active>auth_admin</allow_active>`,
			},
		},
		{
			path: filepath.Join(root, "docs", "rufusarm64-device-backup.1"),
			parts: []string{
				`.TH RUFUSARM64-DEVICE-BACKUP 1`,
				`Existing destination files are never replaced`,
				`--expected-identity`,
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
