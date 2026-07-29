//go:build linux

package windowsmedia

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectWIMPathInEveryImageRequiresEveryEdition(t *testing.T) {
	tool := filepath.Join(t.TempDir(), "fake-wimlib")
	script := `#!/bin/sh
if [ "$1" = dir ] && [ "$3" = 1 ]; then
  printf '%s\n' '/Windows/System32/SecureBootUpdates/SkuSiPolicy.p7b'
  exit 0
fi
if [ "$1" = dir ] && [ "$3" = 2 ]; then
  echo 'The path does not exist in the WIM image' >&2
  exit 1
fi
exit 2
`
	if err := os.WriteFile(tool, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	available, err := inspectWIMPath(context.Background(), tool, "install.wim", 1, skuSiPolicyWIMPath)
	if err != nil || !available {
		t.Fatalf("image 1 capability = %v, %v", available, err)
	}
	available, err = inspectWIMPath(context.Background(), tool, "install.wim", 2, skuSiPolicyWIMPath)
	if err != nil || available {
		t.Fatalf("image 2 capability = %v, %v", available, err)
	}
}

func TestInspectWIMPathReportsOperationalFailure(t *testing.T) {
	tool := filepath.Join(t.TempDir(), "fake-wimlib")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\necho 'corrupt WIM' >&2\nexit 3\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := inspectWIMPath(context.Background(), tool, "install.wim", 1, skuSiPolicyWIMPath)
	if err == nil || !strings.Contains(err.Error(), "corrupt wim") {
		t.Fatalf("operational error = %v", err)
	}
}
