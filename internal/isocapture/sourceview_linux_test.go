//go:build linux

package isocapture

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenReadOnlySourceViewRejectsNilContext(t *testing.T) {
	view, err := OpenReadOnlySourceView(nil, t.TempDir(), strings.Repeat("a", 64), Limits{})
	if view != nil || err == nil || !strings.Contains(err.Error(), "context") {
		t.Fatalf("view=%v error=%v", view, err)
	}
}

func TestOpenReadOnlySourceViewRequiresRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("non-root contract is exercised by normal CI users")
	}
	view, err := OpenReadOnlySourceView(context.Background(), t.TempDir(), strings.Repeat("a", 64), Limits{})
	if view != nil || err == nil || !strings.Contains(err.Error(), "root privileges") {
		t.Fatalf("view=%v error=%v", view, err)
	}
}

func TestRequireExpectedSourceBinding(t *testing.T) {
	digest := strings.Repeat("a", 64)
	inventory := Inventory{BindingSHA256: digest}
	if err := requireExpectedSourceBinding(inventory, digest); err != nil {
		t.Fatal(err)
	}
	if err := requireExpectedSourceBinding(inventory, strings.Repeat("b", 64)); err == nil || !strings.Contains(err.Error(), "does not match reviewed plan") {
		t.Fatalf("unexpected mismatch error: %v", err)
	}
	if err := requireExpectedSourceBinding(inventory, "bad"); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("unexpected malformed digest error: %v", err)
	}
}

func TestRequireReadOnlySourceMountRejectsWritableDirectory(t *testing.T) {
	root, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := requireReadOnlySourceMount(root); err == nil || !strings.Contains(err.Error(), "read-only safety flags") {
		t.Fatalf("writable mount error = %v", err)
	}
}

func TestSourceViewClosePreservesWorkspaceWhenUnmountFails(t *testing.T) {
	workspace := t.TempDir()
	mountpoint := filepath.Join(workspace, "not-mounted")
	if err := os.Mkdir(mountpoint, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.Open(mountpoint)
	if err != nil {
		t.Fatal(err)
	}
	view := &SourceView{Root: root, Mountpoint: mountpoint, workspace: workspace}
	if err := view.Close(); err == nil || !strings.Contains(err.Error(), "unmount") {
		t.Fatalf("close error = %v", err)
	}
	if _, err := os.Stat(workspace); err != nil {
		t.Fatalf("workspace was removed after failed unmount: %v", err)
	}
	if err := view.Close(); err == nil {
		t.Fatal("idempotent close lost the original unmount failure")
	}
}

func TestSourceViewCloseNil(t *testing.T) {
	var view *SourceView
	if err := view.Close(); err != nil {
		t.Fatal(err)
	}
}
