//go:build linux

package isocapture

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
)

const sourceViewWorkspaceRoot = "/run"

// SourceView is a dedicated read-only bind mount of one already selected source
// filesystem. The held Root descriptor is the only source passed to inventory
// and mastering code.
type SourceView struct {
	Root       *os.File
	Mountpoint string
	Inventory  Inventory

	workspace string
	closeOnce sync.Once
	closeErr  error
}

// OpenReadOnlySourceView authenticates a real source directory, inventories it,
// then creates a root-only bind mount with read-only, nosuid, nodev and noexec
// flags. The mounted view must preserve the exact supported content inventory.
func OpenReadOnlySourceView(ctx context.Context, sourcePath string, limits Limits) (*SourceView, error) {
	if ctx == nil {
		return nil, errors.New("ISO source-view context is nil")
	}
	if os.Geteuid() != 0 {
		return nil, errors.New("ISO source-view creation requires root privileges")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	clean := filepath.Clean(sourcePath)
	if sourcePath == "" || !filepath.IsAbs(clean) || clean == string(filepath.Separator) {
		return nil, errors.New("ISO source path must be an absolute non-root directory")
	}
	pathInfo, err := os.Lstat(clean)
	if err != nil {
		return nil, fmt.Errorf("inspect ISO source directory: %w", err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.IsDir() {
		return nil, errors.New("ISO source path must be a real directory")
	}
	original, err := os.OpenFile(clean, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open ISO source directory: %w", err)
	}
	defer original.Close()
	openInfo, err := original.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect open ISO source directory: %w", err)
	}
	if !os.SameFile(pathInfo, openInfo) {
		return nil, errors.New("ISO source directory changed while it was opened")
	}
	originalStat, ok := openInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errors.New("ISO source directory has no Linux identity metadata")
	}
	originalMountID, err := descriptorMountID(original.Fd())
	if err != nil {
		return nil, fmt.Errorf("inspect ISO source mount identity: %w", err)
	}
	before, err := Scan(ctx, original, limits)
	if err != nil {
		return nil, fmt.Errorf("inventory ISO source before creating the read-only view: %w", err)
	}

	mountExecutable, err := resolveMountUtility()
	if err != nil {
		return nil, fmt.Errorf("resolve trusted mount: %w", err)
	}
	workspaceRoot, err := openSecureWorkspaceRoot(sourceViewWorkspaceRoot)
	if err != nil {
		return nil, err
	}
	defer workspaceRoot.Close()
	workspaceProc := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), workspaceRoot.Fd())
	created, err := os.MkdirTemp(workspaceProc, "rufusarm64-iso-source-")
	if err != nil {
		return nil, fmt.Errorf("create ISO source-view workspace: %w", err)
	}
	workspaceName := filepath.Base(created)
	workspace := filepath.Join(sourceViewWorkspaceRoot, workspaceName)
	removeWorkspace := true
	defer func() {
		if removeWorkspace {
			_ = os.RemoveAll(workspace)
		}
	}()
	if err := os.Chmod(workspace, 0o700); err != nil {
		return nil, fmt.Errorf("secure ISO source-view workspace: %w", err)
	}
	mountpoint := filepath.Join(workspace, "source")
	if err := os.Mkdir(mountpoint, 0o700); err != nil {
		return nil, fmt.Errorf("create ISO source-view mountpoint: %w", err)
	}
	preMount, err := os.OpenFile(mountpoint, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open ISO source-view mountpoint: %w", err)
	}
	preMountID, err := descriptorMountID(preMount.Fd())
	preMount.Close()
	if err != nil {
		return nil, fmt.Errorf("inspect ISO source-view mountpoint: %w", err)
	}

	diagnostics := newBoundedDiagnostic(maxProviderDiagnostic)
	bindCommand := exec.Command(
		mountExecutable,
		"--internal-only",
		"--no-canonicalize",
		"--no-mtab",
		"--bind",
		"--",
		"/proc/self/fd/3",
		mountpoint,
	)
	configureMountCommand(bindCommand, diagnostics)
	bindCommand.ExtraFiles = []*os.File{original}
	if err := runProcessGroup(ctx, bindCommand); err != nil {
		return nil, providerError(fmt.Errorf("bind ISO source directory: %w", err), diagnostics)
	}
	mounted := true
	cleanupMount := func() error {
		if !mounted {
			return nil
		}
		if err := syscall.Unmount(mountpoint, 0); err != nil {
			return fmt.Errorf("unmount ISO source view: %w", err)
		}
		mounted = false
		return nil
	}
	cleanupOnError := true
	defer func() {
		if cleanupOnError {
			if err := cleanupMount(); err != nil {
				removeWorkspace = false
			}
		}
	}()

	diagnostics = newBoundedDiagnostic(maxProviderDiagnostic)
	remountCommand := exec.Command(
		mountExecutable,
		"--internal-only",
		"--no-canonicalize",
		"--no-mtab",
		"-o",
		"remount,bind,ro,nosuid,nodev,noexec",
		"--",
		mountpoint,
	)
	configureMountCommand(remountCommand, diagnostics)
	if err := runProcessGroup(ctx, remountCommand); err != nil {
		return nil, providerError(fmt.Errorf("make ISO source view read-only: %w", err), diagnostics)
	}

	root, err := os.OpenFile(mountpoint, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open read-only ISO source view: %w", err)
	}
	viewInfo, err := root.Stat()
	if err != nil {
		root.Close()
		return nil, fmt.Errorf("inspect read-only ISO source view: %w", err)
	}
	viewStat, ok := viewInfo.Sys().(*syscall.Stat_t)
	if !ok {
		root.Close()
		return nil, errors.New("ISO source view has no Linux identity metadata")
	}
	if !sameStatIdentity(*originalStat, *viewStat) {
		root.Close()
		return nil, errors.New("ISO source view does not refer to the selected source root")
	}
	viewMountID, err := descriptorMountID(root.Fd())
	if err != nil {
		root.Close()
		return nil, fmt.Errorf("inspect read-only ISO source-view mount identity: %w", err)
	}
	if viewMountID == preMountID || viewMountID == originalMountID {
		root.Close()
		return nil, errors.New("ISO source view did not create a distinct bind mount")
	}
	if err := requireReadOnlySourceMount(root); err != nil {
		root.Close()
		return nil, err
	}
	viewInventory, err := Scan(ctx, root, limits)
	if err != nil {
		root.Close()
		return nil, fmt.Errorf("inventory read-only ISO source view: %w", err)
	}
	if before.ContentSHA256 != viewInventory.ContentSHA256 {
		root.Close()
		return nil, errors.New("read-only ISO source view differs from the selected source inventory")
	}

	cleanupOnError = false
	removeWorkspace = false
	return &SourceView{
		Root:       root,
		Mountpoint: mountpoint,
		Inventory:  viewInventory,
		workspace:  workspace,
	}, nil
}

func configureMountCommand(command *exec.Cmd, diagnostics *boundedDiagnostic) {
	command.Dir = "/"
	command.Env = []string{
		"HOME=/nonexistent",
		"LC_ALL=C.UTF-8",
		"LIBMOUNT_FSTAB=/dev/null",
		"LIBMOUNT_FORCE_MOUNT2=always",
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"TZ=UTC",
	}
	command.Stdout = diagnostics
	command.Stderr = diagnostics
}

func requireReadOnlySourceMount(root *os.File) error {
	var statfs syscall.Statfs_t
	if err := syscall.Fstatfs(int(root.Fd()), &statfs); err != nil {
		return fmt.Errorf("inspect ISO source-view filesystem flags: %w", err)
	}
	required := uint64(statfsReadOnly | statfsNoSuid | statfsNoDev | statfsNoExec)
	if uint64(statfs.Flags)&required != required {
		return fmt.Errorf("ISO source view is missing required read-only safety flags: flags=%#x required=%#x", statfs.Flags, required)
	}
	return nil
}

// Close releases the held root descriptor, unmounts the read-only view and
// removes its private workspace. A failed unmount preserves the workspace and
// is returned to the caller rather than recursively deleting a mounted tree.
func (view *SourceView) Close() error {
	if view == nil {
		return nil
	}
	view.closeOnce.Do(func() {
		var closeErr error
		if view.Root != nil {
			closeErr = view.Root.Close()
			view.Root = nil
		}
		unmountErr := syscall.Unmount(view.Mountpoint, 0)
		if unmountErr != nil {
			view.closeErr = errors.Join(closeErr, fmt.Errorf("unmount ISO source view: %w", unmountErr))
			return
		}
		removeErr := os.RemoveAll(view.workspace)
		view.closeErr = errors.Join(closeErr, removeErr)
	})
	return view.closeErr
}
