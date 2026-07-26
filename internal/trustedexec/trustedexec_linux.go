//go:build linux

package trustedexec

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

var allowedUtilities = map[string]struct{}{
	"blockdev": {},
	"findmnt":  {},
	"lsblk":    {},
	"qemu-img": {},
	"umount":   {},
	"wipefs":   {},
}

var systemUtilityRoots = []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin"}

// Resolve returns one root-owned executable from an allowlisted system
// directory. Ambient PATH is never consulted.
func Resolve(name string) (string, error) {
	return resolveAt(name, systemUtilityRoots, 0)
}

func resolveAt(name string, roots []string, trustedUID uint32) (string, error) {
	if strings.TrimSpace(name) != name || name == "" || filepath.Base(name) != name {
		return "", fmt.Errorf("invalid trusted utility name %q", name)
	}
	if _, ok := allowedUtilities[name]; !ok {
		return "", fmt.Errorf("utility %q is not allowlisted", name)
	}
	if len(roots) == 0 {
		return "", errors.New("trusted utility roots are empty")
	}

	canonicalRoots := make([]string, 0, len(roots))
	for _, root := range roots {
		clean := filepath.Clean(root)
		if !filepath.IsAbs(clean) || clean == string(filepath.Separator) {
			return "", fmt.Errorf("invalid trusted utility root %q", root)
		}
		resolved, err := filepath.EvalSymlinks(clean)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return "", fmt.Errorf("resolve trusted utility root %s: %w", clean, err)
		}
		info, err := os.Stat(resolved)
		if err != nil {
			return "", fmt.Errorf("stat trusted utility root %s: %w", resolved, err)
		}
		if err := validateTrustedPath(resolved, info, trustedUID, true); err != nil {
			return "", err
		}
		if !containsPath(canonicalRoots, resolved) {
			canonicalRoots = append(canonicalRoots, resolved)
		}
	}
	if len(canonicalRoots) == 0 {
		return "", errors.New("no trusted utility root is available")
	}

	var rejected []string
	for _, root := range canonicalRoots {
		candidate := filepath.Join(root, name)
		resolved, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			rejected = append(rejected, fmt.Sprintf("%s: %v", candidate, err))
			continue
		}
		if !beneathAnyRoot(resolved, canonicalRoots) {
			rejected = append(rejected, fmt.Sprintf("%s resolves outside trusted roots", candidate))
			continue
		}
		info, err := os.Stat(resolved)
		if err != nil {
			rejected = append(rejected, fmt.Sprintf("%s: %v", resolved, err))
			continue
		}
		if err := validateTrustedPath(resolved, info, trustedUID, false); err != nil {
			rejected = append(rejected, err.Error())
			continue
		}
		return resolved, nil
	}
	if len(rejected) != 0 {
		return "", fmt.Errorf("no safe %s utility found: %s", name, strings.Join(rejected, "; "))
	}
	return "", fmt.Errorf("trusted utility %s was not found", name)
}

func validateTrustedPath(path string, info os.FileInfo, trustedUID uint32, directory bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("trusted path %s has no Linux ownership metadata", path)
	}
	if uint32(stat.Uid) != trustedUID {
		return fmt.Errorf("trusted path %s is owned by uid %d, expected %d", path, stat.Uid, trustedUID)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("trusted path %s is group/world writable", path)
	}
	if directory {
		if !info.IsDir() {
			return fmt.Errorf("trusted utility root %s is not a directory", path)
		}
		return nil
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("trusted utility %s is not a regular file", path)
	}
	if info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("trusted utility %s is not executable", path)
	}
	return nil
}

func beneathAnyRoot(path string, roots []string) bool {
	clean := filepath.Clean(path)
	for _, root := range roots {
		if clean == root || strings.HasPrefix(clean, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func containsPath(paths []string, target string) bool {
	for _, path := range paths {
		if path == target {
			return true
		}
	}
	return false
}
