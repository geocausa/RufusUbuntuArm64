//go:build linux

package windowsmedia

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// findUniqueRelativeCaseInsensitive resolves one security-critical media
// path while refusing case-colliding aliases, symlinks, and wrong file
// types. ISO filesystems are case-insensitive in common Windows media,
// but extracted test trees can otherwise hide ambiguous payloads.
func findUniqueRelativeCaseInsensitive(root, relative string) (string, bool, error) {
	parts := strings.Split(filepath.ToSlash(relative), "/")
	current := root
	for index, wanted := range parts {
		entries, err := os.ReadDir(current)
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		if err != nil {
			return "", false, fmt.Errorf("read Windows media path %s: %w", filepath.ToSlash(relative), err)
		}
		var match os.DirEntry
		for _, entry := range entries {
			if !strings.EqualFold(entry.Name(), wanted) {
				continue
			}
			if match != nil {
				return "", false, fmt.Errorf("ambiguous case-insensitive Windows media path %s: %s and %s", filepath.ToSlash(relative), match.Name(), entry.Name())
			}
			match = entry
		}
		if match == nil {
			return "", false, nil
		}
		if match.Type()&os.ModeSymlink != 0 {
			return "", false, fmt.Errorf("security-critical Windows media path is a symbolic link: %s", filepath.ToSlash(relative))
		}
		last := index == len(parts)-1
		if !last && !match.IsDir() {
			return "", false, fmt.Errorf("windows media path component is not a directory: %s", filepath.ToSlash(relative))
		}
		if last && match.IsDir() {
			return "", false, fmt.Errorf("security-critical Windows media path is not a regular file: %s", filepath.ToSlash(relative))
		}
		current = filepath.Join(current, match.Name())
	}
	info, err := os.Lstat(current)
	if err != nil {
		return "", false, fmt.Errorf("inspect Windows media path %s: %w", filepath.ToSlash(relative), err)
	}
	if !info.Mode().IsRegular() {
		return "", false, fmt.Errorf("security-critical Windows media path is not a regular file: %s", filepath.ToSlash(relative))
	}
	return current, true, nil
}
