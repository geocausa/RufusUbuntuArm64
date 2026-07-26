//go:build linux

package isocapture

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"syscall"
)

const unsupportedSpecialModeBits = syscall.S_ISUID | syscall.S_ISGID | syscall.S_ISVTX

// requirePortableMetadata refuses metadata that the fixed genisoimage UDF
// bridge cannot preserve and independently verify. Ordinary ownership and
// permission bits are recorded in the source-binding digest but intentionally
// normalized by the read-only filesystem remaster.
func requirePortableMetadata(fd uintptr, stat syscall.Stat_t, path string) error {
	if stat.Mode&unsupportedSpecialModeBits != 0 {
		return fmt.Errorf("source object %q uses setuid, setgid, or sticky permission semantics", displayPath(path))
	}
	descriptorPath := "/proc/self/fd/" + strconv.FormatUint(uint64(fd), 10)
	size, err := syscall.Listxattr(descriptorPath, nil)
	if errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP) {
		return nil
	}
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("inspect extended metadata for %q: permission denied", displayPath(path))
		}
		return fmt.Errorf("inspect extended metadata for %q: %w", displayPath(path), err)
	}
	if size != 0 {
		return fmt.Errorf("source object %q has extended attributes or ACL metadata that ISO capture cannot preserve", displayPath(path))
	}
	return nil
}
