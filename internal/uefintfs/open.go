//go:build linux

package uefintfs

// Open verifies one explicit path against the pinned UEFI:NTFS size and SHA-256.
// It is used by callers that already recorded the path returned by Locate and
// need to re-admit the same bytes immediately before writing or readback.
func Open(path string) (Asset, error) {
	return verifyAsset(path, ImageSize, ImageSHA256)
}
