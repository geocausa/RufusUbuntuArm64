//go:build !linux

package persistence

import "io/fs"

func detectPathBackedFS(root fs.FS) (Detection, bool, error) {
	return Detection{}, false, nil
}
