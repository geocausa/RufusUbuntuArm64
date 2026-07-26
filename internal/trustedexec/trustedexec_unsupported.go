//go:build !linux

package trustedexec

import "fmt"

func Resolve(name string) (string, error) {
	return "", fmt.Errorf("trusted utility %q is supported only on Linux", name)
}
