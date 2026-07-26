//go:build linux

package safety

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/geocausa/RufusArm64/internal/device"
	"github.com/geocausa/RufusArm64/internal/trustedexec"
)

var (
	resolveSafetyUtility = trustedexec.Resolve
	findSafetyDevice     = device.Find
)

func trustedSafetyCommandContext(ctx context.Context, name string, args ...string) (*exec.Cmd, error) {
	path, err := resolveSafetyUtility(name)
	if err != nil {
		return nil, fmt.Errorf("resolve trusted utility %s: %w", name, err)
	}
	return exec.CommandContext(ctx, path, args...), nil
}
