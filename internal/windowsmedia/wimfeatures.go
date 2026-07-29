//go:build linux

package windowsmedia

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/geocausa/RufusArm64/internal/windowsconfig"
)

const skuSiPolicyWIMPath = "/Windows/System32/SecureBootUpdates/SkuSiPolicy.p7b"

// InspectWIMSetupMetadata combines bounded WIM identity metadata with the
// capability evidence needed by optional Windows setup policies.
func InspectWIMSetupMetadata(ctx context.Context, imagePath string) (windowsconfig.MediaMetadata, error) {
	metadata, err := InspectWIMMetadata(ctx, imagePath)
	if err != nil {
		return windowsconfig.MediaMetadata{}, err
	}
	if strings.EqualFold(filepath.Ext(imagePath), ".swm") {
		metadata.SkuSiPolicyUnavailableWhy = "SkuSiPolicy probing is not yet qualified for split SWM installation payloads"
		return metadata, nil
	}
	available, err := inspectWIMPathInEveryImage(ctx, imagePath, metadata.ImageCount, skuSiPolicyWIMPath)
	if err != nil {
		return windowsconfig.MediaMetadata{}, fmt.Errorf("inspect SkuSiPolicy capability: %w", err)
	}
	metadata.SkuSiPolicyAvailable = available
	if !available {
		metadata.SkuSiPolicyUnavailableWhy = "SkuSiPolicy.p7b was not found in every Windows installation image"
	}
	return metadata, nil
}

func inspectWIMPathInEveryImage(ctx context.Context, imagePath string, imageCount int, wimPath string) (bool, error) {
	if imageCount <= 0 || imageCount > maxWIMImages {
		return false, fmt.Errorf("invalid WIM image count %d", imageCount)
	}
	wimlib, err := wimlibExecutable()
	if err != nil {
		return false, err
	}
	for index := 1; index <= imageCount; index++ {
		available, err := inspectWIMPath(ctx, wimlib, imagePath, index, wimPath)
		if err != nil {
			return false, err
		}
		if !available {
			return false, nil
		}
	}
	return true, nil
}

func inspectWIMPath(ctx context.Context, executable, imagePath string, imageIndex int, wimPath string) (bool, error) {
	if strings.TrimSpace(executable) == "" || strings.TrimSpace(imagePath) == "" || imageIndex <= 0 || !strings.HasPrefix(wimPath, "/") {
		return false, errors.New("invalid WIM path inspection request")
	}
	stdout := NewBoundedBuffer(256 * 1024)
	stderr := NewBoundedBuffer(64 * 1024)
	command := exec.CommandContext(ctx, executable, "dir", imagePath, strconv.Itoa(imageIndex), "--path="+wimPath)
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if err != nil {
		detail := strings.ToLower(strings.TrimSpace(stderr.String() + "\n" + stdout.String()))
		for _, marker := range []string{"does not exist", "no matches", "path not found", "no such file"} {
			if strings.Contains(detail, marker) {
				return false, nil
			}
		}
		return false, fmt.Errorf("inspect WIM image %d path %s: %w: %s", imageIndex, wimPath, err, strings.TrimSpace(detail))
	}
	output := strings.ToLower(strings.ReplaceAll(stdout.String(), "\\", "/"))
	return strings.Contains(output, strings.ToLower(wimPath)) || strings.Contains(output, strings.ToLower(filepath.Base(wimPath))), nil
}
