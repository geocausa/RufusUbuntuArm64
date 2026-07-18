//go:build linux

package windowsmedia

import (
	"context"

	"github.com/geocausa/RufusArm64/internal/windowsconfig"
)

func init() {
	inspectCustomizationWIMMetadata = func(context.Context, string) (windowsconfig.MediaMetadata, error) {
		return windowsconfig.MediaMetadata{
			ProductName:      "Windows 11 Pro",
			Version:          "10.0.26100",
			Architecture:     "arm64",
			InstallationType: "Client",
		}, nil
	}
}
