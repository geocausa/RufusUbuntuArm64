//go:build linux

package windowsmedia

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/geocausa/RufusArm64/internal/windowsconfig"
)

const maxWIMMetadataBytes = 8 * 1024 * 1024

type wimInfoXML struct {
	Images []wimImageXML `xml:"IMAGE"`
}

type wimImageXML struct {
	Name    string        `xml:"NAME"`
	Windows wimWindowsXML `xml:"WINDOWS"`
}

type wimWindowsXML struct {
	Architecture     string        `xml:"ARCH"`
	ProductName      string        `xml:"PRODUCTNAME"`
	InstallationType string        `xml:"INSTALLATIONTYPE"`
	Version          wimVersionXML `xml:"VERSION"`
}

type wimVersionXML struct {
	Major string `xml:"MAJOR"`
	Minor string `xml:"MINOR"`
	Build string `xml:"BUILD"`
}

// parseWIMMetadata converts bounded wimlib XML output into the conservative
// capability metadata shared by Windows setup validation and the GUI.
func parseWIMMetadata(reader io.Reader) (windowsconfig.MediaMetadata, error) {
	if reader == nil {
		return windowsconfig.MediaMetadata{}, errors.New("WIM metadata reader is nil")
	}
	limited := io.LimitReader(reader, maxWIMMetadataBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return windowsconfig.MediaMetadata{}, fmt.Errorf("read WIM metadata: %w", err)
	}
	if len(data) > maxWIMMetadataBytes {
		return windowsconfig.MediaMetadata{}, errors.New("WIM metadata exceeds the safe size limit")
	}
	var document wimInfoXML
	if err := xml.Unmarshal(data, &document); err != nil {
		return windowsconfig.MediaMetadata{}, fmt.Errorf("parse WIM metadata XML: %w", err)
	}
	if len(document.Images) == 0 {
		return windowsconfig.MediaMetadata{}, errors.New("WIM metadata contains no Windows images")
	}

	var result windowsconfig.MediaMetadata
	for index, image := range document.Images {
		current := windowsconfig.MediaMetadata{
			ProductName:      firstNonEmpty(image.Windows.ProductName, image.Name),
			Version:          joinVersion(image.Windows.Version),
			Architecture:     normalizeWIMArchitecture(image.Windows.Architecture),
			InstallationType: strings.TrimSpace(image.Windows.InstallationType),
		}
		if index == 0 {
			result = current
			continue
		}
		if metadataClass(result) != metadataClass(current) {
			return windowsconfig.MediaMetadata{}, errors.New("WIM editions contain conflicting Windows generation, family, or architecture metadata")
		}
	}
	return result, nil
}

func metadataClass(metadata windowsconfig.MediaMetadata) string {
	profile := windowsconfig.Capabilities(metadata)
	return strings.Join([]string{profile.Generation, profile.Family, profile.Architecture, profile.Reason}, "|")
}

func joinVersion(version wimVersionXML) string {
	parts := []string{strings.TrimSpace(version.Major), strings.TrimSpace(version.Minor), strings.TrimSpace(version.Build)}
	for len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return strings.Join(parts, ".")
}

func normalizeWIMArchitecture(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "12", "arm64", "aarch64":
		return "arm64"
	case "9", "amd64", "x64", "x86-64":
		return "amd64"
	case "0", "x86", "i386", "i686":
		return "x86"
	default:
		return strings.TrimSpace(value)
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
