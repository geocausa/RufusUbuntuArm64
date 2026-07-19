//go:build linux

package windowsmedia

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os/exec"
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

// BoundedBuffer collects command output while enforcing a hard byte limit.
// It is exported so callers that need the same bounded command contract can
// reuse it without silently falling back to unbounded CombinedOutput calls.
type BoundedBuffer struct {
	buffer bytes.Buffer
	limit  int
}

// NewBoundedBuffer creates a bounded command-output collector.
func NewBoundedBuffer(limit int) *BoundedBuffer {
	return &BoundedBuffer{limit: limit}
}

func (b *BoundedBuffer) Write(data []byte) (int, error) {
	if b == nil || b.limit <= 0 {
		return 0, errors.New("bounded buffer has no positive size limit")
	}
	if b.buffer.Len()+len(data) > b.limit {
		return 0, errors.New("WIM metadata exceeds the safe size limit")
	}
	return b.buffer.Write(data)
}

// Bytes returns the collected bytes.
func (b *BoundedBuffer) Bytes() []byte {
	if b == nil {
		return nil
	}
	return b.buffer.Bytes()
}

// String returns the collected output as text.
func (b *BoundedBuffer) String() string {
	if b == nil {
		return ""
	}
	return b.buffer.String()
}

// InspectWIMMetadata executes the pinned or system wimlib engine without a
// shell and caps XML output before parsing it.
func InspectWIMMetadata(ctx context.Context, imagePath string) (windowsconfig.MediaMetadata, error) {
	wimlib, err := wimlibExecutable()
	if err != nil {
		return windowsconfig.MediaMetadata{}, err
	}
	stdout := NewBoundedBuffer(maxWIMMetadataBytes)
	stderr := NewBoundedBuffer(64 * 1024)
	command := exec.CommandContext(ctx, wimlib, "info", imagePath, "--xml")
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return windowsconfig.MediaMetadata{}, fmt.Errorf("inspect Windows image metadata: %w: %s", err, detail)
		}
		return windowsconfig.MediaMetadata{}, fmt.Errorf("inspect Windows image metadata: %w", err)
	}
	return parseWIMMetadata(bytes.NewReader(stdout.Bytes()))
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
