//go:build linux

package windowsmedia

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"unicode"

	"github.com/geocausa/RufusArm64/internal/windowsconfig"
)

const (
	maxWIMMetadataBytes = 8 * 1024 * 1024
	maxWIMImages        = 256
	maxWIMEditionName   = 256
)

type wimInfoXML struct {
	Images []wimImageXML `xml:"IMAGE"`
}

type wimImageXML struct {
	Index       string        `xml:"INDEX,attr"`
	TotalBytes  string        `xml:"TOTALBYTES"`
	Name        string        `xml:"NAME"`
	DisplayName string        `xml:"DISPLAYNAME"`
	Description string        `xml:"DESCRIPTION"`
	Windows     wimWindowsXML `xml:"WINDOWS"`
}

type wimWindowsXML struct {
	Architecture     string          `xml:"ARCH"`
	ProductName      string          `xml:"PRODUCTNAME"`
	InstallationType string          `xml:"INSTALLATIONTYPE"`
	Languages        wimLanguagesXML `xml:"LANGUAGES"`
	Version          wimVersionXML   `xml:"VERSION"`
}

type wimLanguagesXML struct {
	Languages []string `xml:"LANGUAGE"`
	Default   string   `xml:"DEFAULT"`
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
// shell and caps XML output before parsing it. wiminfo can inspect the first
// part of a split WIM directly because its XML image metadata is stored there;
// no resource extraction or automatic edition selection is performed.
func InspectWIMMetadata(ctx context.Context, imagePath string) (windowsconfig.MediaMetadata, error) {
	wimlib, err := wimlibExecutable()
	if err != nil {
		return windowsconfig.MediaMetadata{}, err
	}
	return InspectWIMMetadataWithExecutable(ctx, wimlib, imagePath)
}

// InspectWIMMetadataWithExecutable runs the same bounded parser through an
// explicitly selected WIM engine. Specialized privileged writers use this to
// ensure that preflight metadata and image application are performed by the
// same package-owned executable rather than an ambient PATH binary.
func InspectWIMMetadataWithExecutable(ctx context.Context, executable, imagePath string) (windowsconfig.MediaMetadata, error) {
	if ctx == nil {
		return windowsconfig.MediaMetadata{}, errors.New("WIM metadata context is nil")
	}
	if strings.TrimSpace(executable) == "" {
		return windowsconfig.MediaMetadata{}, errors.New("WIM metadata executable is empty")
	}
	stdout := NewBoundedBuffer(maxWIMMetadataBytes)
	stderr := NewBoundedBuffer(64 * 1024)
	command := exec.CommandContext(ctx, executable, "info", imagePath, "--xml")
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
// capability metadata shared by Windows setup validation and the GUI. Every
// edition must agree on generation, family, and architecture before the result
// is accepted; the bounded edition list is retained only for disclosure.
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
	normalized, wasUTF16, err := normalizeWIMMetadataXML(data)
	if err != nil {
		return windowsconfig.MediaMetadata{}, err
	}
	var document wimInfoXML
	decoder := xml.NewDecoder(bytes.NewReader(normalized))
	if wasUTF16 {
		decoder.CharsetReader = func(label string, input io.Reader) (io.Reader, error) {
			label = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(label), "_", "-"))
			switch label {
			case "utf-16", "utf-16le", "utf-16-le", "utf-16be", "utf-16-be":
				return input, nil
			default:
				return nil, fmt.Errorf("unsupported WIM metadata XML encoding %q", label)
			}
		}
	}
	if err := decoder.Decode(&document); err != nil {
		return windowsconfig.MediaMetadata{}, fmt.Errorf("parse WIM metadata XML: %w", err)
	}
	if len(document.Images) == 0 {
		return windowsconfig.MediaMetadata{}, errors.New("WIM metadata contains no Windows images")
	}
	if len(document.Images) > maxWIMImages {
		return windowsconfig.MediaMetadata{}, fmt.Errorf("WIM metadata contains %d images; the safe limit is %d", len(document.Images), maxWIMImages)
	}

	var result windowsconfig.MediaMetadata
	seenNames := make(map[string]struct{})
	seenIndexes := make(map[int]struct{}, len(document.Images))
	for index, image := range document.Images {
		current := windowsconfig.MediaMetadata{
			ProductName:      firstNonEmpty(image.DisplayName, image.Windows.ProductName, image.Name),
			Version:          joinVersion(image.Windows.Version),
			Architecture:     normalizeWIMArchitecture(image.Windows.Architecture),
			InstallationType: strings.TrimSpace(image.Windows.InstallationType),
		}
		if index == 0 {
			result = current
		} else if metadataClass(result) != metadataClass(current) {
			return windowsconfig.MediaMetadata{}, errors.New("WIM editions contain conflicting Windows generation, family, or architecture metadata")
		}

		name := firstNonEmpty(image.DisplayName, image.Description, image.Name, image.Windows.ProductName)
		if len(name) > maxWIMEditionName {
			return windowsconfig.MediaMetadata{}, fmt.Errorf("WIM edition name exceeds the %d-byte safe limit", maxWIMEditionName)
		}
		imageIndex, err := strconv.Atoi(strings.TrimSpace(image.Index))
		if err != nil || imageIndex <= 0 || imageIndex > maxWIMImages {
			return windowsconfig.MediaMetadata{}, fmt.Errorf("WIM image %d has invalid INDEX %q", index+1, image.Index)
		}
		if _, duplicate := seenIndexes[imageIndex]; duplicate {
			return windowsconfig.MediaMetadata{}, fmt.Errorf("WIM image INDEX %d is duplicated", imageIndex)
		}
		seenIndexes[imageIndex] = struct{}{}
		language, err := normalizeWIMLanguage(image.Windows.Languages)
		if err != nil {
			return windowsconfig.MediaMetadata{}, fmt.Errorf("WIM image %d language metadata: %w", imageIndex, err)
		}
		totalBytes, err := normalizeWIMTotalBytes(image.TotalBytes)
		if err != nil {
			return windowsconfig.MediaMetadata{}, fmt.Errorf("WIM image %d expanded-size metadata: %w", imageIndex, err)
		}
		result.Images = append(result.Images, windowsconfig.WindowsImage{
			Index: imageIndex, Name: name, DefaultLanguage: language, TotalBytes: totalBytes,
		})
		if name != "" {
			key := strings.ToLower(name)
			if _, exists := seenNames[key]; !exists {
				seenNames[key] = struct{}{}
				result.EditionNames = append(result.EditionNames, name)
			}
		}
	}
	result.ImageCount = len(document.Images)
	return result, nil
}

func normalizeWIMTotalBytes(value string) (uint64, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	total, err := strconv.ParseUint(value, 10, 64)
	if err != nil || total == 0 {
		return 0, fmt.Errorf("TOTALBYTES %q is not a positive decimal integer", value)
	}
	return total, nil
}

func normalizeWIMLanguage(languages wimLanguagesXML) (string, error) {
	value := strings.TrimSpace(languages.Default)
	if value == "" {
		for _, candidate := range languages.Languages {
			if value = strings.TrimSpace(candidate); value != "" {
				break
			}
		}
	}
	if value == "" {
		return "", nil
	}
	if len(value) > 32 {
		return "", errors.New("default language exceeds 32 bytes")
	}
	for _, character := range value {
		if unicode.IsControl(character) || !(unicode.IsLetter(character) || unicode.IsDigit(character) || character == '-') {
			return "", fmt.Errorf("default language %q contains unsupported characters", value)
		}
	}
	return value, nil
}

func wimImageByIndex(metadata windowsconfig.MediaMetadata, index int) (windowsconfig.WindowsImage, bool) {
	for _, image := range metadata.Images {
		if image.Index == index {
			return image, true
		}
	}
	return windowsconfig.WindowsImage{}, false
}

func normalizeWIMMetadataXML(data []byte) ([]byte, bool, error) {
	if bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf}) {
		return data[3:], false, nil
	}

	var order binary.ByteOrder
	offset := 0
	switch {
	case bytes.HasPrefix(data, []byte{0xff, 0xfe}):
		order = binary.LittleEndian
		offset = 2
	case bytes.HasPrefix(data, []byte{0xfe, 0xff}):
		order = binary.BigEndian
		offset = 2
	case len(data) >= 4 && data[0] == '<' && data[1] == 0:
		order = binary.LittleEndian
	case len(data) >= 4 && data[0] == 0 && data[1] == '<':
		order = binary.BigEndian
	default:
		return data, false, nil
	}

	if (len(data)-offset)%2 != 0 {
		return nil, false, errors.New("WIM metadata UTF-16 byte count is not even")
	}
	var decoded bytes.Buffer
	for index := offset; index < len(data); index += 2 {
		unit := order.Uint16(data[index : index+2])
		if index == offset && unit == 0xfeff {
			continue
		}
		switch {
		case unit >= 0xd800 && unit <= 0xdbff:
			if index+3 >= len(data) {
				return nil, false, errors.New("WIM metadata UTF-16 ends with an incomplete surrogate pair")
			}
			low := order.Uint16(data[index+2 : index+4])
			if low < 0xdc00 || low > 0xdfff {
				return nil, false, errors.New("WIM metadata UTF-16 contains a malformed surrogate pair")
			}
			value := 0x10000 + (rune(unit)-0xd800)<<10 + (rune(low) - 0xdc00)
			decoded.WriteRune(value)
			index += 2
		case unit >= 0xdc00 && unit <= 0xdfff:
			return nil, false, errors.New("WIM metadata UTF-16 contains an unpaired low surrogate")
		default:
			decoded.WriteRune(rune(unit))
		}
	}
	return decoded.Bytes(), true, nil
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
