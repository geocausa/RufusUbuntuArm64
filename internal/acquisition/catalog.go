package acquisition

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	SchemaVersion      = 1
	MaxCatalogBytes    = 1024 * 1024
	MaxCatalogEntries  = 512
	MaxImageBytes      = uint64(128 * 1024 * 1024 * 1024)
	maxCatalogLifetime = 366 * 24 * time.Hour
)

var imageIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// Catalog is a signed collection of downloadable installation images.
// The detached Ed25519 signature covers the exact JSON bytes, not a
// re-serialized representation.
type Catalog struct {
	Schema    int     `json:"schema"`
	Generated string  `json:"generated"`
	Expires   string  `json:"expires"`
	Images    []Image `json:"images"`
}

// Image identifies one immutable download. RedirectHosts are additional
// HTTPS hosts to which the signed URL may redirect (for example a CDN).
type Image struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Version       string   `json:"version"`
	Architecture  string   `json:"architecture"`
	Filename      string   `json:"filename"`
	URL           string   `json:"url"`
	SHA256        string   `json:"sha256"`
	Size          uint64   `json:"size"`
	RedirectHosts []string `json:"redirect_hosts,omitempty"`
}

// VerifiedCatalog carries parsed timestamps and the digest of the exact
// authenticated catalog bytes.
type VerifiedCatalog struct {
	Catalog
	GeneratedAt time.Time `json:"generated_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	SHA256      string    `json:"sha256"`
}

func VerifyCatalog(catalogBytes, signatureBytes, publicKeyBytes []byte, now time.Time) (*VerifiedCatalog, error) {
	if len(catalogBytes) == 0 {
		return nil, errors.New("catalog is empty")
	}
	if len(catalogBytes) > MaxCatalogBytes {
		return nil, fmt.Errorf("catalog exceeds the %d-byte limit", MaxCatalogBytes)
	}
	publicKey, err := DecodePublicKey(publicKeyBytes)
	if err != nil {
		return nil, err
	}
	signature, err := DecodeSignature(signatureBytes)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(publicKey, catalogBytes, signature) {
		return nil, errors.New("catalog signature verification failed")
	}
	catalog, generated, expires, err := parseCatalog(catalogBytes, now)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(catalogBytes)
	return &VerifiedCatalog{
		Catalog:     catalog,
		GeneratedAt: generated,
		ExpiresAt:   expires,
		SHA256:      hex.EncodeToString(digest[:]),
	}, nil
}

func DecodePublicKey(data []byte) (ed25519.PublicKey, error) {
	decoded, err := decodeFixed(data, ed25519.PublicKeySize, "Ed25519 public key")
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(decoded), nil
}

func DecodeSignature(data []byte) ([]byte, error) {
	return decodeFixed(data, ed25519.SignatureSize, "Ed25519 signature")
}

func decodeFixed(data []byte, size int, label string) ([]byte, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == size {
		return append([]byte(nil), trimmed...), nil
	}
	for _, decode := range []func(string) ([]byte, error){
		func(value string) ([]byte, error) { return hex.DecodeString(value) },
		func(value string) ([]byte, error) { return base64.StdEncoding.DecodeString(value) },
		func(value string) ([]byte, error) { return base64.RawStdEncoding.DecodeString(value) },
	} {
		value, err := decode(string(trimmed))
		if err == nil && len(value) == size {
			return value, nil
		}
	}
	return nil, fmt.Errorf("%s must be %d raw bytes, hex, or base64", label, size)
}

func parseCatalog(data []byte, now time.Time) (Catalog, time.Time, time.Time, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var catalog Catalog
	if err := decoder.Decode(&catalog); err != nil {
		return Catalog{}, time.Time{}, time.Time{}, fmt.Errorf("parse catalog: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Catalog{}, time.Time{}, time.Time{}, errors.New("catalog contains trailing JSON data")
	}
	if catalog.Schema != SchemaVersion {
		return Catalog{}, time.Time{}, time.Time{}, fmt.Errorf("unsupported catalog schema %d", catalog.Schema)
	}
	generated, err := time.Parse(time.RFC3339, catalog.Generated)
	if err != nil {
		return Catalog{}, time.Time{}, time.Time{}, fmt.Errorf("invalid generated timestamp: %w", err)
	}
	expires, err := time.Parse(time.RFC3339, catalog.Expires)
	if err != nil {
		return Catalog{}, time.Time{}, time.Time{}, fmt.Errorf("invalid expiry timestamp: %w", err)
	}
	generated, expires = generated.UTC(), expires.UTC()
	if !expires.After(generated) {
		return Catalog{}, time.Time{}, time.Time{}, errors.New("catalog expiry must be after its generation time")
	}
	if expires.Sub(generated) > maxCatalogLifetime {
		return Catalog{}, time.Time{}, time.Time{}, errors.New("catalog validity period is unreasonably long")
	}
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	if generated.After(now.Add(24 * time.Hour)) {
		return Catalog{}, time.Time{}, time.Time{}, errors.New("catalog generation time is too far in the future")
	}
	if !expires.After(now) {
		return Catalog{}, time.Time{}, time.Time{}, errors.New("catalog has expired")
	}
	if len(catalog.Images) == 0 {
		return Catalog{}, time.Time{}, time.Time{}, errors.New("catalog contains no images")
	}
	if len(catalog.Images) > MaxCatalogEntries {
		return Catalog{}, time.Time{}, time.Time{}, fmt.Errorf("catalog contains more than %d images", MaxCatalogEntries)
	}
	seenIDs := make(map[string]struct{}, len(catalog.Images))
	for i := range catalog.Images {
		if err := catalog.Images[i].validate(); err != nil {
			return Catalog{}, time.Time{}, time.Time{}, fmt.Errorf("image %d: %w", i+1, err)
		}
		if _, exists := seenIDs[catalog.Images[i].ID]; exists {
			return Catalog{}, time.Time{}, time.Time{}, fmt.Errorf("duplicate image id %q", catalog.Images[i].ID)
		}
		seenIDs[catalog.Images[i].ID] = struct{}{}
	}
	sort.SliceStable(catalog.Images, func(i, j int) bool { return catalog.Images[i].ID < catalog.Images[j].ID })
	return catalog, generated, expires, nil
}

func (image *Image) validate() error {
	return image.validateWithPolicy(false)
}

func (image *Image) validateWithPolicy(allowHTTP bool) error {
	image.ID = strings.ToLower(strings.TrimSpace(image.ID))
	image.Name = strings.TrimSpace(image.Name)
	image.Version = strings.TrimSpace(image.Version)
	image.Architecture = strings.ToLower(strings.TrimSpace(image.Architecture))
	image.Filename = strings.TrimSpace(image.Filename)
	image.URL = strings.TrimSpace(image.URL)
	image.SHA256 = strings.ToLower(strings.TrimSpace(image.SHA256))
	if !imageIDPattern.MatchString(image.ID) {
		return errors.New("id must use lowercase letters, numbers, dots, underscores, or hyphens")
	}
	if image.Name == "" || len(image.Name) > 160 || hasControl(image.Name) {
		return errors.New("name is empty, too long, or contains control characters")
	}
	if image.Version == "" || len(image.Version) > 80 || hasControl(image.Version) {
		return errors.New("version is empty, too long, or contains control characters")
	}
	if image.Architecture == "" || len(image.Architecture) > 32 || strings.ContainsAny(image.Architecture, " /\\") {
		return errors.New("architecture is invalid")
	}
	if err := validateFilename(image.Filename); err != nil {
		return err
	}
	parsed, err := validateImageURL(image.URL, allowHTTP)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}
	image.URL = parsed.String()
	if _, err := hex.DecodeString(image.SHA256); err != nil || len(image.SHA256) != sha256.Size*2 {
		return errors.New("sha256 must be a 64-character hexadecimal digest")
	}
	if image.Size == 0 || image.Size > MaxImageBytes {
		return fmt.Errorf("size must be between 1 byte and %d bytes", MaxImageBytes)
	}
	seenHosts := map[string]struct{}{strings.ToLower(parsed.Hostname()): {}}
	for i, host := range image.RedirectHosts {
		host = strings.ToLower(strings.TrimSpace(host))
		if err := validateHostname(host); err != nil {
			return fmt.Errorf("redirect_hosts[%d]: %w", i, err)
		}
		if _, exists := seenHosts[host]; exists {
			return fmt.Errorf("duplicate redirect host %q", host)
		}
		seenHosts[host] = struct{}{}
		image.RedirectHosts[i] = host
	}
	return nil
}

func validateFilename(name string) error {
	if name == "" || name == "." || name == ".." || len(name) > 255 || hasControl(name) {
		return errors.New("filename is empty, unsafe, or too long")
	}
	if filepath.Base(name) != name || strings.ContainsAny(name, `/\\`) {
		return errors.New("filename must not contain a path")
	}
	return nil
}

func validateImageURL(value string, allowHTTP bool) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, err
	}
	host := strings.ToLower(parsed.Hostname())
	if parsed.Hostname() == "" || (parsed.Scheme != "https" && !(allowHTTP && parsed.Scheme == "http" && isLoopbackHost(host))) {
		return nil, errors.New("only absolute HTTPS URLs are allowed")
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return nil, errors.New("URL user information and fragments are not allowed")
	}
	if parsed.Scheme == "https" {
		if err := validateHostname(host); err != nil {
			return nil, err
		}
	}
	return parsed, nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validateHostname(host string) error {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " /\\@") {
		return errors.New("hostname is invalid")
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() {
			return errors.New("private, loopback, unspecified, or multicast hosts are not allowed")
		}
		return nil
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") {
		return errors.New("local hostnames are not allowed")
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return errors.New("hostname must be a fully qualified DNS name")
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return errors.New("hostname is invalid")
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z') && !(char >= '0' && char <= '9') && char != '-' {
				return errors.New("hostname is invalid")
			}
		}
	}
	return nil
}

func hasControl(value string) bool {
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return true
		}
	}
	return false
}

func (catalog *VerifiedCatalog) Find(id string) (Image, error) {
	id = strings.ToLower(strings.TrimSpace(id))
	for _, image := range catalog.Images {
		if image.ID == id {
			return image, nil
		}
	}
	return Image{}, fmt.Errorf("catalog image %q was not found", id)
}
