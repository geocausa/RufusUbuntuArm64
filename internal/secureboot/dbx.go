package secureboot

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	maxDBXDownload       = int64(64 * 1024 * 1024)
	maxSignatureListSize = uint32(64 * 1024 * 1024)
)

var (
	// EFI_CERT_SHA256_GUID = c1c41626-504c-4092-aca9-41f936934328
	certSHA256GUID = GUID{0xc1c41626, 0x504c, 0x4092, [8]byte{0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28}}
	// EFI_CERT_X509_GUID = a5c059a1-94e4-4aa7-87b5-ab155c2bf072
	certX509GUID = GUID{0xa5c059a1, 0x94e4, 0x4aa7, [8]byte{0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72}}
	// EFI_CERT_TYPE_PKCS7_GUID = 4aafd29d-68df-49ee-8aa9-347d375665a7
	certPKCS7GUID = GUID{0x4aafd29d, 0x68df, 0x49ee, [8]byte{0x8a, 0xa9, 0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7}}
)

type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

func (g GUID) String() string {
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		g.Data1, g.Data2, g.Data3,
		g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3], g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7])
}

func parseGUID(data []byte) (GUID, error) {
	if len(data) < 16 {
		return GUID{}, io.ErrUnexpectedEOF
	}
	var tail [8]byte
	copy(tail[:], data[8:16])
	return GUID{
		Data1: binary.LittleEndian.Uint32(data[0:4]),
		Data2: binary.LittleEndian.Uint16(data[4:6]),
		Data3: binary.LittleEndian.Uint16(data[6:8]),
		Data4: tail,
	}, nil
}

type Signature struct {
	Type  GUID
	Owner GUID
	Data  []byte
}

type Database struct {
	Source             string
	Authenticated      bool
	Timestamp          *time.Time
	PayloadOffset      int
	SHA256             map[[sha256.Size]byte]struct{}
	X509Certificates   [][]byte
	X509               map[[sha256.Size]byte]struct{}
	OtherSignatures    []Signature
	SignatureListCount int
	SignatureCount     int
	FileSHA256         string
}

type Summary struct {
	Source           string `json:"source"`
	Authenticated    bool   `json:"authenticated_update_format"`
	Timestamp        string `json:"timestamp,omitempty"`
	SignatureLists   int    `json:"signature_lists"`
	Signatures       int    `json:"signatures"`
	SHA256Hashes     int    `json:"sha256_hashes"`
	X509Certificates int    `json:"x509_certificates"`
	OtherSignatures  int    `json:"other_signatures"`
	FileSHA256       string `json:"file_sha256"`
}

func (d *Database) Summary() Summary {
	result := Summary{
		Source:           d.Source,
		Authenticated:    d.Authenticated,
		SignatureLists:   d.SignatureListCount,
		Signatures:       d.SignatureCount,
		SHA256Hashes:     len(d.SHA256),
		X509Certificates: len(d.X509Certificates),
		OtherSignatures:  len(d.OtherSignatures),
		FileSHA256:       d.FileSHA256,
	}
	if d.Timestamp != nil {
		result.Timestamp = d.Timestamp.UTC().Format(time.RFC3339)
	}
	return result
}

func Parse(data []byte, source string) (*Database, error) {
	if len(data) < 28 {
		return nil, errors.New("DBX data is too small")
	}
	sum := sha256.Sum256(data)
	db := &Database{Source: source, SHA256: make(map[[sha256.Size]byte]struct{}), X509: make(map[[sha256.Size]byte]struct{}), FileSHA256: hex.EncodeToString(sum[:])}
	payload := data

	// A Microsoft DBXUpdate.bin uses the EFI_VARIABLE_AUTHENTICATION_2 structure:
	// EFI_TIME (16 bytes), followed by WIN_CERTIFICATE_UEFI_GUID whose dwLength
	// includes its 24-byte header. Firmware efivar data contains raw ESLs and
	// therefore begins directly with an EFI_SIGNATURE_LIST.
	if timestamp, ok := parseEFITime(data[:16]); ok && len(data) >= 40 {
		certLength := binary.LittleEndian.Uint32(data[16:20])
		revision := binary.LittleEndian.Uint16(data[20:22])
		certType := binary.LittleEndian.Uint16(data[22:24])
		certGUID, guidErr := parseGUID(data[24:40])
		end := 16 + int(certLength)
		if guidErr == nil && certLength >= 24 && end <= len(data) && revision == 0x0200 && certType == 0x0ef1 && certGUID == certPKCS7GUID {
			db.Authenticated = true
			db.Timestamp = &timestamp
			db.PayloadOffset = end
			payload = data[end:]
		}
	}
	if err := parseSignatureLists(payload, db); err != nil {
		return nil, err
	}
	if db.SignatureCount == 0 {
		return nil, errors.New("DBX contains no EFI signatures")
	}
	return db, nil
}

func ParseFile(path string) (*Database, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read DBX file: %w", err)
	}
	return Parse(data, path)
}

func parseSignatureLists(payload []byte, db *Database) error {
	offset := 0
	for offset < len(payload) {
		if len(payload)-offset < 28 {
			// Authenticated payloads may carry alignment padding. Only accept
			// an all-zero tail; non-zero bytes indicate a malformed structure.
			if allZero(payload[offset:]) {
				return nil
			}
			return fmt.Errorf("truncated EFI signature list at offset %d", offset)
		}
		typ, err := parseGUID(payload[offset : offset+16])
		if err != nil {
			return err
		}
		listSize := binary.LittleEndian.Uint32(payload[offset+16 : offset+20])
		headerSize := binary.LittleEndian.Uint32(payload[offset+20 : offset+24])
		signatureSize := binary.LittleEndian.Uint32(payload[offset+24 : offset+28])
		if listSize < 28 || listSize > maxSignatureListSize || int(listSize) > len(payload)-offset {
			return fmt.Errorf("invalid EFI signature-list size %d at offset %d", listSize, offset)
		}
		if headerSize > listSize-28 || signatureSize < 16 {
			return fmt.Errorf("invalid EFI signature-list header/signature size at offset %d", offset)
		}
		entriesBytes := listSize - 28 - headerSize
		if entriesBytes%signatureSize != 0 {
			return fmt.Errorf("EFI signature-list entries are not aligned at offset %d", offset)
		}
		entryOffset := offset + 28 + int(headerSize)
		entries := int(entriesBytes / signatureSize)
		db.SignatureListCount++
		for i := 0; i < entries; i++ {
			entry := payload[entryOffset+i*int(signatureSize) : entryOffset+(i+1)*int(signatureSize)]
			owner, err := parseGUID(entry[:16])
			if err != nil {
				return err
			}
			value := append([]byte(nil), entry[16:]...)
			db.SignatureCount++
			switch {
			case typ == certSHA256GUID && len(value) == sha256.Size:
				var digest [sha256.Size]byte
				copy(digest[:], value)
				db.SHA256[digest] = struct{}{}
			case typ == certX509GUID:
				db.X509Certificates = append(db.X509Certificates, value)
				db.X509[sha256.Sum256(value)] = struct{}{}
			default:
				db.OtherSignatures = append(db.OtherSignatures, Signature{Type: typ, Owner: owner, Data: value})
			}
		}
		offset += int(listSize)
	}
	return nil
}

func parseEFITime(data []byte) (time.Time, bool) {
	if len(data) < 16 {
		return time.Time{}, false
	}
	year := int(binary.LittleEndian.Uint16(data[0:2]))
	month, day := time.Month(data[2]), int(data[3])
	hour, minute, second := int(data[4]), int(data[5]), int(data[6])
	if year < 1998 || year > 9999 || month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 60 {
		return time.Time{}, false
	}
	nanosecond := int(binary.LittleEndian.Uint32(data[8:12]))
	if nanosecond < 0 || nanosecond >= 1_000_000_000 {
		return time.Time{}, false
	}
	return time.Date(year, month, day, hour, minute, second, nanosecond, time.UTC), true
}

func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

func FirmwareDBX() (*Database, error) {
	paths, err := filepath.Glob("/sys/firmware/efi/efivars/dbx-*")
	if err != nil {
		return nil, fmt.Errorf("locate firmware DBX variable: %w", err)
	}
	if len(paths) == 0 {
		return nil, errors.New("firmware DBX variable is unavailable; the system may not be booted in UEFI mode or efivarfs may not be mounted")
	}
	sort.Strings(paths)
	data, err := os.ReadFile(paths[0])
	if err != nil {
		return nil, fmt.Errorf("read firmware DBX variable: %w", err)
	}
	if len(data) <= 4 {
		return nil, errors.New("firmware DBX variable is empty")
	}
	return Parse(data[4:], paths[0]) // efivarfs prepends uint32 attributes.
}

func ArchitectureName(value string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" || normalized == "native" || normalized == "auto" {
		normalized = runtime.GOARCH
	}
	switch normalized {
	case "386", "i386", "i686", "x86":
		return "x86", nil
	case "amd64", "x86_64", "x64":
		return "amd64", nil
	case "arm", "arm32":
		return "arm", nil
	case "arm64", "aarch64":
		return "arm64", nil
	case "ia64":
		return "ia64", nil
	default:
		return "", fmt.Errorf("unsupported DBX architecture %q", value)
	}
}

func MicrosoftDBXURL(arch string) (string, error) {
	normalized, err := ArchitectureName(arch)
	if err != nil {
		return "", err
	}
	return "https://raw.githubusercontent.com/microsoft/secureboot_objects/main/PostSignedObjects/DBX/" + normalized + "/DBXUpdate.bin", nil
}

type DownloadResult struct {
	Path    string  `json:"path"`
	URL     string  `json:"url"`
	SHA256  string  `json:"sha256"`
	Summary Summary `json:"summary"`
}

func DownloadMicrosoftDBX(ctx context.Context, arch, destination string) (DownloadResult, error) {
	url, err := MicrosoftDBXURL(arch)
	if err != nil {
		return DownloadResult{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return DownloadResult{}, err
	}
	request.Header.Set("User-Agent", "RufusArm64-secureboot/1")
	client := &http.Client{
		Timeout: 60 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many DBX download redirects")
			}
			host := strings.ToLower(req.URL.Hostname())
			if host != "raw.githubusercontent.com" && host != "github.com" && host != "objects.githubusercontent.com" {
				return fmt.Errorf("refusing DBX redirect to untrusted host %q", host)
			}
			return nil
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return DownloadResult{}, fmt.Errorf("download Microsoft DBX: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return DownloadResult{}, fmt.Errorf("download Microsoft DBX: HTTP %s", response.Status)
	}
	limited := io.LimitReader(response.Body, maxDBXDownload+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return DownloadResult{}, fmt.Errorf("read Microsoft DBX response: %w", err)
	}
	if int64(len(data)) > maxDBXDownload {
		return DownloadResult{}, errors.New("Microsoft DBX response is unexpectedly large")
	}
	db, err := Parse(data, url)
	if err != nil {
		return DownloadResult{}, fmt.Errorf("validate downloaded Microsoft DBX: %w", err)
	}
	if !db.Authenticated {
		return DownloadResult{}, errors.New("downloaded DBX does not use the authenticated UEFI variable-update format")
	}
	if destination == "" {
		cacheRoot, err := os.UserCacheDir()
		if err != nil {
			return DownloadResult{}, fmt.Errorf("locate user cache: %w", err)
		}
		normalized, _ := ArchitectureName(arch)
		destination = filepath.Join(cacheRoot, "rufusarm64", "dbx", normalized+"-DBXUpdate.bin")
	}
	destination, err = filepath.Abs(destination)
	if err != nil {
		return DownloadResult{}, fmt.Errorf("resolve DBX destination: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return DownloadResult{}, fmt.Errorf("create DBX cache directory: %w", err)
	}
	temp, err := os.CreateTemp(filepath.Dir(destination), ".dbx-download-")
	if err != nil {
		return DownloadResult{}, fmt.Errorf("create DBX temporary file: %w", err)
	}
	tempName := temp.Name()
	cleanup := func() { temp.Close(); os.Remove(tempName) }
	if err := temp.Chmod(0o600); err != nil {
		cleanup()
		return DownloadResult{}, err
	}
	if _, err := temp.Write(data); err != nil {
		cleanup()
		return DownloadResult{}, fmt.Errorf("write DBX temporary file: %w", err)
	}
	if err := temp.Sync(); err != nil {
		cleanup()
		return DownloadResult{}, fmt.Errorf("sync DBX temporary file: %w", err)
	}
	if err := temp.Close(); err != nil {
		os.Remove(tempName)
		return DownloadResult{}, fmt.Errorf("close DBX temporary file: %w", err)
	}
	if err := os.Rename(tempName, destination); err != nil {
		os.Remove(tempName)
		return DownloadResult{}, fmt.Errorf("install DBX cache: %w", err)
	}
	return DownloadResult{Path: destination, URL: url, SHA256: db.FileSHA256, Summary: db.Summary()}, nil
}

func MarshalSummary(db *Database) ([]byte, error) {
	return json.MarshalIndent(db.Summary(), "", "  ")
}

func (d *Database) IsX509Revoked(certificateDER []byte) bool {
	if d == nil || len(certificateDER) == 0 {
		return false
	}
	_, ok := d.X509[sha256.Sum256(certificateDER)]
	return ok
}

func (d *Database) IsSHA256Revoked(digest [sha256.Size]byte) bool {
	if d == nil {
		return false
	}
	_, ok := d.SHA256[digest]
	return ok
}

func Merge(databases ...*Database) *Database {
	merged := &Database{Source: "merged", SHA256: make(map[[sha256.Size]byte]struct{}), X509: make(map[[sha256.Size]byte]struct{})}
	seenX509 := make(map[[sha256.Size]byte]struct{})
	for _, db := range databases {
		if db == nil {
			continue
		}
		merged.SignatureListCount += db.SignatureListCount
		merged.SignatureCount += db.SignatureCount
		for digest := range db.SHA256 {
			merged.SHA256[digest] = struct{}{}
		}
		for _, cert := range db.X509Certificates {
			digest := sha256.Sum256(cert)
			if _, exists := seenX509[digest]; !exists {
				seenX509[digest] = struct{}{}
				merged.X509Certificates = append(merged.X509Certificates, append([]byte(nil), cert...))
				merged.X509[digest] = struct{}{}
			}
		}
		merged.OtherSignatures = append(merged.OtherSignatures, db.OtherSignatures...)
	}
	return merged
}

func EqualPayload(a, b *Database) bool {
	if a == nil || b == nil || len(a.SHA256) != len(b.SHA256) || len(a.X509Certificates) != len(b.X509Certificates) {
		return false
	}
	for digest := range a.SHA256 {
		if _, ok := b.SHA256[digest]; !ok {
			return false
		}
	}
	certs := func(values [][]byte) map[[sha256.Size]byte]struct{} {
		result := make(map[[sha256.Size]byte]struct{}, len(values))
		for _, value := range values {
			result[sha256.Sum256(value)] = struct{}{}
		}
		return result
	}
	ac, bc := certs(a.X509Certificates), certs(b.X509Certificates)
	if len(ac) != len(bc) {
		return false
	}
	for digest := range ac {
		if _, ok := bc[digest]; !ok {
			return false
		}
	}
	return true
}
