package secureboot

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	pe32Magic     = 0x10b
	pe32PlusMagic = 0x20b
	peSectionSize = 40
	maxPEFileSize = int64(2 * 1024 * 1024 * 1024)
)

type PEHash struct {
	SHA256                 string `json:"authenticode_sha256"`
	Machine                uint16 `json:"machine"`
	NumberOfSections       uint16 `json:"number_of_sections"`
	CertificateTableOffset uint32 `json:"certificate_table_offset"`
	CertificateTableSize   uint32 `json:"certificate_table_size"`
}

type peSection struct {
	offset uint32
	size   uint32
}

// AuthenticodeSHA256File computes the PE/COFF image digest used by Secure Boot
// DB/DBX SHA-256 entries. The checksum field, certificate-table directory entry,
// and certificate table itself are omitted according to the Authenticode PE
// hashing algorithm.
func AuthenticodeSHA256File(path string) (PEHash, error) {
	file, err := os.Open(path)
	if err != nil {
		return PEHash{}, fmt.Errorf("open PE image: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return PEHash{}, fmt.Errorf("stat PE image: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxPEFileSize {
		return PEHash{}, errors.New("PE image must be a non-empty regular file smaller than 2 GiB")
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return PEHash{}, fmt.Errorf("read PE image: %w", err)
	}
	return AuthenticodeSHA256(data)
}

func AuthenticodeSHA256(data []byte) (PEHash, error) {
	if len(data) < 0x40 || data[0] != 'M' || data[1] != 'Z' {
		return PEHash{}, errors.New("file is not a PE/COFF image")
	}
	peOffset := int(binary.LittleEndian.Uint32(data[0x3c:0x40]))
	if peOffset < 0x40 || peOffset > len(data)-24 || !bytes.Equal(data[peOffset:peOffset+4], []byte{'P', 'E', 0, 0}) {
		return PEHash{}, errors.New("invalid PE header offset or signature")
	}
	coff := peOffset + 4
	machine := binary.LittleEndian.Uint16(data[coff : coff+2])
	sectionsCount := binary.LittleEndian.Uint16(data[coff+2 : coff+4])
	optionalSize := int(binary.LittleEndian.Uint16(data[coff+16 : coff+18]))
	optional := coff + 20
	if optionalSize < 96 || optional > len(data)-optionalSize {
		return PEHash{}, errors.New("invalid PE optional-header size")
	}
	magic := binary.LittleEndian.Uint16(data[optional : optional+2])
	var dataDirectoryOffset, numberOfDirectoriesOffset int
	switch magic {
	case pe32Magic:
		dataDirectoryOffset = optional + 96
		numberOfDirectoriesOffset = optional + 92
	case pe32PlusMagic:
		dataDirectoryOffset = optional + 112
		numberOfDirectoriesOffset = optional + 108
	default:
		return PEHash{}, fmt.Errorf("unsupported PE optional-header magic 0x%x", magic)
	}
	checksumOffset := optional + 64
	sizeOfHeadersOffset := optional + 60
	if checksumOffset+4 > optional+optionalSize || sizeOfHeadersOffset+4 > optional+optionalSize || numberOfDirectoriesOffset+4 > optional+optionalSize {
		return PEHash{}, errors.New("truncated PE optional header")
	}
	numberOfDirectories := binary.LittleEndian.Uint32(data[numberOfDirectoriesOffset : numberOfDirectoriesOffset+4])
	if numberOfDirectories <= 4 || dataDirectoryOffset+5*8 > optional+optionalSize {
		return PEHash{}, errors.New("PE image has no certificate-table directory entry")
	}
	certDirectoryOffset := dataDirectoryOffset + 4*8
	certificateOffset := binary.LittleEndian.Uint32(data[certDirectoryOffset : certDirectoryOffset+4])
	certificateSize := binary.LittleEndian.Uint32(data[certDirectoryOffset+4 : certDirectoryOffset+8])
	if certificateSize > 0 {
		end := uint64(certificateOffset) + uint64(certificateSize)
		if certificateOffset == 0 || end > uint64(len(data)) || end < uint64(certificateOffset) {
			return PEHash{}, errors.New("invalid PE certificate-table extent")
		}
	}
	sizeOfHeaders := binary.LittleEndian.Uint32(data[sizeOfHeadersOffset : sizeOfHeadersOffset+4])
	if sizeOfHeaders == 0 || uint64(sizeOfHeaders) > uint64(len(data)) || int(sizeOfHeaders) < certDirectoryOffset+8 {
		return PEHash{}, errors.New("invalid PE SizeOfHeaders")
	}

	sectionTable := optional + optionalSize
	sectionTableBytes := int(sectionsCount) * peSectionSize
	if sectionsCount > 4096 || sectionTable > len(data)-sectionTableBytes {
		return PEHash{}, errors.New("invalid or truncated PE section table")
	}
	sections := make([]peSection, 0, sectionsCount)
	for index := 0; index < int(sectionsCount); index++ {
		entry := data[sectionTable+index*peSectionSize : sectionTable+(index+1)*peSectionSize]
		size := binary.LittleEndian.Uint32(entry[16:20])
		offset := binary.LittleEndian.Uint32(entry[20:24])
		if size == 0 {
			continue
		}
		end := uint64(offset) + uint64(size)
		if offset == 0 || end > uint64(len(data)) || end < uint64(offset) {
			return PEHash{}, fmt.Errorf("invalid PE section %d extent", index)
		}
		sections = append(sections, peSection{offset: offset, size: size})
	}
	sort.Slice(sections, func(i, j int) bool { return sections[i].offset < sections[j].offset })
	for index := 1; index < len(sections); index++ {
		previousEnd := uint64(sections[index-1].offset) + uint64(sections[index-1].size)
		if uint64(sections[index].offset) < previousEnd {
			return PEHash{}, errors.New("overlapping PE sections are unsupported")
		}
	}

	hash := sha256.New()
	hash.Write(data[:checksumOffset])
	hash.Write(data[checksumOffset+4 : certDirectoryOffset])
	hash.Write(data[certDirectoryOffset+8 : int(sizeOfHeaders)])

	var sumOfBytesHashed uint64 = uint64(sizeOfHeaders)
	for _, section := range sections {
		hash.Write(data[section.offset : uint64(section.offset)+uint64(section.size)])
		sumOfBytesHashed += uint64(section.size)
	}
	if sumOfBytesHashed > uint64(len(data)) {
		return PEHash{}, errors.New("PE section sizes exceed file size")
	}

	// Authenticode normally places the certificate table at the end. Hash any
	// remaining overlay bytes while excluding only the certificate table. This
	// also handles files that carry data after the certificate table.
	overlayStart := sumOfBytesHashed
	certStart := uint64(certificateOffset)
	certEnd := certStart + uint64(certificateSize)
	if certificateSize == 0 {
		hash.Write(data[overlayStart:])
	} else {
		if certStart < overlayStart {
			// A certificate table may not overlap headers or section data.
			return PEHash{}, errors.New("PE certificate table overlaps hashed image data")
		}
		hash.Write(data[overlayStart:certStart])
		if certEnd < uint64(len(data)) {
			hash.Write(data[certEnd:])
		}
	}
	digest := hash.Sum(nil)
	return PEHash{
		SHA256:                 hex.EncodeToString(digest),
		Machine:                machine,
		NumberOfSections:       sectionsCount,
		CertificateTableOffset: certificateOffset,
		CertificateTableSize:   certificateSize,
	}, nil
}

type CheckResult struct {
	Path                   string   `json:"path"`
	AuthenticodeSHA256     string   `json:"authenticode_sha256,omitempty"`
	Machine                uint16   `json:"machine,omitempty"`
	DirectHashRevoked      bool     `json:"direct_hash_revoked"`
	X509CertificateRevoked bool     `json:"x509_certificate_revoked"`
	X509RevocationChecked  bool     `json:"x509_revocation_checked"`
	EmbeddedCertificates   int      `json:"embedded_certificates"`
	RevokedCertificates    []string `json:"revoked_certificates,omitempty"`
	Error                  string   `json:"error,omitempty"`
}

func CheckPEFile(path string, db *Database) CheckResult {
	result := CheckResult{Path: path}
	peHash, err := AuthenticodeSHA256File(path)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.AuthenticodeSHA256 = peHash.SHA256
	result.Machine = peHash.Machine
	digestBytes, err := hex.DecodeString(peHash.SHA256)
	if err == nil && len(digestBytes) == sha256.Size {
		var digest [sha256.Size]byte
		copy(digest[:], digestBytes)
		result.DirectHashRevoked = db.IsSHA256Revoked(digest)
	}
	certificates, certErr := EmbeddedAuthenticodeCertificates(path)
	if certErr != nil {
		// The direct image hash remains useful even when a malformed certificate
		// table prevents certificate-based checking. Surface the distinction.
		result.Error = certErr.Error()
		return result
	}
	result.X509RevocationChecked = true
	result.EmbeddedCertificates = len(certificates)
	for _, certificate := range certificates {
		if db.IsX509Revoked(certificate.Raw) {
			result.X509CertificateRevoked = true
			name := strings.TrimSpace(certificate.Subject.String())
			if name == "" {
				name = certificate.SerialNumber.String()
			}
			result.RevokedCertificates = append(result.RevokedCertificates, name)
		}
	}
	return result
}

// EmbeddedAuthenticodeCertificates returns the X.509 certificates carried in
// WIN_CERTIFICATE PKCS#7 records. Secure Boot DBX X.509 entries revoke exact
// certificates; matching the DER bytes catches a revoked signer or chain
// certificate embedded in the Authenticode signature. This deliberately does
// not claim full path building or online revocation checking.
func EmbeddedAuthenticodeCertificates(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read PE image certificates: %w", err)
	}
	hashInfo, err := AuthenticodeSHA256(data)
	if err != nil {
		return nil, err
	}
	if hashInfo.CertificateTableSize == 0 {
		return nil, nil
	}
	start := int(hashInfo.CertificateTableOffset)
	end := start + int(hashInfo.CertificateTableSize)
	if start < 0 || end < start || end > len(data) {
		return nil, errors.New("invalid PE certificate table")
	}
	var result []*x509.Certificate
	for offset := start; offset < end; {
		if end-offset < 8 {
			if allZeroBytes(data[offset:end]) {
				break
			}
			return nil, errors.New("truncated WIN_CERTIFICATE record")
		}
		length := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
		certificateType := binary.LittleEndian.Uint16(data[offset+6 : offset+8])
		if length < 8 || offset+length > end {
			return nil, errors.New("invalid WIN_CERTIFICATE length")
		}
		if certificateType == 0x0002 {
			certs, err := parsePKCS7Certificates(data[offset+8 : offset+length])
			if err != nil {
				return nil, fmt.Errorf("parse Authenticode PKCS#7 certificates: %w", err)
			}
			result = append(result, certs...)
		}
		offset += (length + 7) &^ 7
	}
	return result, nil
}

var oidPKCS7SignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

func parsePKCS7Certificates(data []byte) ([]*x509.Certificate, error) {
	var contentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
	}
	rest, err := asn1.Unmarshal(data, &contentInfo)
	if err != nil {
		return nil, err
	}
	if len(bytes.Trim(rest, "\x00")) != 0 {
		return nil, errors.New("unexpected data after PKCS#7 ContentInfo")
	}
	if !contentInfo.ContentType.Equal(oidPKCS7SignedData) || len(contentInfo.Content.Bytes) == 0 {
		return nil, errors.New("certificate table does not contain PKCS#7 SignedData")
	}
	var signedData asn1.RawValue
	if _, err := asn1.Unmarshal(contentInfo.Content.Bytes, &signedData); err != nil {
		return nil, err
	}
	if signedData.Tag != asn1.TagSequence || !signedData.IsCompound {
		return nil, errors.New("invalid PKCS#7 SignedData sequence")
	}
	remaining := signedData.Bytes
	// version, digestAlgorithms, encapContentInfo
	for index := 0; index < 3; index++ {
		var field asn1.RawValue
		var err error
		remaining, err = asn1.Unmarshal(remaining, &field)
		if err != nil {
			return nil, errors.New("truncated PKCS#7 SignedData")
		}
	}
	var certificates []*x509.Certificate
	for len(remaining) > 0 {
		var field asn1.RawValue
		next, err := asn1.Unmarshal(remaining, &field)
		if err != nil {
			return nil, err
		}
		remaining = next
		if field.Class != asn1.ClassContextSpecific || field.Tag != 0 {
			continue
		}
		choices := field.Bytes
		for len(choices) > 0 {
			var choice asn1.RawValue
			choices, err = asn1.Unmarshal(choices, &choice)
			if err != nil {
				return nil, err
			}
			if choice.Class != asn1.ClassUniversal || choice.Tag != asn1.TagSequence {
				continue // ExtendedCertificate/attribute-certificate choices.
			}
			certificate, err := x509.ParseCertificate(choice.FullBytes)
			if err != nil {
				return nil, err
			}
			certificates = append(certificates, certificate)
		}
		break
	}
	return certificates, nil
}

func allZeroBytes(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

func ScanEFIDirectory(root string, db *Database, maxFiles int) ([]CheckResult, error) {
	if maxFiles <= 0 {
		maxFiles = 512
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	var paths []string
	err = filepath.WalkDir(absolute, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		name := strings.ToLower(entry.Name())
		if strings.HasSuffix(name, ".efi") || name == "bootmgr" {
			paths = append(paths, path)
			if len(paths) > maxFiles {
				return fmt.Errorf("more than %d EFI boot files found; refusing an unbounded scan", maxFiles)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	results := make([]CheckResult, 0, len(paths))
	for _, path := range paths {
		result := CheckPEFile(path, db)
		if relative, err := filepath.Rel(absolute, path); err == nil {
			result.Path = filepath.ToSlash(relative)
		}
		results = append(results, result)
	}
	return results, nil
}
