package ffu

import (
	"context"
	"crypto/sha1" // #nosec G505 -- SHA-1 is the explicitly encoded legacy Windows catalog member digest, not a new trust primitive.
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"strings"
	"time"
)

const (
	catalogMemberPlanSchema = 1
	maxFFUCatalogBytes      = uint64(16 << 20)
	maxCatalogDERNodes      = 4096
	maxCatalogDERDepth      = 24
	maxCatalogMembers       = 1024
	maxCatalogCertificates  = 32
	maxCatalogSigners       = 8
	maxCatalogAttributes    = 128
)

const (
	oidPKCS7SignedData     = "1.2.840.113549.1.7.2"
	oidMicrosoftCTL        = "1.3.6.1.4.1.311.10.1"
	oidCatalogNameValue    = "1.3.6.1.4.1.311.12.2.1"
	oidSPCIndirectData     = "1.3.6.1.4.1.311.2.1.4"
	oidSHA1                = "1.3.14.3.2.26"
	catalogHashTableMember = "HashTable.blob"
	catalogNameBase64Flag  = uint64(0x00020000)
)

// CatalogCertificate reports embedded certificate metadata only. Parsing an
// embedded certificate never establishes a chain or publisher trust.
type CatalogCertificate struct {
	Index              int    `json:"index"`
	Subject            string `json:"subject"`
	Issuer             string `json:"issuer"`
	SerialNumber       string `json:"serial_number"`
	SHA256             string `json:"sha256"`
	NotBefore          string `json:"not_before"`
	NotAfter           string `json:"not_after"`
	PublicKeyAlgorithm string `json:"public_key_algorithm"`
	SignatureAlgorithm string `json:"signature_algorithm"`
}

// CatalogSigner reports one PKCS#7 SignerInfo structurally. Its cryptographic
// signature is not verified by the member-binding tranche.
type CatalogSigner struct {
	Index                 int      `json:"index"`
	Version               uint64   `json:"version"`
	IdentifierType        string   `json:"identifier_type"`
	IdentifierSHA256      string   `json:"identifier_sha256"`
	DigestAlgorithmOID    string   `json:"digest_algorithm_oid"`
	SignatureAlgorithmOID string   `json:"signature_algorithm_oid"`
	SignedAttributeOIDs   []string `json:"signed_attribute_oids"`
}

// CatalogMemberPlan binds the single supported HashTable.blob catalog member to
// the complete embedded FFU hash table. Signature and trust states deliberately
// remain false even when the member digest matches.
type CatalogMemberPlan struct {
	Schema                         int                  `json:"schema"`
	SourceFileSize                 uint64               `json:"source_file_size"`
	CatalogOffset                  uint64               `json:"catalog_offset"`
	CatalogLength                  uint64               `json:"catalog_length"`
	CatalogSHA256                  string               `json:"catalog_sha256"`
	OuterContentTypeOID            string               `json:"outer_content_type_oid"`
	EncapsulatedContentTypeOID     string               `json:"encapsulated_content_type_oid"`
	CatalogMemberCount             uint64               `json:"catalog_member_count"`
	HashTableMemberName            string               `json:"hash_table_member_name"`
	HashTableMemberDigestAlgorithm string               `json:"hash_table_member_digest_algorithm"`
	HashTableMemberDigestOID       string               `json:"hash_table_member_digest_oid"`
	HashTableMemberDigest          string               `json:"hash_table_member_digest"`
	CalculatedHashTableDigest      string               `json:"calculated_hash_table_digest"`
	HashTableSHA256                string               `json:"hash_table_sha256"`
	HashTableLength                uint64               `json:"hash_table_length"`
	HashTableMemberMatches         bool                 `json:"hash_table_member_matches"`
	SignatureStructureParsed       bool                 `json:"signature_structure_parsed"`
	CryptographicSignatureVerified bool                 `json:"cryptographic_signature_verified"`
	CertificateChainBuilt          bool                 `json:"certificate_chain_built"`
	PublisherTrusted               bool                 `json:"publisher_trusted"`
	HashTableCatalogAuthenticated  bool                 `json:"hash_table_catalog_authenticated"`
	Certificates                   []CatalogCertificate `json:"certificates"`
	Signers                        []CatalogSigner      `json:"signers"`
	PlanSHA256                     string               `json:"plan_sha256"`
	Limitations                    []string             `json:"limitations"`
}

// PlanCatalogMember parses the bounded embedded Windows catalog, requires one
// supported HashTable.blob member, and compares its encoded SHA-1 digest with
// SHA-1 of the complete embedded FFU hash table. It does not verify signatures,
// build a certificate chain, consult trust roots, or access any target.
func PlanCatalogMember(ctx context.Context, reader io.ReaderAt, size uint64) (Inspection, HashTablePlan, CatalogMemberPlan, error) {
	if ctx == nil {
		return Inspection{}, HashTablePlan{}, CatalogMemberPlan{}, errors.New("FFU catalog-member context is nil")
	}
	if err := ctx.Err(); err != nil {
		return Inspection{}, HashTablePlan{}, CatalogMemberPlan{}, err
	}
	inspection, err := Inspect(reader, size)
	if err != nil {
		return Inspection{}, HashTablePlan{}, CatalogMemberPlan{}, err
	}
	if uint64(inspection.Security.CatalogSize) > maxFFUCatalogBytes {
		return inspection, HashTablePlan{}, CatalogMemberPlan{}, fmt.Errorf("FFU catalog length %d exceeds read-only parsing limit %d", inspection.Security.CatalogSize, maxFFUCatalogBytes)
	}
	inspection, hashPlan, err := PlanHashTable(ctx, reader, size)
	if err != nil {
		return inspection, hashPlan, CatalogMemberPlan{}, err
	}
	catalogLength := uint64(inspection.Security.CatalogSize)
	catalogBytes, err := readCatalogRegion(reader, inspection.CatalogOffset, catalogLength)
	if err != nil {
		return inspection, hashPlan, CatalogMemberPlan{}, err
	}
	parsed, err := parseWindowsCatalog(catalogBytes)
	if err != nil {
		return inspection, hashPlan, CatalogMemberPlan{}, err
	}
	calculatedDigest, err := hashFFUTableSHA1(ctx, reader, hashPlan.HashTableOffset, hashPlan.HashTableLength)
	if err != nil {
		return inspection, hashPlan, CatalogMemberPlan{}, fmt.Errorf("hash FFU table for catalog member: %w", err)
	}

	plan := CatalogMemberPlan{
		Schema:                         catalogMemberPlanSchema,
		SourceFileSize:                 size,
		CatalogOffset:                  inspection.CatalogOffset,
		CatalogLength:                  catalogLength,
		CatalogSHA256:                  hashPlan.CatalogSHA256,
		OuterContentTypeOID:            parsed.outerContentTypeOID,
		EncapsulatedContentTypeOID:     parsed.encapsulatedContentTypeOID,
		CatalogMemberCount:             parsed.memberCount,
		HashTableMemberName:            parsed.memberName,
		HashTableMemberDigestAlgorithm: "SHA-1",
		HashTableMemberDigestOID:       parsed.memberDigestOID,
		HashTableMemberDigest:          hex.EncodeToString(parsed.memberDigest),
		CalculatedHashTableDigest:      hex.EncodeToString(calculatedDigest),
		HashTableSHA256:                hashPlan.HashTableSHA256,
		HashTableLength:                hashPlan.HashTableLength,
		SignatureStructureParsed:       true,
		Certificates:                   parsed.certificates,
		Signers:                        parsed.signers,
		Limitations: []string{
			"the catalog member digest is legacy SHA-1 because that is the format encoded by the supported Windows catalog member",
			"matching the member proves catalog-to-table consistency but does not verify the PKCS#7 signature",
			"embedded certificates and signer records are metadata only; no chain or publisher trust policy is applied",
			"no target is accepted and no regular-file, loop-device or physical-device executor exists",
		},
	}
	plan.HashTableMemberMatches = subtle.ConstantTimeCompare(parsed.memberDigest, calculatedDigest) == 1
	plan.HashTableCatalogAuthenticated = plan.HashTableMemberMatches && plan.CryptographicSignatureVerified && plan.CertificateChainBuilt && plan.PublisherTrusted
	plan.PlanSHA256 = catalogMemberPlanDigest(plan)
	if !plan.HashTableMemberMatches {
		return inspection, hashPlan, plan, errors.New("FFU catalog HashTable.blob member digest does not match the embedded hash table")
	}
	return inspection, hashPlan, plan, nil
}

type parsedWindowsCatalog struct {
	outerContentTypeOID        string
	encapsulatedContentTypeOID string
	memberCount                uint64
	memberName                 string
	memberDigestOID            string
	memberDigest               []byte
	certificates               []CatalogCertificate
	signers                    []CatalogSigner
}

type derValue struct {
	class       byte
	tag         byte
	constructed bool
	full        []byte
	content     []byte
}

type derBudget struct {
	nodes int
}

func parseWindowsCatalog(data []byte) (parsedWindowsCatalog, error) {
	if len(data) == 0 {
		return parsedWindowsCatalog{}, errors.New("FFU catalog is empty")
	}
	budget := &derBudget{}
	outer, rest, err := parseDERValue(data, budget)
	if err != nil {
		return parsedWindowsCatalog{}, fmt.Errorf("parse FFU catalog ContentInfo: %w", err)
	}
	if len(rest) != 0 {
		return parsedWindowsCatalog{}, fmt.Errorf("FFU catalog has %d trailing bytes after ContentInfo", len(rest))
	}
	outerChildren, err := requireDERChildren(outer, 0, 16, 2, 2, budget, "catalog ContentInfo")
	if err != nil {
		return parsedWindowsCatalog{}, err
	}
	outerOID, err := requireOID(outerChildren[0], "catalog outer content type")
	if err != nil {
		return parsedWindowsCatalog{}, err
	}
	if outerOID != oidPKCS7SignedData {
		return parsedWindowsCatalog{}, fmt.Errorf("unsupported FFU catalog outer content type %s", outerOID)
	}
	signedExplicit, err := requireContextSingle(outerChildren[1], 0, 1, budget, "catalog signedData")
	if err != nil {
		return parsedWindowsCatalog{}, err
	}
	signedChildren, err := requireDERChildren(signedExplicit, 0, 16, 4, 8, budget, "catalog SignedData")
	if err != nil {
		return parsedWindowsCatalog{}, err
	}
	if _, err := requireNonnegativeInteger(signedChildren[0], "catalog SignedData version"); err != nil {
		return parsedWindowsCatalog{}, err
	}
	if _, err := requireDERChildren(signedChildren[1], 0, 17, 1, 16, budget, "catalog digestAlgorithms"); err != nil {
		return parsedWindowsCatalog{}, err
	}
	encapChildren, err := requireDERChildren(signedChildren[2], 0, 16, 2, 2, budget, "catalog encapContentInfo")
	if err != nil {
		return parsedWindowsCatalog{}, err
	}
	encapOID, err := requireOID(encapChildren[0], "catalog encapsulated content type")
	if err != nil {
		return parsedWindowsCatalog{}, err
	}
	if encapOID != oidMicrosoftCTL {
		return parsedWindowsCatalog{}, fmt.Errorf("unsupported FFU catalog encapsulated content type %s", encapOID)
	}
	ctlValue, err := requireContextSingle(encapChildren[1], 0, 2, budget, "catalog CTL content")
	if err != nil {
		return parsedWindowsCatalog{}, err
	}
	if ctlValue.class == 0 && ctlValue.tag == 4 {
		ctlValue, rest, err = parseDERValue(ctlValue.content, budget)
		if err != nil || len(rest) != 0 {
			return parsedWindowsCatalog{}, errors.New("FFU catalog CTL octet string does not contain exactly one DER value")
		}
	}

	result := parsedWindowsCatalog{
		outerContentTypeOID:        outerOID,
		encapsulatedContentTypeOID: encapOID,
	}
	if err := parseCatalogMembers(ctlValue, budget, &result); err != nil {
		return parsedWindowsCatalog{}, err
	}
	if err := parseSignedDataMetadata(signedChildren[3:], budget, &result); err != nil {
		return parsedWindowsCatalog{}, err
	}
	if result.memberName == "" || len(result.memberDigest) == 0 {
		return parsedWindowsCatalog{}, errors.New("FFU catalog contains no supported HashTable.blob member")
	}
	return result, nil
}

func parseCatalogMembers(ctlValue derValue, budget *derBudget, result *parsedWindowsCatalog) error {
	ctlChildren, err := requireDERChildren(ctlValue, 0, 16, 5, 6, budget, "catalog MS CTL content")
	if err != nil {
		return err
	}
	if _, err := requireDERChildren(ctlChildren[0], 0, 16, 1, 2, budget, "catalog CTL type"); err != nil {
		return err
	}
	if err := requireUniversal(ctlChildren[1], 4, false, "catalog CTL identifier"); err != nil {
		return err
	}
	if err := requireUniversal(ctlChildren[2], 23, false, "catalog CTL time"); err != nil {
		return err
	}
	if _, err := requireDERChildren(ctlChildren[3], 0, 16, 1, 2, budget, "catalog CTL version"); err != nil {
		return err
	}
	members, err := requireDERChildren(ctlChildren[4], 0, 16, 1, maxCatalogMembers, budget, "catalog member list")
	if err != nil {
		return err
	}
	result.memberCount = uint64(len(members))
	matches := 0
	for memberIndex, member := range members {
		memberChildren, err := requireDERChildren(member, 0, 16, 2, 2, budget, fmt.Sprintf("catalog member %d", memberIndex))
		if err != nil {
			return err
		}
		if err := requireUniversal(memberChildren[0], 4, false, fmt.Sprintf("catalog member %d digest", memberIndex)); err != nil {
			return err
		}
		attributes, err := requireDERChildren(memberChildren[1], 0, 17, 1, maxCatalogAttributes, budget, fmt.Sprintf("catalog member %d attributes", memberIndex))
		if err != nil {
			return err
		}
		var name string
		var digestOID string
		var digest []byte
		nameCount := 0
		digestCount := 0
		for attributeIndex, attribute := range attributes {
			attributeChildren, err := requireDERChildren(attribute, 0, 16, 1, 2, budget, fmt.Sprintf("catalog member %d attribute %d", memberIndex, attributeIndex))
			if err != nil {
				return err
			}
			attributeOID, err := requireOID(attributeChildren[0], fmt.Sprintf("catalog member %d attribute %d type", memberIndex, attributeIndex))
			if err != nil {
				return err
			}
			if len(attributeChildren) == 1 {
				continue
			}
			switch attributeOID {
			case oidCatalogNameValue:
				nameCount++
				if nameCount > 1 {
					return fmt.Errorf("catalog member %d has duplicate name attributes", memberIndex)
				}
				name, err = parseCatalogMemberName(attributeChildren[1], budget, memberIndex)
				if err != nil {
					return err
				}
			case oidSPCIndirectData:
				digestCount++
				if digestCount > 1 {
					return fmt.Errorf("catalog member %d has duplicate indirect-data attributes", memberIndex)
				}
				digestOID, digest, err = parseCatalogMemberDigest(attributeChildren[1], budget, memberIndex)
				if err != nil {
					return err
				}
			}
		}
		if name != catalogHashTableMember {
			continue
		}
		matches++
		if matches > 1 {
			return errors.New("FFU catalog contains multiple HashTable.blob members")
		}
		if digestCount != 1 || len(digest) == 0 {
			return fmt.Errorf("catalog HashTable.blob member %d has no supported indirect-data digest", memberIndex)
		}
		result.memberName = name
		result.memberDigestOID = digestOID
		result.memberDigest = append([]byte(nil), digest...)
	}
	return nil
}

func parseCatalogMemberName(contents derValue, budget *derBudget, memberIndex int) (string, error) {
	setChildren, err := requireDERChildren(contents, 0, 17, 1, 1, budget, fmt.Sprintf("catalog member %d name contents", memberIndex))
	if err != nil {
		return "", err
	}
	nameChildren, err := requireDERChildren(setChildren[0], 0, 16, 3, 3, budget, fmt.Sprintf("catalog member %d name value", memberIndex))
	if err != nil {
		return "", err
	}
	if err := requireUniversal(nameChildren[0], 30, false, fmt.Sprintf("catalog member %d name tag", memberIndex)); err != nil {
		return "", err
	}
	if len(nameChildren[0].content)%2 != 0 {
		return "", fmt.Errorf("catalog member %d BMP name tag has odd length", memberIndex)
	}
	flags, err := requireNonnegativeInteger(nameChildren[1], fmt.Sprintf("catalog member %d name flags", memberIndex))
	if err != nil {
		return "", err
	}
	if flags&catalogNameBase64Flag != 0 {
		return "", fmt.Errorf("catalog member %d uses unsupported base64 member-name encoding", memberIndex)
	}
	if err := requireUniversal(nameChildren[2], 4, false, fmt.Sprintf("catalog member %d name bytes", memberIndex)); err != nil {
		return "", err
	}
	return decodeCatalogUTF16LE(nameChildren[2].content, memberIndex)
}

func parseCatalogMemberDigest(contents derValue, budget *derBudget, memberIndex int) (string, []byte, error) {
	setChildren, err := requireDERChildren(contents, 0, 17, 1, 1, budget, fmt.Sprintf("catalog member %d indirect-data contents", memberIndex))
	if err != nil {
		return "", nil, err
	}
	indirectChildren, err := requireDERChildren(setChildren[0], 0, 16, 2, 2, budget, fmt.Sprintf("catalog member %d indirect data", memberIndex))
	if err != nil {
		return "", nil, err
	}
	if _, err := requireDERChildren(indirectChildren[0], 0, 16, 1, 2, budget, fmt.Sprintf("catalog member %d indirect data type", memberIndex)); err != nil {
		return "", nil, err
	}
	digestInfo, err := requireDERChildren(indirectChildren[1], 0, 16, 2, 2, budget, fmt.Sprintf("catalog member %d digest info", memberIndex))
	if err != nil {
		return "", nil, err
	}
	algorithmOID, err := parseAlgorithmIdentifier(digestInfo[0], budget, fmt.Sprintf("catalog member %d digest algorithm", memberIndex))
	if err != nil {
		return "", nil, err
	}
	if algorithmOID != oidSHA1 {
		return "", nil, fmt.Errorf("unsupported catalog HashTable.blob digest algorithm %s", algorithmOID)
	}
	if err := requireUniversal(digestInfo[1], 4, false, fmt.Sprintf("catalog member %d digest bytes", memberIndex)); err != nil {
		return "", nil, err
	}
	if len(digestInfo[1].content) != sha1.Size {
		return "", nil, fmt.Errorf("catalog HashTable.blob SHA-1 digest has length %d, expected %d", len(digestInfo[1].content), sha1.Size)
	}
	return algorithmOID, append([]byte(nil), digestInfo[1].content...), nil
}

func parseSignedDataMetadata(nodes []derValue, budget *derBudget, result *parsedWindowsCatalog) error {
	var certificateNode *derValue
	var signerNode *derValue
	for index := range nodes {
		node := nodes[index]
		switch {
		case node.class == 2 && node.tag == 0:
			if certificateNode != nil {
				return errors.New("FFU catalog SignedData has duplicate certificate sets")
			}
			certificateNode = &nodes[index]
		case node.class == 2 && node.tag == 1:
			// CRLs are outside this metadata-only tranche but their bounded DER
			// envelope remains covered by the outer parser.
		case node.class == 0 && node.tag == 17:
			if signerNode != nil {
				return errors.New("FFU catalog SignedData has duplicate signer sets")
			}
			signerNode = &nodes[index]
		default:
			return fmt.Errorf("unsupported FFU catalog SignedData field class=%d tag=%d", node.class, node.tag)
		}
	}
	if signerNode == nil {
		return errors.New("FFU catalog SignedData contains no signerInfos set")
	}
	if certificateNode != nil {
		certificates, err := parseImplicitChildren(*certificateNode, 1, maxCatalogCertificates, budget, "catalog certificates")
		if err != nil {
			return err
		}
		for index, certificateDER := range certificates {
			if err := requireUniversal(certificateDER, 16, true, fmt.Sprintf("catalog certificate %d", index)); err != nil {
				return err
			}
			certificate, err := x509.ParseCertificate(certificateDER.full)
			if err != nil {
				return fmt.Errorf("parse catalog certificate %d: %w", index, err)
			}
			fingerprint := sha256.Sum256(certificate.Raw)
			result.certificates = append(result.certificates, CatalogCertificate{
				Index:              index,
				Subject:            certificate.Subject.String(),
				Issuer:             certificate.Issuer.String(),
				SerialNumber:       certificate.SerialNumber.Text(16),
				SHA256:             hex.EncodeToString(fingerprint[:]),
				NotBefore:          certificate.NotBefore.UTC().Format(time.RFC3339),
				NotAfter:           certificate.NotAfter.UTC().Format(time.RFC3339),
				PublicKeyAlgorithm: certificate.PublicKeyAlgorithm.String(),
				SignatureAlgorithm: certificate.SignatureAlgorithm.String(),
			})
		}
	}
	signers, err := requireDERChildren(*signerNode, 0, 17, 1, maxCatalogSigners, budget, "catalog signerInfos")
	if err != nil {
		return err
	}
	for index, signer := range signers {
		parsed, err := parseCatalogSigner(index, signer, budget)
		if err != nil {
			return err
		}
		result.signers = append(result.signers, parsed)
	}
	return nil
}

func parseCatalogSigner(index int, signer derValue, budget *derBudget) (CatalogSigner, error) {
	children, err := requireDERChildren(signer, 0, 16, 5, 7, budget, fmt.Sprintf("catalog signer %d", index))
	if err != nil {
		return CatalogSigner{}, err
	}
	version, err := requireNonnegativeInteger(children[0], fmt.Sprintf("catalog signer %d version", index))
	if err != nil {
		return CatalogSigner{}, err
	}
	identifierType := "issuer-and-serial"
	if children[1].class == 2 && children[1].tag == 0 {
		identifierType = "subject-key-identifier"
	} else if err := requireUniversal(children[1], 16, true, fmt.Sprintf("catalog signer %d identifier", index)); err != nil {
		return CatalogSigner{}, err
	}
	identifierDigest := sha256.Sum256(children[1].full)
	digestOID, err := parseAlgorithmIdentifier(children[2], budget, fmt.Sprintf("catalog signer %d digest algorithm", index))
	if err != nil {
		return CatalogSigner{}, err
	}
	cursor := 3
	var signedOIDs []string
	if children[cursor].class == 2 && children[cursor].tag == 0 {
		attributes, err := parseImplicitChildren(children[cursor], 1, maxCatalogAttributes, budget, fmt.Sprintf("catalog signer %d signed attributes", index))
		if err != nil {
			return CatalogSigner{}, err
		}
		for attributeIndex, attribute := range attributes {
			attributeChildren, err := requireDERChildren(attribute, 0, 16, 2, 2, budget, fmt.Sprintf("catalog signer %d signed attribute %d", index, attributeIndex))
			if err != nil {
				return CatalogSigner{}, err
			}
			oid, err := requireOID(attributeChildren[0], fmt.Sprintf("catalog signer %d signed attribute %d type", index, attributeIndex))
			if err != nil {
				return CatalogSigner{}, err
			}
			signedOIDs = append(signedOIDs, oid)
		}
		cursor++
	}
	if cursor+1 >= len(children) {
		return CatalogSigner{}, fmt.Errorf("catalog signer %d is missing signature algorithm or signature", index)
	}
	signatureOID, err := parseAlgorithmIdentifier(children[cursor], budget, fmt.Sprintf("catalog signer %d signature algorithm", index))
	if err != nil {
		return CatalogSigner{}, err
	}
	if err := requireUniversal(children[cursor+1], 4, false, fmt.Sprintf("catalog signer %d signature", index)); err != nil {
		return CatalogSigner{}, err
	}
	if len(children[cursor+1].content) == 0 {
		return CatalogSigner{}, fmt.Errorf("catalog signer %d has an empty signature", index)
	}
	cursor += 2
	if cursor < len(children) {
		if children[cursor].class != 2 || children[cursor].tag != 1 || cursor+1 != len(children) {
			return CatalogSigner{}, fmt.Errorf("catalog signer %d has unsupported trailing fields", index)
		}
	}
	return CatalogSigner{
		Index:                 index,
		Version:               version,
		IdentifierType:        identifierType,
		IdentifierSHA256:      hex.EncodeToString(identifierDigest[:]),
		DigestAlgorithmOID:    digestOID,
		SignatureAlgorithmOID: signatureOID,
		SignedAttributeOIDs:   signedOIDs,
	}, nil
}

func parseAlgorithmIdentifier(value derValue, budget *derBudget, label string) (string, error) {
	children, err := requireDERChildren(value, 0, 16, 1, 2, budget, label)
	if err != nil {
		return "", err
	}
	oid, err := requireOID(children[0], label+" OID")
	if err != nil {
		return "", err
	}
	if len(children) == 2 && !(children[1].class == 0 && children[1].tag == 5 && len(children[1].content) == 0) {
		return "", fmt.Errorf("%s has unsupported non-NULL parameters", label)
	}
	return oid, nil
}

func readCatalogRegion(reader io.ReaderAt, offset, length uint64) ([]byte, error) {
	if length == 0 || length > maxFFUCatalogBytes {
		return nil, fmt.Errorf("invalid bounded FFU catalog length %d", length)
	}
	return readRegion(reader, offset+length, offset, int(length), "catalog")
}

func hashFFUTableSHA1(ctx context.Context, reader io.ReaderAt, offset, length uint64) ([]byte, error) {
	section := io.NewSectionReader(reader, int64(offset), int64(length))
	digest := sha1.New() // #nosec G401 -- required solely to compare the explicitly encoded legacy catalog member digest.
	buffer := make([]byte, ffuHashReadBufferBytes)
	copied, err := io.CopyBuffer(digest, &ffuContextReader{ctx: ctx, reader: section}, buffer)
	if err != nil {
		return nil, err
	}
	if copied != int64(length) {
		return nil, fmt.Errorf("read %d of %d hash-table bytes", copied, length)
	}
	return digest.Sum(nil), nil
}

func parseDERValue(data []byte, budget *derBudget) (derValue, []byte, error) {
	if budget == nil {
		return derValue{}, nil, errors.New("DER parser budget is nil")
	}
	budget.nodes++
	if budget.nodes > maxCatalogDERNodes {
		return derValue{}, nil, fmt.Errorf("catalog DER node count exceeds limit %d", maxCatalogDERNodes)
	}
	if len(data) < 2 {
		return derValue{}, nil, errors.New("truncated DER header")
	}
	identifier := data[0]
	tag := identifier & 0x1f
	if tag == 0x1f {
		return derValue{}, nil, errors.New("high-tag-number DER form is unsupported")
	}
	lengthByte := data[1]
	headerLength := 2
	var contentLength uint64
	if lengthByte&0x80 == 0 {
		contentLength = uint64(lengthByte)
	} else {
		lengthBytes := int(lengthByte & 0x7f)
		if lengthBytes == 0 {
			return derValue{}, nil, errors.New("indefinite DER length is forbidden")
		}
		if lengthBytes > 8 || len(data) < 2+lengthBytes {
			return derValue{}, nil, errors.New("invalid DER long-form length")
		}
		if data[2] == 0 {
			return derValue{}, nil, errors.New("non-minimal DER long-form length")
		}
		for _, current := range data[2 : 2+lengthBytes] {
			if contentLength > (^uint64(0)-uint64(current))/256 {
				return derValue{}, nil, errors.New("DER length overflows")
			}
			contentLength = contentLength*256 + uint64(current)
		}
		if contentLength < 128 {
			return derValue{}, nil, errors.New("non-minimal DER long-form length")
		}
		headerLength += lengthBytes
	}
	if contentLength > uint64(len(data)-headerLength) {
		return derValue{}, nil, errors.New("truncated DER value")
	}
	end := headerLength + int(contentLength)
	return derValue{
		class:       identifier >> 6,
		tag:         tag,
		constructed: identifier&0x20 != 0,
		full:        data[:end],
		content:     data[headerLength:end],
	}, data[end:], nil
}

func requireDERChildren(value derValue, class, tag byte, minimum, maximum int, budget *derBudget, label string) ([]derValue, error) {
	if value.class != class || value.tag != tag || !value.constructed {
		return nil, fmt.Errorf("%s has unexpected DER class=%d tag=%d constructed=%t", label, value.class, value.tag, value.constructed)
	}
	return parseDERChildren(value.content, 1, minimum, maximum, budget, label)
}

func parseImplicitChildren(value derValue, minimum, maximum int, budget *derBudget, label string) ([]derValue, error) {
	if !value.constructed {
		return nil, fmt.Errorf("%s is not constructed", label)
	}
	return parseDERChildren(value.content, 1, minimum, maximum, budget, label)
}

func parseDERChildren(data []byte, depth, minimum, maximum int, budget *derBudget, label string) ([]derValue, error) {
	if depth > maxCatalogDERDepth {
		return nil, fmt.Errorf("%s exceeds DER depth limit %d", label, maxCatalogDERDepth)
	}
	result := make([]derValue, 0)
	for len(data) != 0 {
		if len(result) >= maximum {
			return nil, fmt.Errorf("%s contains more than %d values", label, maximum)
		}
		child, rest, err := parseDERValue(data, budget)
		if err != nil {
			return nil, fmt.Errorf("%s child %d: %w", label, len(result), err)
		}
		result = append(result, child)
		data = rest
	}
	if len(result) < minimum {
		return nil, fmt.Errorf("%s contains %d values, expected at least %d", label, len(result), minimum)
	}
	return result, nil
}

func requireContextSingle(value derValue, tag byte, depth int, budget *derBudget, label string) (derValue, error) {
	if value.class != 2 || value.tag != tag || !value.constructed {
		return derValue{}, fmt.Errorf("%s has unexpected DER class=%d tag=%d", label, value.class, value.tag)
	}
	children, err := parseDERChildren(value.content, depth, 1, 1, budget, label)
	if err != nil {
		return derValue{}, err
	}
	return children[0], nil
}

func requireUniversal(value derValue, tag byte, constructed bool, label string) error {
	if value.class != 0 || value.tag != tag || value.constructed != constructed {
		return fmt.Errorf("%s has unexpected DER class=%d tag=%d constructed=%t", label, value.class, value.tag, value.constructed)
	}
	return nil
}

func requireOID(value derValue, label string) (string, error) {
	if err := requireUniversal(value, 6, false, label); err != nil {
		return "", err
	}
	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(value.full, &oid)
	if err != nil || len(rest) != 0 || len(oid) < 2 {
		return "", fmt.Errorf("%s is not a valid DER object identifier", label)
	}
	return oid.String(), nil
}

func requireNonnegativeInteger(value derValue, label string) (uint64, error) {
	if err := requireUniversal(value, 2, false, label); err != nil {
		return 0, err
	}
	if len(value.content) == 0 || value.content[0]&0x80 != 0 {
		return 0, fmt.Errorf("%s must be a non-negative DER integer", label)
	}
	if len(value.content) > 1 && value.content[0] == 0 && value.content[1]&0x80 == 0 {
		return 0, fmt.Errorf("%s uses non-minimal DER integer encoding", label)
	}
	integer := new(big.Int).SetBytes(value.content)
	if !integer.IsUint64() {
		return 0, fmt.Errorf("%s exceeds uint64", label)
	}
	return integer.Uint64(), nil
}

func decodeCatalogUTF16LE(data []byte, memberIndex int) (string, error) {
	if len(data)%2 != 0 {
		return "", fmt.Errorf("catalog member %d name has odd UTF-16LE length", memberIndex)
	}
	var builder strings.Builder
	terminated := false
	for index := 0; index < len(data); index += 2 {
		value := binary.LittleEndian.Uint16(data[index : index+2])
		if value == 0 {
			terminated = true
			continue
		}
		if terminated {
			return "", fmt.Errorf("catalog member %d name contains data after its terminator", memberIndex)
		}
		if value < 0x20 || value > 0x7e {
			return "", fmt.Errorf("catalog member %d name contains unsupported UTF-16 value 0x%04x", memberIndex, value)
		}
		builder.WriteByte(byte(value))
	}
	if builder.Len() == 0 {
		return "", fmt.Errorf("catalog member %d name is empty", memberIndex)
	}
	return builder.String(), nil
}

func catalogMemberPlanDigest(plan CatalogMemberPlan) string {
	digest := sha256.New()
	writeCatalogUint64(digest, uint64(plan.Schema))
	writeCatalogUint64(digest, plan.SourceFileSize)
	writeCatalogUint64(digest, plan.CatalogOffset)
	writeCatalogUint64(digest, plan.CatalogLength)
	writeCatalogString(digest, plan.CatalogSHA256)
	writeCatalogString(digest, plan.OuterContentTypeOID)
	writeCatalogString(digest, plan.EncapsulatedContentTypeOID)
	writeCatalogUint64(digest, plan.CatalogMemberCount)
	writeCatalogString(digest, plan.HashTableMemberName)
	writeCatalogString(digest, plan.HashTableMemberDigestAlgorithm)
	writeCatalogString(digest, plan.HashTableMemberDigestOID)
	writeCatalogString(digest, plan.HashTableMemberDigest)
	writeCatalogString(digest, plan.CalculatedHashTableDigest)
	writeCatalogString(digest, plan.HashTableSHA256)
	writeCatalogUint64(digest, plan.HashTableLength)
	writeCatalogBool(digest, plan.HashTableMemberMatches)
	writeCatalogBool(digest, plan.SignatureStructureParsed)
	writeCatalogBool(digest, plan.CryptographicSignatureVerified)
	writeCatalogBool(digest, plan.CertificateChainBuilt)
	writeCatalogBool(digest, plan.PublisherTrusted)
	writeCatalogBool(digest, plan.HashTableCatalogAuthenticated)
	writeCatalogUint64(digest, uint64(len(plan.Certificates)))
	for _, certificate := range plan.Certificates {
		writeCatalogUint64(digest, uint64(certificate.Index))
		writeCatalogString(digest, certificate.Subject)
		writeCatalogString(digest, certificate.Issuer)
		writeCatalogString(digest, certificate.SerialNumber)
		writeCatalogString(digest, certificate.SHA256)
		writeCatalogString(digest, certificate.NotBefore)
		writeCatalogString(digest, certificate.NotAfter)
		writeCatalogString(digest, certificate.PublicKeyAlgorithm)
		writeCatalogString(digest, certificate.SignatureAlgorithm)
	}
	writeCatalogUint64(digest, uint64(len(plan.Signers)))
	for _, signer := range plan.Signers {
		writeCatalogUint64(digest, uint64(signer.Index))
		writeCatalogUint64(digest, signer.Version)
		writeCatalogString(digest, signer.IdentifierType)
		writeCatalogString(digest, signer.IdentifierSHA256)
		writeCatalogString(digest, signer.DigestAlgorithmOID)
		writeCatalogString(digest, signer.SignatureAlgorithmOID)
		writeCatalogUint64(digest, uint64(len(signer.SignedAttributeOIDs)))
		for _, oid := range signer.SignedAttributeOIDs {
			writeCatalogString(digest, oid)
		}
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func writeCatalogUint64(digest hash.Hash, value uint64) {
	var buffer [8]byte
	binary.LittleEndian.PutUint64(buffer[:], value)
	_, _ = digest.Write(buffer[:])
}

func writeCatalogString(digest hash.Hash, value string) {
	writeCatalogUint64(digest, uint64(len(value)))
	_, _ = digest.Write([]byte(value))
}

func writeCatalogBool(digest hash.Hash, value bool) {
	if value {
		writeCatalogUint64(digest, 1)
		return
	}
	writeCatalogUint64(digest, 0)
}
