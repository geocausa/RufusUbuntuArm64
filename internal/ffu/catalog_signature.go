package ffu

import (
	"bytes"
	"context"
	"crypto/sha1" // #nosec G505 -- accepted only when the catalog explicitly declares the legacy SHA-1 digest.
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math/big"
)

const catalogSignaturePlanSchema = 1

const (
	oidPKCS9ContentType   = "1.2.840.113549.1.9.3"
	oidPKCS9MessageDigest = "1.2.840.113549.1.9.4"
	oidSHA256             = "2.16.840.1.101.3.4.2.1"
	oidRSAEncryption      = "1.2.840.113549.1.1.1"
	oidSHA1WithRSA        = "1.2.840.113549.1.1.5"
	oidSHA256WithRSA      = "1.2.840.113549.1.1.11"
	oidECDSAWithSHA256    = "1.2.840.10045.4.3.2"
	oidEd25519            = "1.3.101.112"
)

// CatalogSignaturePlan records cryptographic verification of one supported
// PKCS#7 SignerInfo. A valid signature proves possession of the embedded
// certificate's private key only; it does not build a chain or trust a publisher.
type CatalogSignaturePlan struct {
	Schema                         int      `json:"schema"`
	SourceFileSize                 uint64   `json:"source_file_size"`
	CatalogMemberPlanSHA256        string   `json:"catalog_member_plan_sha256"`
	CatalogSHA256                  string   `json:"catalog_sha256"`
	EncapsulatedContentTypeOID     string   `json:"encapsulated_content_type_oid"`
	EncapsulatedContentLength      uint64   `json:"encapsulated_content_length"`
	EncapsulatedContentSHA256      string   `json:"encapsulated_content_sha256"`
	SignerIndex                    int      `json:"signer_index"`
	SignerIdentifierType           string   `json:"signer_identifier_type"`
	SignerIdentifierSHA256         string   `json:"signer_identifier_sha256"`
	CertificateIndex               int      `json:"certificate_index"`
	CertificateSHA256              string   `json:"certificate_sha256"`
	CertificateSubject             string   `json:"certificate_subject"`
	DigestAlgorithmOID             string   `json:"digest_algorithm_oid"`
	DigestAlgorithm                string   `json:"digest_algorithm"`
	SignatureAlgorithmOID          string   `json:"signature_algorithm_oid"`
	SignatureAlgorithm             string   `json:"signature_algorithm"`
	SignedAttributesSHA256         string   `json:"signed_attributes_sha256"`
	SignedAttributeOIDs            []string `json:"signed_attribute_oids"`
	EncodedMessageDigest           string   `json:"encoded_message_digest"`
	CalculatedMessageDigest        string   `json:"calculated_message_digest"`
	ContentDigestVerified          bool     `json:"content_digest_verified"`
	SignatureVerificationAttempted bool     `json:"signature_verification_attempted"`
	CryptographicSignatureVerified bool     `json:"cryptographic_signature_verified"`
	CertificateChainBuilt          bool     `json:"certificate_chain_built"`
	PublisherTrusted               bool     `json:"publisher_trusted"`
	HashTableCatalogAuthenticated  bool     `json:"hash_table_catalog_authenticated"`
	PlanSHA256                     string   `json:"plan_sha256"`
	Limitations                    []string `json:"limitations"`
}

// VerifyCatalogSignature verifies one supported catalog SignerInfo and its
// mandatory signed attributes. It deliberately performs no chain building,
// revocation, timestamp, publisher policy, target binding, or execution.
func VerifyCatalogSignature(ctx context.Context, reader interface {
	ReadAt([]byte, int64) (int, error)
}, size uint64) (Inspection, HashTablePlan, CatalogMemberPlan, CatalogSignaturePlan, error) {
	if ctx == nil {
		return Inspection{}, HashTablePlan{}, CatalogMemberPlan{}, CatalogSignaturePlan{}, errors.New("FFU catalog-signature context is nil")
	}
	if err := ctx.Err(); err != nil {
		return Inspection{}, HashTablePlan{}, CatalogMemberPlan{}, CatalogSignaturePlan{}, err
	}
	inspection, hashPlan, memberPlan, err := PlanCatalogMember(ctx, reader, size)
	if err != nil {
		return inspection, hashPlan, memberPlan, CatalogSignaturePlan{}, err
	}
	catalogBytes, err := readCatalogRegion(reader, inspection.CatalogOffset, uint64(inspection.Security.CatalogSize))
	if err != nil {
		return inspection, hashPlan, memberPlan, CatalogSignaturePlan{}, err
	}
	catalogDigest := sha256.Sum256(catalogBytes)
	if hex.EncodeToString(catalogDigest[:]) != memberPlan.CatalogSHA256 {
		return inspection, hashPlan, memberPlan, CatalogSignaturePlan{}, errors.New("FFU catalog changed between member and signature planning")
	}
	envelope, err := parseCatalogSignatureEnvelope(catalogBytes)
	if err != nil {
		return inspection, hashPlan, memberPlan, CatalogSignaturePlan{}, err
	}
	certificateIndex, certificate, err := resolveCatalogSignerCertificate(envelope.certificates, envelope.signer)
	if err != nil {
		return inspection, hashPlan, memberPlan, CatalogSignaturePlan{}, err
	}

	contentSHA256 := sha256.Sum256(envelope.content)
	signedAttributesSHA256 := sha256.Sum256(envelope.signer.signedAttributesDER)
	calculatedDigest, digestName, err := calculateCatalogContentDigest(envelope.signer.digestAlgorithmOID, envelope.content)
	if err != nil {
		return inspection, hashPlan, memberPlan, CatalogSignaturePlan{}, err
	}
	signatureAlgorithm, signatureName, err := catalogSignatureAlgorithm(envelope.signer.digestAlgorithmOID, envelope.signer.signatureAlgorithmOID)
	if err != nil {
		return inspection, hashPlan, memberPlan, CatalogSignaturePlan{}, err
	}

	plan := CatalogSignaturePlan{
		Schema:                     catalogSignaturePlanSchema,
		SourceFileSize:             size,
		CatalogMemberPlanSHA256:    memberPlan.PlanSHA256,
		CatalogSHA256:              memberPlan.CatalogSHA256,
		EncapsulatedContentTypeOID: envelope.contentTypeOID,
		EncapsulatedContentLength:  uint64(len(envelope.content)),
		EncapsulatedContentSHA256:  hex.EncodeToString(contentSHA256[:]),
		SignerIndex:                0,
		SignerIdentifierType:       envelope.signer.identifierType,
		SignerIdentifierSHA256:     envelope.signer.identifierSHA256,
		CertificateIndex:           certificateIndex,
		CertificateSHA256:          certificateFingerprint(certificate),
		CertificateSubject:         certificate.Subject.String(),
		DigestAlgorithmOID:         envelope.signer.digestAlgorithmOID,
		DigestAlgorithm:            digestName,
		SignatureAlgorithmOID:      envelope.signer.signatureAlgorithmOID,
		SignatureAlgorithm:         signatureName,
		SignedAttributesSHA256:     hex.EncodeToString(signedAttributesSHA256[:]),
		SignedAttributeOIDs:        append([]string(nil), envelope.signer.signedAttributeOIDs...),
		EncodedMessageDigest:       hex.EncodeToString(envelope.signer.messageDigest),
		CalculatedMessageDigest:    hex.EncodeToString(calculatedDigest),
		Limitations: []string{
			"a valid signature proves only possession of the private key corresponding to the embedded signer certificate",
			"no certificate chain, validity-time, key-usage, revocation, timestamp, or publisher policy is applied",
			"no target is accepted and no regular-file, loop-device or physical-device executor exists",
		},
	}
	if subtle.ConstantTimeCompare(envelope.signer.messageDigest, calculatedDigest) != 1 {
		plan.PlanSHA256 = catalogSignaturePlanDigest(plan)
		return inspection, hashPlan, memberPlan, plan, errors.New("FFU catalog signed message-digest attribute does not match the encapsulated CTL content")
	}
	plan.ContentDigestVerified = true
	plan.SignatureVerificationAttempted = true
	if err := certificate.CheckSignature(signatureAlgorithm, envelope.signer.signedAttributesDER, envelope.signer.signature); err != nil {
		plan.PlanSHA256 = catalogSignaturePlanDigest(plan)
		return inspection, hashPlan, memberPlan, plan, fmt.Errorf("verify FFU catalog SignerInfo signature: %w", err)
	}
	plan.CryptographicSignatureVerified = true
	plan.HashTableCatalogAuthenticated = memberPlan.HashTableMemberMatches && plan.CryptographicSignatureVerified && plan.CertificateChainBuilt && plan.PublisherTrusted
	plan.PlanSHA256 = catalogSignaturePlanDigest(plan)
	return inspection, hashPlan, memberPlan, plan, nil
}

type catalogSignatureEnvelope struct {
	contentTypeOID string
	content        []byte
	certificates   []*x509.Certificate
	signer         catalogSignatureSigner
}

type catalogSignatureSigner struct {
	identifierType        string
	identifierSHA256      string
	issuerDER             []byte
	serialNumber          *big.Int
	subjectKeyIdentifier  []byte
	digestAlgorithmOID    string
	signatureAlgorithmOID string
	signedAttributesDER   []byte
	signedAttributeOIDs   []string
	messageDigest         []byte
	signature             []byte
}

func parseCatalogSignatureEnvelope(data []byte) (catalogSignatureEnvelope, error) {
	budget := &derBudget{}
	outer, rest, err := parseDERValue(data, budget)
	if err != nil {
		return catalogSignatureEnvelope{}, fmt.Errorf("parse FFU catalog signature ContentInfo: %w", err)
	}
	if len(rest) != 0 {
		return catalogSignatureEnvelope{}, fmt.Errorf("FFU catalog signature has %d trailing bytes", len(rest))
	}
	outerChildren, err := requireDERChildren(outer, 0, 16, 2, 2, budget, "catalog signature ContentInfo")
	if err != nil {
		return catalogSignatureEnvelope{}, err
	}
	outerOID, err := requireOID(outerChildren[0], "catalog signature outer content type")
	if err != nil {
		return catalogSignatureEnvelope{}, err
	}
	if outerOID != oidPKCS7SignedData {
		return catalogSignatureEnvelope{}, fmt.Errorf("unsupported FFU catalog signature outer content type %s", outerOID)
	}
	signedData, err := requireContextSingle(outerChildren[1], 0, 1, budget, "catalog signature SignedData")
	if err != nil {
		return catalogSignatureEnvelope{}, err
	}
	signedChildren, err := requireDERChildren(signedData, 0, 16, 4, 8, budget, "catalog signature SignedData")
	if err != nil {
		return catalogSignatureEnvelope{}, err
	}
	if _, err := requireNonnegativeInteger(signedChildren[0], "catalog signature SignedData version"); err != nil {
		return catalogSignatureEnvelope{}, err
	}
	digestAlgorithms, err := requireDERChildren(signedChildren[1], 0, 17, 1, 16, budget, "catalog signature digestAlgorithms")
	if err != nil {
		return catalogSignatureEnvelope{}, err
	}
	declaredDigests := make(map[string]struct{}, len(digestAlgorithms))
	for index, algorithm := range digestAlgorithms {
		oid, err := parseAlgorithmIdentifier(algorithm, budget, fmt.Sprintf("catalog signature digest algorithm %d", index))
		if err != nil {
			return catalogSignatureEnvelope{}, err
		}
		if _, exists := declaredDigests[oid]; exists {
			return catalogSignatureEnvelope{}, fmt.Errorf("FFU catalog SignedData has duplicate digest algorithm %s", oid)
		}
		declaredDigests[oid] = struct{}{}
	}
	encapChildren, err := requireDERChildren(signedChildren[2], 0, 16, 2, 2, budget, "catalog signature encapContentInfo")
	if err != nil {
		return catalogSignatureEnvelope{}, err
	}
	contentTypeOID, err := requireOID(encapChildren[0], "catalog signature encapsulated content type")
	if err != nil {
		return catalogSignatureEnvelope{}, err
	}
	if contentTypeOID != oidMicrosoftCTL {
		return catalogSignatureEnvelope{}, fmt.Errorf("unsupported FFU catalog signature content type %s", contentTypeOID)
	}
	contentValue, err := requireContextSingle(encapChildren[1], 0, 2, budget, "catalog signature encapsulated content")
	if err != nil {
		return catalogSignatureEnvelope{}, err
	}
	if err := requireUniversal(contentValue, 4, false, "catalog signature encapsulated content octets"); err != nil {
		return catalogSignatureEnvelope{}, errors.New("FFU catalog signature requires DER OCTET STRING encapsulated content")
	}
	if len(contentValue.content) == 0 {
		return catalogSignatureEnvelope{}, errors.New("FFU catalog signature encapsulated content is empty")
	}

	var certificateNode *derValue
	var signerNode *derValue
	for index := 3; index < len(signedChildren); index++ {
		node := signedChildren[index]
		switch {
		case node.class == 2 && node.tag == 0:
			if certificateNode != nil {
				return catalogSignatureEnvelope{}, errors.New("FFU catalog signature has duplicate certificate sets")
			}
			certificateNode = &signedChildren[index]
		case node.class == 2 && node.tag == 1:
			// CRLs are not evaluated by the signature-only tranche.
		case node.class == 0 && node.tag == 17:
			if signerNode != nil {
				return catalogSignatureEnvelope{}, errors.New("FFU catalog signature has duplicate signer sets")
			}
			signerNode = &signedChildren[index]
		default:
			return catalogSignatureEnvelope{}, fmt.Errorf("unsupported FFU catalog signature SignedData field class=%d tag=%d", node.class, node.tag)
		}
	}
	if certificateNode == nil {
		return catalogSignatureEnvelope{}, errors.New("FFU catalog signature contains no embedded certificates")
	}
	if signerNode == nil {
		return catalogSignatureEnvelope{}, errors.New("FFU catalog signature contains no SignerInfo set")
	}
	certificateValues, err := parseImplicitChildren(*certificateNode, 1, maxCatalogCertificates, budget, "catalog signature certificates")
	if err != nil {
		return catalogSignatureEnvelope{}, err
	}
	certificates := make([]*x509.Certificate, 0, len(certificateValues))
	for index, value := range certificateValues {
		if err := requireUniversal(value, 16, true, fmt.Sprintf("catalog signature certificate %d", index)); err != nil {
			return catalogSignatureEnvelope{}, err
		}
		certificate, err := x509.ParseCertificate(value.full)
		if err != nil {
			return catalogSignatureEnvelope{}, fmt.Errorf("parse catalog signature certificate %d: %w", index, err)
		}
		certificates = append(certificates, certificate)
	}
	signers, err := requireDERChildren(*signerNode, 0, 17, 1, maxCatalogSigners, budget, "catalog signature signerInfos")
	if err != nil {
		return catalogSignatureEnvelope{}, err
	}
	if len(signers) != 1 {
		return catalogSignatureEnvelope{}, fmt.Errorf("FFU catalog signature verification requires exactly one SignerInfo, found %d", len(signers))
	}
	signer, err := parseCatalogSignatureSigner(signers[0], budget)
	if err != nil {
		return catalogSignatureEnvelope{}, err
	}
	if _, ok := declaredDigests[signer.digestAlgorithmOID]; !ok {
		return catalogSignatureEnvelope{}, fmt.Errorf("FFU catalog signer digest algorithm %s is absent from SignedData digestAlgorithms", signer.digestAlgorithmOID)
	}
	return catalogSignatureEnvelope{
		contentTypeOID: contentTypeOID,
		content:        append([]byte(nil), contentValue.content...),
		certificates:   certificates,
		signer:         signer,
	}, nil
}

func parseCatalogSignatureSigner(value derValue, budget *derBudget) (catalogSignatureSigner, error) {
	children, err := requireDERChildren(value, 0, 16, 5, 7, budget, "catalog signature SignerInfo")
	if err != nil {
		return catalogSignatureSigner{}, err
	}
	if _, err := requireNonnegativeInteger(children[0], "catalog signature SignerInfo version"); err != nil {
		return catalogSignatureSigner{}, err
	}
	signer := catalogSignatureSigner{}
	identifierDigest := sha256.Sum256(children[1].full)
	signer.identifierSHA256 = hex.EncodeToString(identifierDigest[:])
	switch {
	case children[1].class == 0 && children[1].tag == 16 && children[1].constructed:
		identifierChildren, err := requireDERChildren(children[1], 0, 16, 2, 2, budget, "catalog signature issuerAndSerialNumber")
		if err != nil {
			return catalogSignatureSigner{}, err
		}
		if err := requireUniversal(identifierChildren[0], 16, true, "catalog signature signer issuer"); err != nil {
			return catalogSignatureSigner{}, err
		}
		serial, err := requireNonnegativeBigInteger(identifierChildren[1], "catalog signature signer serial number")
		if err != nil {
			return catalogSignatureSigner{}, err
		}
		signer.identifierType = "issuer-and-serial"
		signer.issuerDER = append([]byte(nil), identifierChildren[0].full...)
		signer.serialNumber = serial
	case children[1].class == 2 && children[1].tag == 0 && !children[1].constructed:
		if len(children[1].content) == 0 {
			return catalogSignatureSigner{}, errors.New("FFU catalog signer subject-key-identifier is empty")
		}
		signer.identifierType = "subject-key-identifier"
		signer.subjectKeyIdentifier = append([]byte(nil), children[1].content...)
	default:
		return catalogSignatureSigner{}, fmt.Errorf("unsupported FFU catalog signer identifier class=%d tag=%d", children[1].class, children[1].tag)
	}
	signer.digestAlgorithmOID, err = parseAlgorithmIdentifier(children[2], budget, "catalog signature signer digest algorithm")
	if err != nil {
		return catalogSignatureSigner{}, err
	}
	cursor := 3
	if children[cursor].class != 2 || children[cursor].tag != 0 || !children[cursor].constructed {
		return catalogSignatureSigner{}, errors.New("FFU catalog signer has no signed attributes")
	}
	signedAttributes := children[cursor]
	signer.signedAttributesDER = append([]byte(nil), signedAttributes.full...)
	if len(signer.signedAttributesDER) == 0 {
		return catalogSignatureSigner{}, errors.New("FFU catalog signer signed-attribute encoding is empty")
	}
	// CMS signs the DER SET OF encoding, while SignerInfo stores the same
	// content under the IMPLICIT context-specific [0] tag.
	signer.signedAttributesDER[0] = 0x31
	attributes, err := parseImplicitChildren(signedAttributes, 0, maxCatalogAttributes, budget, "catalog signature signed attributes")
	if err != nil {
		return catalogSignatureSigner{}, err
	}
	contentTypeCount := 0
	messageDigestCount := 0
	for index, attribute := range attributes {
		attributeChildren, err := requireDERChildren(attribute, 0, 16, 2, 2, budget, fmt.Sprintf("catalog signature signed attribute %d", index))
		if err != nil {
			return catalogSignatureSigner{}, err
		}
		oid, err := requireOID(attributeChildren[0], fmt.Sprintf("catalog signature signed attribute %d type", index))
		if err != nil {
			return catalogSignatureSigner{}, err
		}
		signer.signedAttributeOIDs = append(signer.signedAttributeOIDs, oid)
		values, err := requireDERChildren(attributeChildren[1], 0, 17, 1, 1, budget, fmt.Sprintf("catalog signature signed attribute %d values", index))
		if err != nil {
			return catalogSignatureSigner{}, err
		}
		switch oid {
		case oidPKCS9ContentType:
			contentTypeCount++
			if contentTypeCount > 1 {
				return catalogSignatureSigner{}, errors.New("FFU catalog signer has duplicate content-type attributes")
			}
			contentTypeOID, err := requireOID(values[0], "catalog signature signed content type")
			if err != nil {
				return catalogSignatureSigner{}, err
			}
			if contentTypeOID != oidMicrosoftCTL {
				return catalogSignatureSigner{}, fmt.Errorf("FFU catalog signed content type is %s, expected %s", contentTypeOID, oidMicrosoftCTL)
			}
		case oidPKCS9MessageDigest:
			messageDigestCount++
			if messageDigestCount > 1 {
				return catalogSignatureSigner{}, errors.New("FFU catalog signer has duplicate message-digest attributes")
			}
			if err := requireUniversal(values[0], 4, false, "catalog signature signed message digest"); err != nil {
				return catalogSignatureSigner{}, err
			}
			if len(values[0].content) == 0 {
				return catalogSignatureSigner{}, errors.New("FFU catalog signed message digest is empty")
			}
			signer.messageDigest = append([]byte(nil), values[0].content...)
		}
	}
	if contentTypeCount != 1 || messageDigestCount != 1 {
		return catalogSignatureSigner{}, errors.New("FFU catalog signer requires exactly one content-type and one message-digest signed attribute")
	}
	cursor++
	if cursor+1 >= len(children) {
		return catalogSignatureSigner{}, errors.New("FFU catalog signer is missing signature algorithm or signature")
	}
	signer.signatureAlgorithmOID, err = parseAlgorithmIdentifier(children[cursor], budget, "catalog signature signer signature algorithm")
	if err != nil {
		return catalogSignatureSigner{}, err
	}
	if err := requireUniversal(children[cursor+1], 4, false, "catalog signature SignerInfo signature"); err != nil {
		return catalogSignatureSigner{}, err
	}
	if len(children[cursor+1].content) == 0 {
		return catalogSignatureSigner{}, errors.New("FFU catalog SignerInfo signature is empty")
	}
	signer.signature = append([]byte(nil), children[cursor+1].content...)
	cursor += 2
	if cursor < len(children) {
		if children[cursor].class != 2 || children[cursor].tag != 1 || cursor+1 != len(children) {
			return catalogSignatureSigner{}, errors.New("FFU catalog signer has unsupported trailing fields")
		}
	}
	return signer, nil
}

func resolveCatalogSignerCertificate(certificates []*x509.Certificate, signer catalogSignatureSigner) (int, *x509.Certificate, error) {
	matchedIndex := -1
	var matched *x509.Certificate
	for index, certificate := range certificates {
		matches := false
		switch signer.identifierType {
		case "issuer-and-serial":
			matches = bytes.Equal(certificate.RawIssuer, signer.issuerDER) && certificate.SerialNumber.Cmp(signer.serialNumber) == 0
		case "subject-key-identifier":
			matches = len(certificate.SubjectKeyId) != 0 && bytes.Equal(certificate.SubjectKeyId, signer.subjectKeyIdentifier)
		}
		if !matches {
			continue
		}
		if matched != nil {
			return -1, nil, errors.New("FFU catalog signer identifier matches multiple embedded certificates")
		}
		matchedIndex = index
		matched = certificate
	}
	if matched == nil {
		return -1, nil, errors.New("FFU catalog signer identifier matches no embedded certificate")
	}
	return matchedIndex, matched, nil
}

func calculateCatalogContentDigest(oid string, content []byte) ([]byte, string, error) {
	switch oid {
	case oidSHA256:
		digest := sha256.Sum256(content)
		return digest[:], "SHA-256", nil
	case oidSHA1:
		digest := sha1.Sum(content) // #nosec G401 -- accepted only for explicitly declared legacy catalog signatures.
		return digest[:], "SHA-1", nil
	default:
		return nil, "", fmt.Errorf("unsupported FFU catalog signer digest algorithm %s", oid)
	}
}

func catalogSignatureAlgorithm(digestOID, signatureOID string) (x509.SignatureAlgorithm, string, error) {
	switch signatureOID {
	case oidRSAEncryption:
		switch digestOID {
		case oidSHA256:
			return x509.SHA256WithRSA, "RSA PKCS#1 v1.5 with SHA-256", nil
		case oidSHA1:
			return x509.SHA1WithRSA, "RSA PKCS#1 v1.5 with SHA-1", nil
		}
	case oidSHA256WithRSA:
		if digestOID == oidSHA256 {
			return x509.SHA256WithRSA, "RSA PKCS#1 v1.5 with SHA-256", nil
		}
	case oidSHA1WithRSA:
		if digestOID == oidSHA1 {
			return x509.SHA1WithRSA, "RSA PKCS#1 v1.5 with SHA-1", nil
		}
	case oidECDSAWithSHA256:
		if digestOID == oidSHA256 {
			return x509.ECDSAWithSHA256, "ECDSA with SHA-256", nil
		}
	case oidEd25519:
		if digestOID == oidSHA256 {
			return x509.PureEd25519, "Ed25519 with SHA-256 content digest", nil
		}
	}
	return x509.UnknownSignatureAlgorithm, "", fmt.Errorf("unsupported FFU catalog signature/digest combination signature=%s digest=%s", signatureOID, digestOID)
}

func requireNonnegativeBigInteger(value derValue, label string) (*big.Int, error) {
	if err := requireUniversal(value, 2, false, label); err != nil {
		return nil, err
	}
	if len(value.content) == 0 || value.content[0]&0x80 != 0 {
		return nil, fmt.Errorf("%s must be a non-negative DER integer", label)
	}
	if len(value.content) > 1 && value.content[0] == 0 && value.content[1]&0x80 == 0 {
		return nil, fmt.Errorf("%s uses non-minimal DER integer encoding", label)
	}
	return new(big.Int).SetBytes(value.content), nil
}

func certificateFingerprint(certificate *x509.Certificate) string {
	digest := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(digest[:])
}

func catalogSignaturePlanDigest(plan CatalogSignaturePlan) string {
	digest := sha256.New()
	writeSignatureUint64(digest, uint64(plan.Schema))
	writeSignatureUint64(digest, plan.SourceFileSize)
	writeSignatureString(digest, plan.CatalogMemberPlanSHA256)
	writeSignatureString(digest, plan.CatalogSHA256)
	writeSignatureString(digest, plan.EncapsulatedContentTypeOID)
	writeSignatureUint64(digest, plan.EncapsulatedContentLength)
	writeSignatureString(digest, plan.EncapsulatedContentSHA256)
	writeSignatureUint64(digest, uint64(plan.SignerIndex))
	writeSignatureString(digest, plan.SignerIdentifierType)
	writeSignatureString(digest, plan.SignerIdentifierSHA256)
	writeSignatureUint64(digest, uint64(plan.CertificateIndex))
	writeSignatureString(digest, plan.CertificateSHA256)
	writeSignatureString(digest, plan.CertificateSubject)
	writeSignatureString(digest, plan.DigestAlgorithmOID)
	writeSignatureString(digest, plan.DigestAlgorithm)
	writeSignatureString(digest, plan.SignatureAlgorithmOID)
	writeSignatureString(digest, plan.SignatureAlgorithm)
	writeSignatureString(digest, plan.SignedAttributesSHA256)
	writeSignatureUint64(digest, uint64(len(plan.SignedAttributeOIDs)))
	for _, oid := range plan.SignedAttributeOIDs {
		writeSignatureString(digest, oid)
	}
	writeSignatureString(digest, plan.EncodedMessageDigest)
	writeSignatureString(digest, plan.CalculatedMessageDigest)
	writeSignatureBool(digest, plan.ContentDigestVerified)
	writeSignatureBool(digest, plan.SignatureVerificationAttempted)
	writeSignatureBool(digest, plan.CryptographicSignatureVerified)
	writeSignatureBool(digest, plan.CertificateChainBuilt)
	writeSignatureBool(digest, plan.PublisherTrusted)
	writeSignatureBool(digest, plan.HashTableCatalogAuthenticated)
	return hex.EncodeToString(digest.Sum(nil))
}

func writeSignatureUint64(digest hash.Hash, value uint64) {
	var buffer [8]byte
	binary.LittleEndian.PutUint64(buffer[:], value)
	_, _ = digest.Write(buffer[:])
}

func writeSignatureString(digest hash.Hash, value string) {
	writeSignatureUint64(digest, uint64(len(value)))
	_, _ = digest.Write([]byte(value))
}

func writeSignatureBool(digest hash.Hash, value bool) {
	if value {
		writeSignatureUint64(digest, 1)
		return
	}
	writeSignatureUint64(digest, 0)
}
