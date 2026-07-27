//go:build linux

package ffu

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

type trustMetadataPolicyJSON TrustMetadataPolicy
type catalogPublisherPolicyJSON CatalogPublisherPolicy

// UnmarshalJSON rejects duplicate and unknown members before accepting a
// caller-provisioned trust-metadata policy. Member names are compared after JSON
// unescaping, so equivalent escaped spellings cannot bypass the check.
func (policy *TrustMetadataPolicy) UnmarshalJSON(data []byte) error {
	if policy == nil {
		return errors.New("FFU trust-metadata policy destination is nil")
	}
	var decoded trustMetadataPolicyJSON
	if err := decodeStrictUniquePolicyJSON(data, &decoded); err != nil {
		return fmt.Errorf("decode FFU trust-metadata policy: %w", err)
	}
	*policy = TrustMetadataPolicy(decoded)
	return nil
}

// UnmarshalJSON applies the same ambiguity and unknown-field refusal to the
// explicit catalog-publisher allowlist.
func (policy *CatalogPublisherPolicy) UnmarshalJSON(data []byte) error {
	if policy == nil {
		return errors.New("FFU catalog-publisher policy destination is nil")
	}
	var decoded catalogPublisherPolicyJSON
	if err := decodeStrictUniquePolicyJSON(data, &decoded); err != nil {
		return fmt.Errorf("decode FFU catalog-publisher policy: %w", err)
	}
	*policy = CatalogPublisherPolicy(decoded)
	return nil
}

func decodeStrictUniquePolicyJSON(data []byte, destination any) error {
	if len(bytes.TrimSpace(data)) == 0 {
		return errors.New("policy JSON is empty")
	}
	if err := rejectDuplicatePolicyJSONMembers(data); err != nil {
		return err
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("policy JSON contains multiple values")
		}
		return err
	}
	return nil
}

func rejectDuplicatePolicyJSONMembers(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := walkUniquePolicyJSONValue(decoder); err != nil {
		return fmt.Errorf("policy JSON is ambiguous or invalid: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("policy JSON contains multiple values")
		}
		return fmt.Errorf("policy JSON trailing data: %w", err)
	}
	return nil
}

func walkUniquePolicyJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}

	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object member name is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON member %q", key)
			}
			seen[key] = struct{}{}
			if err := walkUniquePolicyJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return errors.New("object did not end with a closing brace")
		}
		return nil
	case '[':
		for decoder.More() {
			if err := walkUniquePolicyJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return errors.New("array did not end with a closing bracket")
		}
		return nil
	default:
		return fmt.Errorf("unexpected opening delimiter %q", delimiter)
	}
}
