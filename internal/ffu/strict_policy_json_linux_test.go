//go:build linux

package ffu

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTrustMetadataPolicyJSONRejectsAmbiguity(t *testing.T) {
	valid := `{"version":1,"threshold":1,"keys":[{"id":"key-1","algorithm":"ed25519","public_key_base64":"AA=="}]}`
	var policy TrustMetadataPolicy
	if err := json.Unmarshal([]byte(valid), &policy); err != nil {
		t.Fatalf("valid trust-metadata policy rejected: %v", err)
	}
	if policy.Version != 1 || policy.Threshold != 1 || len(policy.Keys) != 1 {
		t.Fatalf("trust-metadata policy decoded incorrectly: %#v", policy)
	}

	cases := map[string]string{
		"top-level duplicate": `{"version":1,"version":2,"threshold":1,"keys":[]}`,
		"escaped duplicate":   `{"version":1,"ver\u0073ion":2,"threshold":1,"keys":[]}`,
		"nested duplicate":    `{"version":1,"threshold":1,"keys":[{"id":"a","id":"b","algorithm":"ed25519","public_key_base64":"AA=="}]}`,
		"unknown member":      `{"version":1,"threshold":1,"keys":[],"unexpected":true}`,
		"multiple values":     `{"version":1,"threshold":1,"keys":[]} {"version":2,"threshold":1,"keys":[]}`,
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			var candidate TrustMetadataPolicy
			err := json.Unmarshal([]byte(data), &candidate)
			if err == nil {
				t.Fatal("ambiguous or unknown trust-metadata policy was accepted")
			}
			if strings.Contains(name, "duplicate") && !strings.Contains(err.Error(), "duplicate JSON member") {
				t.Fatalf("unexpected duplicate-member error: %v", err)
			}
		})
	}
}

func TestCatalogPublisherPolicyJSONRejectsAmbiguity(t *testing.T) {
	valid := `{"schema":1,"purpose":"ffu-catalog-publisher-policy","policy_id":"policy-1","version":1,"generated_at":"2026-01-01T00:00:00Z","expires_at":"2027-01-01T00:00:00Z","rules":[{"id":"rule-1","identity_kind":"certificate_sha256","identity_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","root_id":"root-1","root_certificate_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}`
	var policy CatalogPublisherPolicy
	if err := json.Unmarshal([]byte(valid), &policy); err != nil {
		t.Fatalf("valid catalog-publisher policy rejected: %v", err)
	}
	if policy.Schema != 1 || policy.PolicyID != "policy-1" || len(policy.Rules) != 1 {
		t.Fatalf("catalog-publisher policy decoded incorrectly: %#v", policy)
	}

	cases := map[string]string{
		"top-level duplicate": `{"schema":1,"purpose":"ffu-catalog-publisher-policy","policy_id":"a","policy_id":"b","version":1,"generated_at":"2026-01-01T00:00:00Z","expires_at":"2027-01-01T00:00:00Z","rules":[]}`,
		"escaped duplicate":   `{"schema":1,"purpose":"ffu-catalog-publisher-policy","policy_id":"a","policy_\u0069d":"b","version":1,"generated_at":"2026-01-01T00:00:00Z","expires_at":"2027-01-01T00:00:00Z","rules":[]}`,
		"nested duplicate":    `{"schema":1,"purpose":"ffu-catalog-publisher-policy","policy_id":"a","version":1,"generated_at":"2026-01-01T00:00:00Z","expires_at":"2027-01-01T00:00:00Z","rules":[{"id":"a","id":"b","identity_kind":"certificate_sha256","identity_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","root_id":"root-1","root_certificate_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}`,
		"unknown member":      `{"schema":1,"purpose":"ffu-catalog-publisher-policy","policy_id":"a","version":1,"generated_at":"2026-01-01T00:00:00Z","expires_at":"2027-01-01T00:00:00Z","rules":[],"unexpected":true}`,
		"multiple values":     `{"schema":1,"purpose":"ffu-catalog-publisher-policy","policy_id":"a","version":1,"generated_at":"2026-01-01T00:00:00Z","expires_at":"2027-01-01T00:00:00Z","rules":[]} {"schema":1}`,
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			var candidate CatalogPublisherPolicy
			err := json.Unmarshal([]byte(data), &candidate)
			if err == nil {
				t.Fatal("ambiguous or unknown catalog-publisher policy was accepted")
			}
			if strings.Contains(name, "duplicate") && !strings.Contains(err.Error(), "duplicate JSON member") {
				t.Fatalf("unexpected duplicate-member error: %v", err)
			}
		})
	}
}
