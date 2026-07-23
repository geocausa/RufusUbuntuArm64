package defaultparity

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

type Contract struct {
	Schema           int               `json:"schema"`
	ReviewedUpstream UpstreamReference `json:"reviewed_upstream"`
	Defaults         []DefaultRule     `json:"defaults"`
}

type UpstreamReference struct {
	Repository string   `json:"repository"`
	Commit     string   `json:"commit"`
	Paths      []string `json:"paths"`
}

type DefaultRule struct {
	ID         string   `json:"id"`
	Upstream   string   `json:"upstream"`
	RufusArm64 string   `json:"rufusarm64"`
	Status     string   `json:"status"`
	HighRisk   bool     `json:"high_risk"`
	Sources    []string `json:"sources"`
	Note       string   `json:"note"`
}

var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
var idPattern = regexp.MustCompile(`^[a-z0-9]+(?:_[a-z0-9]+)*$`)

var requiredDefaults = map[string][2]string{
	"post_write_verification":  {"off", "off"},
	"quick_format":             {"on", "on"},
	"bad_block_check":          {"off", "off"},
	"windows_partition_scheme": {"image_derived", "image_derived"},
	"windows_target_system":    {"image_derived", "image_derived"},
	"windows_filesystem":       {"fat32_preferred", "fat32_preferred"},
	"windows_cluster_size":     {"automatic", "automatic"},
	"persistence":              {"off", "off"},
	"persistence_size":         {"zero", "zero"},
	"windows_customizations":   {"off", "off"},
	"raw_isohybrid_mode":       {"embedded_layout", "embedded_layout"},
	"volume_label":             {"image_derived", "static_rufusarm64"},
}

func Decode(reader io.Reader) (Contract, error) {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	var contract Contract
	if err := decoder.Decode(&contract); err != nil {
		return Contract{}, fmt.Errorf("decode upstream-default contract: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return Contract{}, fmt.Errorf("upstream-default contract contains trailing JSON")
		}
		return Contract{}, fmt.Errorf("decode trailing upstream-default data: %w", err)
	}
	if err := Validate(contract); err != nil {
		return Contract{}, err
	}
	return contract, nil
}

func Validate(contract Contract) error {
	if contract.Schema != 1 {
		return fmt.Errorf("upstream-default schema must be 1, got %d", contract.Schema)
	}
	if contract.ReviewedUpstream.Repository != "pbatard/rufus" {
		return fmt.Errorf("reviewed upstream repository must be pbatard/rufus")
	}
	if !commitPattern.MatchString(contract.ReviewedUpstream.Commit) {
		return fmt.Errorf("reviewed upstream commit must be a lowercase 40-character Git object ID")
	}
	if len(contract.ReviewedUpstream.Paths) == 0 {
		return fmt.Errorf("reviewed upstream paths must not be empty")
	}
	rules := make(map[string]DefaultRule, len(contract.Defaults))
	for _, rule := range contract.Defaults {
		if !idPattern.MatchString(rule.ID) {
			return fmt.Errorf("invalid default ID %q", rule.ID)
		}
		if _, duplicate := rules[rule.ID]; duplicate {
			return fmt.Errorf("duplicate default ID %q", rule.ID)
		}
		if strings.TrimSpace(rule.Upstream) == "" || strings.TrimSpace(rule.RufusArm64) == "" ||
			strings.TrimSpace(rule.Note) == "" || len(rule.Sources) == 0 {
			return fmt.Errorf("default %s must describe both values, sources, and rationale", rule.ID)
		}
		switch rule.Status {
		case "conformant":
			if rule.Upstream != rule.RufusArm64 {
				return fmt.Errorf("conformant default %s has unequal values", rule.ID)
			}
		case "divergence":
			if rule.Upstream == rule.RufusArm64 {
				return fmt.Errorf("divergent default %s has equal values", rule.ID)
			}
		default:
			return fmt.Errorf("default %s has invalid status %q", rule.ID, rule.Status)
		}
		rules[rule.ID] = rule
	}
	for id, expected := range requiredDefaults {
		rule, ok := rules[id]
		if !ok {
			return fmt.Errorf("required default %q is missing", id)
		}
		if rule.Upstream != expected[0] || rule.RufusArm64 != expected[1] {
			return fmt.Errorf("default %s must remain %s/%s, got %s/%s", id, expected[0], expected[1], rule.Upstream, rule.RufusArm64)
		}
		if id != "volume_label" && !rule.HighRisk {
			return fmt.Errorf("default %s must remain high-risk", id)
		}
	}
	return nil
}
