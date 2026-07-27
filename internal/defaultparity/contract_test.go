package defaultparity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepositoryDefaultContract(t *testing.T) {
	contract := loadRepositoryContract(t)
	if contract.ReviewedUpstream.Commit != "6d8fbf98305ff37eb531c45cbd6ff44563c53917" {
		t.Fatalf("reviewed upstream commit=%q", contract.ReviewedUpstream.Commit)
	}
}

func TestValidateRejectsVerificationDefaultOn(t *testing.T) {
	contract := loadRepositoryContract(t)
	index := findRule(t, contract, "post_write_verification")
	contract.Defaults[index].RufusArm64 = "on"
	if err := Validate(contract); err == nil || !strings.Contains(err.Error(), "post_write_verification") {
		t.Fatalf("verification default error=%v", err)
	}
}

func TestValidateRejectsConcreteWindowsLayoutDefault(t *testing.T) {
	for _, id := range []string{"windows_partition_scheme", "windows_target_system"} {
		contract := loadRepositoryContract(t)
		index := findRule(t, contract, id)
		contract.Defaults[index].RufusArm64 = "gpt"
		if err := Validate(contract); err == nil || !strings.Contains(err.Error(), id) {
			t.Fatalf("%s concrete default error=%v", id, err)
		}
	}
}

func TestValidateKeepsCapacityScaledOptionsOff(t *testing.T) {
	for _, id := range []string{"quick_format", "bad_block_check"} {
		contract := loadRepositoryContract(t)
		index := findRule(t, contract, id)
		contract.Defaults[index].RufusArm64 = "wrong"
		if err := Validate(contract); err == nil || !strings.Contains(err.Error(), id) {
			t.Fatalf("%s default error=%v", id, err)
		}
	}
}

func TestDecodeRejectsUnknownAndTrailingData(t *testing.T) {
	for name, text := range map[string]string{
		"unknown":  `{"schema":1,"reviewed_upstream":{"repository":"pbatard/rufus","commit":"0000000000000000000000000000000000000000","paths":["src/rufus.c"]},"defaults":[],"extra":true}`,
		"trailing": `{"schema":1,"reviewed_upstream":{"repository":"pbatard/rufus","commit":"0000000000000000000000000000000000000000","paths":["src/rufus.c"]},"defaults":[]} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(strings.NewReader(text)); err == nil {
				t.Fatal("invalid contract was accepted")
			}
		})
	}
}

func loadRepositoryContract(t *testing.T) Contract {
	t.Helper()
	file, err := os.Open(filepath.Join("..", "..", "docs", "upstream-default-contract.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	contract, err := Decode(file)
	if err != nil {
		t.Fatal(err)
	}
	return contract
}

func findRule(t *testing.T, contract Contract, id string) int {
	t.Helper()
	for index, rule := range contract.Defaults {
		if rule.ID == id {
			return index
		}
	}
	t.Fatalf("default %q not found", id)
	return -1
}
