package operationcost

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepositoryOperationCostContract(t *testing.T) {
	contract := loadRepositoryContract(t)
	if contract.ReviewedUpstream.Repository != "pbatard/rufus" {
		t.Fatalf("reviewed upstream = %q", contract.ReviewedUpstream.Repository)
	}
}

func TestValidateRejectsCapacityScaledOrdinaryCreation(t *testing.T) {
	contract := loadRepositoryContract(t)
	operation := findOperationIndex(t, contract, "freedos_create")
	contract.Operations[operation].Phases[0].Scaling = "target_capacity"
	if err := Validate(contract); err == nil || !strings.Contains(err.Error(), "must not perform default target_write work scaled to target_capacity") {
		t.Fatalf("capacity-scaled ordinary creation error = %v", err)
	}
}

func TestValidateKeepsExhaustiveQualificationExplicit(t *testing.T) {
	contract := loadRepositoryContract(t)
	operation := findOperationIndex(t, contract, "check_usb_full")
	contract.Operations[operation].Classification = "ordinary_creation"
	if err := Validate(contract); err == nil || !strings.Contains(err.Error(), "must not perform default target_write work scaled to target_capacity") {
		t.Fatalf("misclassified full qualification error = %v", err)
	}
}

func TestValidateRequiresEveryPublicWorkflow(t *testing.T) {
	contract := loadRepositoryContract(t)
	operation := findOperationIndex(t, contract, "windows_install")
	contract.Operations = append(contract.Operations[:operation], contract.Operations[operation+1:]...)
	if err := Validate(contract); err == nil || !strings.Contains(err.Error(), `required operation "windows_install" is missing`) {
		t.Fatalf("missing public workflow error = %v", err)
	}
}

func TestValidateRequiresOneDefaultWindowsISOHash(t *testing.T) {
	contract := loadRepositoryContract(t)
	operation := findOperationIndex(t, contract, "windows_install")
	contract.Operations[operation].Phases[0].Multiplier = 3
	if err := Validate(contract); err == nil || !strings.Contains(err.Error(), "authenticate_held_iso") {
		t.Fatalf("Windows default source-hash boundary error = %v", err)
	}
}

func TestValidateRequiresOneDefaultPersistentLinuxSourceHash(t *testing.T) {
	contract := loadRepositoryContract(t)
	operation := findOperationIndex(t, contract, "linux_persistent_create")
	contract.Operations[operation].Phases[0].Multiplier = 3
	if err := Validate(contract); err == nil || !strings.Contains(err.Error(), "authenticate_held_source_image") {
		t.Fatalf("persistent Linux default source-hash boundary error = %v", err)
	}
}

func TestValidateForbidsRawVerificationSourcePass(t *testing.T) {
	contract := loadRepositoryContract(t)
	operation := findOperationIndex(t, contract, "raw_image_write")
	contract.Operations[operation].Phases = append(contract.Operations[operation].Phases, Phase{
		Name:             "verification_source_read",
		Direction:        "source_read",
		Scaling:          "source_size",
		Multiplier:       1,
		EnabledByDefault: false,
	})
	if err := Validate(contract); err == nil || !strings.Contains(err.Error(), "must not contain phase verification_source_read") {
		t.Fatalf("raw optional source reread boundary error = %v", err)
	}
}

func TestValidateRequiresSinglePreparedRawWriterRead(t *testing.T) {
	contract := loadRepositoryContract(t)
	for _, id := range []string{"compressed_image_prepare", "zip_image_prepare", "virtual_disk_prepare"} {
		operation := findOperationIndex(t, contract, id)
		for phase := range contract.Operations[operation].Phases {
			if contract.Operations[operation].Phases[phase].Name == "write_authenticated_prepared_raw" {
				contract.Operations[operation].Phases[phase].Multiplier = 2
			}
		}
		if err := Validate(contract); err == nil || !strings.Contains(err.Error(), "write_authenticated_prepared_raw") {
			t.Fatalf("%s prepared raw read boundary error = %v", id, err)
		}
		contract = loadRepositoryContract(t)
	}
}

func TestDecodeRejectsUnknownFieldsAndTrailingJSON(t *testing.T) {
	for name, value := range map[string]string{
		"unknown":  `{"schema":1,"reviewed_upstream":{"repository":"pbatard/rufus","commit":"0000000000000000000000000000000000000000","paths":["src/format.c"]},"scaling_bases":[],"operations":[],"unexpected":true}`,
		"trailing": `{"schema":1,"reviewed_upstream":{"repository":"pbatard/rufus","commit":"0000000000000000000000000000000000000000","paths":["src/format.c"]},"scaling_bases":[],"operations":[]} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(strings.NewReader(value)); err == nil {
				t.Fatal("Decode accepted an invalid contract")
			}
		})
	}
}

func loadRepositoryContract(t *testing.T) Contract {
	t.Helper()
	path := filepath.Join("..", "..", "docs", "operation-cost-contract.json")
	file, err := os.Open(path)
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

func findOperationIndex(t *testing.T, contract Contract, id string) int {
	t.Helper()
	for index, operation := range contract.Operations {
		if operation.ID == id {
			return index
		}
	}
	t.Fatalf("operation %q not found", id)
	return -1
}
