package qualification_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

const interruptionMatrixPath = "docs/interruption-qualification.json"

type interruptionMatrix struct {
	SchemaVersion        int                    `json:"schema_version"`
	Title                string                 `json:"title"`
	RequiredBoundaries   []string               `json:"required_boundaries"`
	Entries              []interruptionEntry    `json:"entries"`
	ResidualSoftwareGaps []interruptionGapEntry `json:"residual_software_gaps"`
}

type interruptionEntry struct {
	ID          string   `json:"id"`
	Boundary    string   `json:"boundary"`
	Component   string   `json:"component"`
	FailureMode string   `json:"failure_mode"`
	Phase       string   `json:"phase"`
	Status      string   `json:"status"`
	TestFile    string   `json:"test_file"`
	TestName    string   `json:"test_name"`
	Platforms   []string `json:"platforms"`
	Invariant   string   `json:"invariant"`
}

type interruptionGapEntry struct {
	ID              string `json:"id"`
	Boundary        string `json:"boundary"`
	Component       string `json:"component"`
	FailureMode     string `json:"failure_mode"`
	Reason          string `json:"reason"`
	PlannedTestKind string `json:"planned_test_kind"`
}

func TestInterruptionQualificationMatrix(t *testing.T) {
	root := repositoryRoot(t)
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(interruptionMatrixPath)))
	if err != nil {
		t.Fatal(err)
	}
	document, err := decodeInterruptionMatrix(data)
	if err != nil {
		t.Fatal(err)
	}
	errorsFound := validateInterruptionMatrix(document, func(path string) ([]byte, error) {
		return os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
	})
	if len(errorsFound) != 0 {
		t.Fatalf("interruption qualification matrix is invalid:\n- %s", strings.Join(errorsFound, "\n- "))
	}
}

func TestInterruptionQualificationMatrixValidatorRejectsIncompleteDocuments(t *testing.T) {
	document := interruptionMatrix{
		SchemaVersion:      1,
		Title:              "test matrix",
		RequiredBoundaries: []string{"covered", "missing", "covered"},
		Entries: []interruptionEntry{
			{
				ID:          "duplicate",
				Boundary:    "covered",
				Component:   "component",
				FailureMode: "failure",
				Phase:       "post-mutation",
				Status:      "automated",
				TestFile:    "internal/example/missing_test.go",
				TestName:    "TestMissing",
				Platforms:   []string{"linux-arm64"},
				Invariant:   "never reports success",
			},
		},
		ResidualSoftwareGaps: []interruptionGapEntry{
			{ID: "duplicate", Boundary: "covered"},
		},
	}
	errorsFound := validateInterruptionMatrix(document, func(string) ([]byte, error) {
		return nil, os.ErrNotExist
	})
	joined := strings.Join(errorsFound, "\n")
	for _, expected := range []string{
		"required boundary covered is duplicated",
		"required boundary missing is not represented",
		"test file internal/example/missing_test.go",
		"id duplicate is duplicated",
		"planned test kind is empty",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("validator did not report %q:\n%s", expected, joined)
		}
	}
}

func decodeInterruptionMatrix(data []byte) (interruptionMatrix, error) {
	var document interruptionMatrix
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return interruptionMatrix{}, fmt.Errorf("decode %s: %w", interruptionMatrixPath, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return interruptionMatrix{}, fmt.Errorf("decode %s: trailing JSON value", interruptionMatrixPath)
		}
		return interruptionMatrix{}, fmt.Errorf("decode %s trailing data: %w", interruptionMatrixPath, err)
	}
	return document, nil
}

func validateInterruptionMatrix(document interruptionMatrix, readFile func(string) ([]byte, error)) []string {
	var failures []string
	if document.SchemaVersion != 1 {
		failures = append(failures, fmt.Sprintf("schema_version = %d, want 1", document.SchemaVersion))
	}
	if strings.TrimSpace(document.Title) == "" {
		failures = append(failures, "title is empty")
	}
	if len(document.RequiredBoundaries) == 0 {
		failures = append(failures, "required_boundaries is empty")
	}
	if len(document.Entries) == 0 {
		failures = append(failures, "entries is empty")
	}

	required := make(map[string]struct{}, len(document.RequiredBoundaries))
	for _, boundary := range document.RequiredBoundaries {
		boundary = strings.TrimSpace(boundary)
		if boundary == "" {
			failures = append(failures, "required boundary is empty")
			continue
		}
		if _, exists := required[boundary]; exists {
			failures = append(failures, fmt.Sprintf("required boundary %s is duplicated", boundary))
			continue
		}
		required[boundary] = struct{}{}
	}

	covered := make(map[string]struct{})
	ids := make(map[string]struct{})
	for index, entry := range document.Entries {
		prefix := fmt.Sprintf("entry[%d]", index)
		validateIdentifier(&failures, ids, prefix, entry.ID)
		validateRequiredText(&failures, prefix, "boundary", entry.Boundary)
		validateRequiredText(&failures, prefix, "component", entry.Component)
		validateRequiredText(&failures, prefix, "failure_mode", entry.FailureMode)
		validateRequiredText(&failures, prefix, "phase", entry.Phase)
		validateRequiredText(&failures, prefix, "invariant", entry.Invariant)
		if _, exists := required[entry.Boundary]; !exists {
			failures = append(failures, fmt.Sprintf("%s boundary %s is not declared in required_boundaries", prefix, entry.Boundary))
		} else {
			covered[entry.Boundary] = struct{}{}
		}
		validatePlatforms(&failures, prefix, entry.Platforms)

		switch entry.Status {
		case "automated":
			if entry.Phase == "physical-only" {
				failures = append(failures, fmt.Sprintf("%s automated entry uses physical-only phase", prefix))
			}
			if !safeRepositoryPath(entry.TestFile) {
				failures = append(failures, fmt.Sprintf("%s test_file %q is not a safe repository-relative path", prefix, entry.TestFile))
				break
			}
			var needle string
			switch {
			case strings.HasSuffix(entry.TestFile, "_test.go"):
				if !strings.HasPrefix(entry.TestName, "Test") {
					failures = append(failures, fmt.Sprintf("%s Go test_name %q does not start with Test", prefix, entry.TestName))
				}
				needle = "func " + entry.TestName + "("
			case strings.HasSuffix(entry.TestFile, ".py") && strings.HasPrefix(filepath.Base(entry.TestFile), "test_"):
				if !strings.HasPrefix(entry.TestName, "test_") {
					failures = append(failures, fmt.Sprintf("%s Python test_name %q does not start with test_", prefix, entry.TestName))
				}
				needle = "def " + entry.TestName + "("
			default:
				failures = append(failures, fmt.Sprintf("%s test_file %s is not a supported Go or Python test file", prefix, entry.TestFile))
			}
			source, err := readFile(entry.TestFile)
			if err != nil {
				failures = append(failures, fmt.Sprintf("%s test file %s cannot be read: %v", prefix, entry.TestFile, err))
				break
			}
			if needle != "" && !bytes.Contains(source, []byte(needle)) {
				failures = append(failures, fmt.Sprintf("%s test %s is not declared in %s", prefix, entry.TestName, entry.TestFile))
			}
		case "physical-only":
			if entry.Phase != "physical-only" {
				failures = append(failures, fmt.Sprintf("%s physical-only entry phase = %q", prefix, entry.Phase))
			}
			if entry.TestFile != "" || entry.TestName != "" {
				failures = append(failures, fmt.Sprintf("%s physical-only entry must not claim an executable test", prefix))
			}
		default:
			failures = append(failures, fmt.Sprintf("%s status = %q, want automated or physical-only", prefix, entry.Status))
		}
	}

	for index, gap := range document.ResidualSoftwareGaps {
		prefix := fmt.Sprintf("residual_software_gaps[%d]", index)
		validateIdentifier(&failures, ids, prefix, gap.ID)
		validateRequiredText(&failures, prefix, "boundary", gap.Boundary)
		validateRequiredText(&failures, prefix, "component", gap.Component)
		validateRequiredText(&failures, prefix, "failure_mode", gap.FailureMode)
		validateRequiredText(&failures, prefix, "reason", gap.Reason)
		if strings.TrimSpace(gap.PlannedTestKind) == "" {
			failures = append(failures, fmt.Sprintf("%s planned test kind is empty", prefix))
		}
		if _, exists := required[gap.Boundary]; !exists {
			failures = append(failures, fmt.Sprintf("%s boundary %s is not declared in required_boundaries", prefix, gap.Boundary))
		} else {
			covered[gap.Boundary] = struct{}{}
		}
		if strings.HasPrefix(gap.Boundary, "physical-") || strings.Contains(strings.ToLower(gap.Reason), "physical-only") {
			failures = append(failures, fmt.Sprintf("%s must describe a software gap, not a physical-only case", prefix))
		}
	}

	for boundary := range required {
		if _, exists := covered[boundary]; !exists {
			failures = append(failures, fmt.Sprintf("required boundary %s is not represented by an entry or residual software gap", boundary))
		}
	}
	sort.Strings(failures)
	return failures
}

func validateIdentifier(failures *[]string, ids map[string]struct{}, prefix, id string) {
	if strings.TrimSpace(id) == "" {
		*failures = append(*failures, fmt.Sprintf("%s id is empty", prefix))
		return
	}
	if _, exists := ids[id]; exists {
		*failures = append(*failures, fmt.Sprintf("%s id %s is duplicated", prefix, id))
		return
	}
	ids[id] = struct{}{}
}

func validateRequiredText(failures *[]string, prefix, field, value string) {
	if strings.TrimSpace(value) == "" {
		*failures = append(*failures, fmt.Sprintf("%s %s is empty", prefix, field))
	}
}

func validatePlatforms(failures *[]string, prefix string, platforms []string) {
	if len(platforms) == 0 {
		*failures = append(*failures, fmt.Sprintf("%s platforms is empty", prefix))
		return
	}
	seen := make(map[string]struct{}, len(platforms))
	for _, platform := range platforms {
		if strings.TrimSpace(platform) == "" {
			*failures = append(*failures, fmt.Sprintf("%s platform is empty", prefix))
			continue
		}
		if _, exists := seen[platform]; exists {
			*failures = append(*failures, fmt.Sprintf("%s platform %s is duplicated", prefix, platform))
			continue
		}
		seen[platform] = struct{}{}
	}
}

func safeRepositoryPath(path string) bool {
	if path == "" || filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller did not return the interruption matrix test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
}
