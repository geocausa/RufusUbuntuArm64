//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseFFUCLIOptionsRequiresExplicitExperimentalBoundary(t *testing.T) {
	args := validFFUCLIArgumentFixture(t)
	withoutExperimental := append([]string(nil), args...)
	withoutExperimental = withoutExperimental[:len(withoutExperimental)-1]
	if _, err := parseFFUCLIOptions("review", withoutExperimental, false); err == nil || !strings.Contains(err.Error(), "--experimental-ffu is required") {
		t.Fatalf("missing experimental boundary error = %v", err)
	}
	options, err := parseFFUCLIOptions("review", args, false)
	if err != nil {
		t.Fatal(err)
	}
	if options.imagePath == "" || options.devicePath == "" || options.expectedTargetIdentity == "" || options.targetSizeBytes == 0 || options.logicalSectorBytes == 0 || options.physicalSectorBytes == 0 || !options.experimental {
		t.Fatalf("parsed FFU options are incomplete: %#v", options)
	}
}

func TestParseFFUCLIRestoreRequiresExactConfirmationInput(t *testing.T) {
	args := validFFUCLIArgumentFixture(t)
	if _, err := parseFFUCLIOptions("restore", args, true); err == nil || !strings.Contains(err.Error(), "--confirm is required") {
		t.Fatalf("missing confirmation error = %v", err)
	}
	args = append(args, "--confirm", "RESTORE AUTHENTICATED FFU TO /dev/test SIZE 32768 BYTES")
	options, err := parseFFUCLIOptions("restore", args, true)
	if err != nil {
		t.Fatal(err)
	}
	if options.confirmationPhrase == "" {
		t.Fatal("restore confirmation phrase was not parsed")
	}
}

func TestFFURestoreRequiresRootBeforeOpeningInputs(t *testing.T) {
	previousUID := ffuCLIGeteuid
	previousContext := ffuCLIContext
	ffuCLIGeteuid = func() int { return 1000 }
	ffuCLIContext = func() (context.Context, context.CancelFunc) {
		t.Fatal("signal context was created before the root gate")
		return nil, nil
	}
	defer func() {
		ffuCLIGeteuid = previousUID
		ffuCLIContext = previousContext
	}()
	args := append(validFFUCLIArgumentFixture(t), "--confirm", "exact phrase")
	if err := runFFURestore(args); err == nil || err.Error() != "FFU restore requires administrator privileges" {
		t.Fatalf("non-root restore error = %v", err)
	}
}

func TestFFUReviewHonorsCancellationBeforeOpeningInputs(t *testing.T) {
	previous := ffuCLIContext
	ffuCLIContext = cancelledFFUCLIContext
	defer func() { ffuCLIContext = previous }()
	if err := runFFUReview(validFFUCLIArgumentFixture(t)); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-input review cancellation error = %v", err)
	}
}

func TestFFURestoreHonorsCancellationBeforeOpeningInputs(t *testing.T) {
	previousUID := ffuCLIGeteuid
	previousContext := ffuCLIContext
	ffuCLIGeteuid = func() int { return 0 }
	ffuCLIContext = cancelledFFUCLIContext
	defer func() {
		ffuCLIGeteuid = previousUID
		ffuCLIContext = previousContext
	}()
	args := append(validFFUCLIArgumentFixture(t), "--confirm", "exact phrase")
	if err := runFFURestore(args); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-input restore cancellation error = %v", err)
	}
}

func TestNewFFUCLIContextRejectsInvalidFactoryResult(t *testing.T) {
	previous := ffuCLIContext
	ffuCLIContext = func() (context.Context, context.CancelFunc) { return nil, nil }
	defer func() { ffuCLIContext = previous }()
	if _, _, err := newFFUCLIContext(); err == nil || !strings.Contains(err.Error(), "invalid context") {
		t.Fatalf("invalid signal context error = %v", err)
	}
}

func cancelledFFUCLIContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx, cancel
}

func TestReadStrictFFUCLIJSON(t *testing.T) {
	type policy struct {
		Version uint64 `json:"version"`
	}
	directory := t.TempDir()
	validPath := filepath.Join(directory, "valid.json")
	if err := os.WriteFile(validPath, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	value, err := readStrictFFUCLIJSON[policy](validPath)
	if err != nil || value.Version != 1 {
		t.Fatalf("valid policy=%#v error=%v", value, err)
	}
	for name, data := range map[string]string{
		"unknown":  `{"version":1,"unknown":true}`,
		"multiple": `{"version":1} {"version":2}`,
		"empty":    ``,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(directory, name+".json")
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := readStrictFFUCLIJSON[policy](path); err == nil {
				t.Fatalf("invalid %s policy was accepted", name)
			}
		})
	}
}

func TestRunRecognizesFFUCommand(t *testing.T) {
	if err := run([]string{"ffu"}); err == nil || !strings.Contains(err.Error(), "ffu <review|restore>") {
		t.Fatalf("FFU dispatch error = %v", err)
	}
	if err := runFFU([]string{"unknown"}); err == nil || !strings.Contains(err.Error(), "unknown FFU command") {
		t.Fatalf("unknown FFU subcommand error = %v", err)
	}
}

func TestFFUCLIProviderSourceContract(t *testing.T) {
	data, err := os.ReadFile("ffu_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{
		"ActivateAuthenticatedTrustBundle",
		"PlanSingleStoreV1",
		"ResolveAuthenticatedSingleStoreV1FullFlash",
		"DiscoverFullFlashTargetPreflight",
		"AcquireAuthenticatedFullFlashSourceLease",
		"AcquireExclusiveFullFlashTarget",
		"ConfirmExclusiveFullFlashTarget",
		"AuthorizeSinglePhaseFullFlashMutation",
		"ExecuteAuthorizedSinglePhaseFullFlash",
		"FFU target must be fully unmounted before restore",
		"FFU restore requires administrator privileges",
		"sourcefile.OpenRegular",
		"sourcefile.Verify",
		"signal.NotifyContext",
		"os.Interrupt",
		"syscall.SIGTERM",
		"ctx.Err()",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("FFU CLI provider is missing required boundary %q", required)
		}
	}
	for _, forbidden := range []string{
		"--allow-fixed",
		"--no-unmount",
		"--force",
		"exec.Command",
		"pkexec",
		"polkit",
		"syscall.Unmount",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("FFU CLI provider contains forbidden bypass or nested privilege primitive %q", forbidden)
		}
	}
}

func validFFUCLIArgumentFixture(t testing.TB) []string {
	t.Helper()
	return []string{
		"--image", filepath.Join(t.TempDir(), "source.ffu"),
		"--device", "/dev/test",
		"--expected-identity", strings.Repeat("a", 64),
		"--target-size", "32768",
		"--logical-sector-size", "512",
		"--physical-sector-size", "512",
		"--trust-store", filepath.Join(t.TempDir(), "trust"),
		"--trust-metadata-policy", filepath.Join(t.TempDir(), "metadata-policy.json"),
		"--publisher-policy", filepath.Join(t.TempDir(), "publisher-policy.json"),
		"--experimental-ffu",
	}
}
