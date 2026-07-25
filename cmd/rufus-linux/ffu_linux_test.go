//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geocausa/RufusArm64/internal/sourcefile"
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
	args = append(args,
		"--confirm", "RESTORE AUTHENTICATED FFU TO /dev/test SIZE 32768 BYTES",
		"--expected-review-binding", strings.Repeat("b", 64),
	)
	options, err := parseFFUCLIOptions("restore", args, true)
	if err != nil {
		t.Fatal(err)
	}
	if options.confirmationPhrase == "" || options.expectedReviewBinding == "" {
		t.Fatal("restore confirmation phrase or review binding was not parsed")
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
	args := append(validFFUCLIArgumentFixture(t), "--confirm", "exact phrase", "--expected-review-binding", strings.Repeat("b", 64))
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
	args := append(validFFUCLIArgumentFixture(t), "--confirm", "exact phrase", "--expected-review-binding", strings.Repeat("b", 64))
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
	boundValue, resolved, identity, err := readStrictFFUCLIJSONWithIdentity[policy](validPath)
	if err != nil || boundValue != value || resolved != validPath || identity.Size <= 0 {
		t.Fatalf("identity-bound policy=%#v path=%q identity=%#v error=%v", boundValue, resolved, identity, err)
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

func TestFFUCLIReviewBindingIsDeterministicAndSubstitutionSensitive(t *testing.T) {
	binding := ffuCLIReviewBinding{
		Schema: ffuCLIReviewBindingSchema, Purpose: ffuCLIReviewBindingPurpose,
		SourcePath: "/images/source.ffu", SourceIdentity: sourcefile.Identity{Device: 1, Inode: 2, Size: 4096, ModifiedNS: 3, ChangedNS: 4}, SourceFileSize: 4096,
		DescriptorPlanSHA256: strings.Repeat("a", 64), CatalogSHA256: strings.Repeat("b", 64), HashTableSHA256: strings.Repeat("c", 64),
		TrustStoreRoot: "/var/lib/rufusarm64/ffu-trust", TrustGeneration: "generation-1", TrustSequence: 1, TrustBundleSHA256: strings.Repeat("d", 64),
		TrustMetadataPolicyPath: "/etc/rufusarm64/metadata.json", TrustMetadataPolicyIdentity: sourcefile.Identity{Device: 5, Inode: 6, Size: 100, ModifiedNS: 7, ChangedNS: 8},
		PublisherPolicyPath: "/etc/rufusarm64/publishers.json", PublisherPolicyIdentity: sourcefile.Identity{Device: 9, Inode: 10, Size: 100, ModifiedNS: 11, ChangedNS: 12},
		DevicePath: "/dev/sdz", ExpectedTargetIdentity: strings.Repeat("e", 64), TargetSizeBytes: 32768, LogicalSectorSizeBytes: 512, PhysicalSectorSizeBytes: 4096,
		KernelDeviceID: 123, MajorMinor: "8:240", ExactConfirmationPhrase: "RESTORE AUTHENTICATED FFU TO /dev/sdz SIZE 32768 BYTES",
	}
	if err := validateFFUCLIReviewBinding(binding); err != nil {
		t.Fatal(err)
	}
	first, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	firstDigest := sha256.Sum256(first)
	second, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	secondDigest := sha256.Sum256(second)
	if firstDigest != secondDigest {
		t.Fatal("review binding digest is nondeterministic")
	}
	changed := binding
	changed.SourceIdentity.Inode++
	changedBytes, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	changedDigest := sha256.Sum256(changedBytes)
	if firstDigest == changedDigest {
		t.Fatal("source substitution did not change review binding")
	}
}

func TestRequireExpectedFFUCLIReviewBinding(t *testing.T) {
	valid := strings.Repeat("a", 64)
	if err := requireExpectedFFUCLIReviewBinding(valid, valid); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{"", strings.Repeat("A", 64), strings.Repeat("b", 64)} {
		if err := requireExpectedFFUCLIReviewBinding(candidate, valid); err == nil {
			t.Fatalf("invalid or substituted review binding %q was accepted", candidate)
		}
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
		"requireExpectedFFUCLIReviewBinding",
		"ReviewBindingSHA256",
		"readStrictFFUCLIJSONWithIdentity",
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
