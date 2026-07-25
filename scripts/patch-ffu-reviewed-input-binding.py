#!/usr/bin/env python3
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label} anchor count is {count}, expected 1")
    return text.replace(old, new, 1)


source = Path("cmd/rufus-linux/ffu_linux.go")
text = source.read_text()
text = replace_once(text, '''\tconfirmationPhrase     string
\texperimental           bool
''', '''\tconfirmationPhrase     string
\texpectedReviewBinding  string
\texperimental           bool
''', "option review binding")
text = replace_once(text, '''\tTrustActivationSHA256   string                           `json:"trust_activation_sha256"`
\tSourcePath              string                           `json:"source_path"`
''', '''\tTrustActivationSHA256   string                           `json:"trust_activation_sha256"`
\tTrustStoreRoot           string                           `json:"trust_store_root"`
\tTrustGeneration          string                           `json:"trust_generation"`
\tTrustSequence            uint64                           `json:"trust_sequence"`
\tTrustBundleSHA256        string                           `json:"trust_bundle_sha256"`
\tTrustMetadataPolicyPath  string                           `json:"trust_metadata_policy_path"`
\tTrustMetadataIdentity    sourcefile.Identity              `json:"trust_metadata_policy_identity"`
\tPublisherPolicyPath      string                           `json:"publisher_policy_path"`
\tPublisherPolicyIdentity  sourcefile.Identity              `json:"publisher_policy_identity"`
\tReviewBindingSHA256      string                           `json:"review_binding_sha256"`
\tSourcePath              string                           `json:"source_path"`
''', "review stable fields")
text = replace_once(text, '''\tprepared, err := prepareFFUCLIReview(ctx, options)
\tif err != nil {
\t\treturn err
\t}
\tprepared.review.ExecutionAttempted = true
''', '''\tprepared, err := prepareFFUCLIReview(ctx, options)
\tif err != nil {
\t\treturn err
\t}
\tif err := requireExpectedFFUCLIReviewBinding(options.expectedReviewBinding, prepared.review.ReviewBindingSHA256); err != nil {
\t\tcloseErr := prepared.file.Close()
\t\treturn errors.Join(err, closeErr)
\t}
\tprepared.review.ExecutionAttempted = true
''', "restore binding gate")
text = replace_once(text, '''\tif requireConfirmation {
\t\tflags.StringVar(&options.confirmationPhrase, "confirm", "", "exact destructive target-and-capacity phrase")
\t}
''', '''\tif requireConfirmation {
\t\tflags.StringVar(&options.confirmationPhrase, "confirm", "", "exact destructive target-and-capacity phrase")
\t\tflags.StringVar(&options.expectedReviewBinding, "expected-review-binding", "", "exact reviewed source, trust-policy, and target binding SHA-256")
\t}
''', "restore binding flag")
text = replace_once(text, '''\tif requireConfirmation && options.confirmationPhrase == "" {
\t\treturn ffuCLIOptions{}, errors.New("--confirm is required")
\t}
''', '''\tif requireConfirmation && options.confirmationPhrase == "" {
\t\treturn ffuCLIOptions{}, errors.New("--confirm is required")
\t}
\tif requireConfirmation && options.expectedReviewBinding == "" {
\t\treturn ffuCLIOptions{}, errors.New("--expected-review-binding is required")
\t}
\tif requireConfirmation && !isCanonicalFFUCLISHA256(options.expectedReviewBinding) {
\t\treturn ffuCLIOptions{}, errors.New("--expected-review-binding must be one lowercase SHA-256")
\t}
''', "restore binding requirement")
text = replace_once(text, '''\tmetadataPolicy, err := readStrictFFUCLIJSON[ffu.TrustMetadataPolicy](options.trustMetadataPolicy)
\tif err != nil {
\t\treturn preparedFFUCLIReview{}, fmt.Errorf("read FFU trust metadata policy: %w", err)
\t}
\tpublisherPolicy, err := readStrictFFUCLIJSON[ffu.CatalogPublisherPolicy](options.publisherPolicy)
\tif err != nil {
\t\treturn preparedFFUCLIReview{}, fmt.Errorf("read FFU publisher policy: %w", err)
\t}
''', '''\tmetadataPolicy, metadataPolicyPath, metadataPolicyIdentity, err := readStrictFFUCLIJSONWithIdentity[ffu.TrustMetadataPolicy](options.trustMetadataPolicy)
\tif err != nil {
\t\treturn preparedFFUCLIReview{}, fmt.Errorf("read FFU trust metadata policy: %w", err)
\t}
\tpublisherPolicy, publisherPolicyPath, publisherPolicyIdentity, err := readStrictFFUCLIJSONWithIdentity[ffu.CatalogPublisherPolicy](options.publisherPolicy)
\tif err != nil {
\t\treturn preparedFFUCLIReview{}, fmt.Errorf("read FFU publisher policy: %w", err)
\t}
''', "policy identity reads")
text = replace_once(text, '''\tif err := sourcefile.Verify(file, identity); err != nil {
\t\treturn preparedFFUCLIReview{}, err
\t}
\treview := ffuCLIReview{
''', '''\tif err := sourcefile.Verify(file, identity); err != nil {
\t\treturn preparedFFUCLIReview{}, err
\t}
\t_, reviewBindingSHA256, err := buildFFUCLIReviewBinding(
\t\tresolved, identity, descriptor, targetPlan, preflight, activation,
\t\tmetadataPolicyPath, metadataPolicyIdentity, publisherPolicyPath, publisherPolicyIdentity, phrase,
\t)
\tif err != nil {
\t\treturn preparedFFUCLIReview{}, err
\t}
\treview := ffuCLIReview{
''', "build review binding")
text = replace_once(text, '''\t\tEvaluationTime:          evaluationTime.Format(time.RFC3339),
\t\tTrustActivationSHA256:   activation.ActivationSHA256,
\t\tSourcePath:              resolved,
''', '''\t\tEvaluationTime:          evaluationTime.Format(time.RFC3339),
\t\tTrustActivationSHA256:   activation.ActivationSHA256,
\t\tTrustStoreRoot:          activation.Root,
\t\tTrustGeneration:         activation.Generation,
\t\tTrustSequence:           activation.Sequence,
\t\tTrustBundleSHA256:       activation.BundleSHA256,
\t\tTrustMetadataPolicyPath: metadataPolicyPath,
\t\tTrustMetadataIdentity:   metadataPolicyIdentity,
\t\tPublisherPolicyPath:     publisherPolicyPath,
\t\tPublisherPolicyIdentity: publisherPolicyIdentity,
\t\tReviewBindingSHA256:     reviewBindingSHA256,
\t\tSourcePath:              resolved,
''', "review binding evidence")
text = replace_once(text, '''func readStrictFFUCLIJSON[T any](path string) (T, error) {
\tvar zero T
\tresolved, identity, err := sourcefile.Inspect(path)
''', '''func readStrictFFUCLIJSON[T any](path string) (T, error) {
\tvalue, _, _, err := readStrictFFUCLIJSONWithIdentity[T](path)
\treturn value, err
}

func readStrictFFUCLIJSONWithIdentity[T any](path string) (T, string, sourcefile.Identity, error) {
\tvar zero T
\tresolved, identity, err := sourcefile.Inspect(path)
''', "identity policy reader")
start = text.index("func readStrictFFUCLIJSONWithIdentity")
end = text.index("\nfunc emitFFUCLIReview", start)
region = text[start:end]
region = region.replace("return zero, err", 'return zero, "", sourcefile.Identity{}, err')
region = region.replace("return zero, fmt.Errorf", 'return zero, "", sourcefile.Identity{}, fmt.Errorf')
region = region.replace("return zero, errors.New", 'return zero, "", sourcefile.Identity{}, errors.New')
region = region.replace("return value, nil", "return value, resolved, identity, nil")
text = text[:start] + region + text[end:]
text = replace_once(text, '''\tfmt.Printf("Target identity: %s\\n", review.TargetPreflight.ExpectedTargetIdentity)
\tfmt.Printf("Mutation bytes: %d\\n", review.TargetPreflight.MutationBytes)
''', '''\tfmt.Printf("Target identity: %s\\n", review.TargetPreflight.ExpectedTargetIdentity)
\tfmt.Printf("Reviewed-input binding: %s\\n", review.ReviewBindingSHA256)
\tfmt.Printf("Trust generation: %s (sequence %d, bundle %s)\\n", review.TrustGeneration, review.TrustSequence, review.TrustBundleSHA256)
\tfmt.Printf("Mutation bytes: %d\\n", review.TargetPreflight.MutationBytes)
''', "plain binding output")
source.write_text(text)


tests = Path("cmd/rufus-linux/ffu_linux_test.go")
text = tests.read_text()
text = replace_once(text, '''\targs = append(args, "--confirm", "RESTORE AUTHENTICATED FFU TO /dev/test SIZE 32768 BYTES")
''', '''\targs = append(args,
\t\t"--confirm", "RESTORE AUTHENTICATED FFU TO /dev/test SIZE 32768 BYTES",
\t\t"--expected-review-binding", strings.Repeat("b", 64),
\t)
''', "restore option fixture")
text = replace_once(text, '''\tif options.confirmationPhrase == "" {
\t\tt.Fatal("restore confirmation phrase was not parsed")
\t}
''', '''\tif options.confirmationPhrase == "" || options.expectedReviewBinding == "" {
\t\tt.Fatal("restore confirmation phrase or review binding was not parsed")
\t}
''', "restore parsed assertion")
text = text.replace('args := append(validFFUCLIArgumentFixture(t), "--confirm", "exact phrase")', 'args := append(validFFUCLIArgumentFixture(t), "--confirm", "exact phrase", "--expected-review-binding", strings.Repeat("b", 64))')
text = replace_once(text, '''\tvalue, err := readStrictFFUCLIJSON[policy](validPath)
\tif err != nil || value.Version != 1 {
\t\tt.Fatalf("valid policy=%#v error=%v", value, err)
\t}
''', '''\tvalue, err := readStrictFFUCLIJSON[policy](validPath)
\tif err != nil || value.Version != 1 {
\t\tt.Fatalf("valid policy=%#v error=%v", value, err)
\t}
\tboundValue, resolved, identity, err := readStrictFFUCLIJSONWithIdentity[policy](validPath)
\tif err != nil || boundValue != value || resolved != validPath || identity.Size <= 0 {
\t\tt.Fatalf("identity-bound policy=%#v path=%q identity=%#v error=%v", boundValue, resolved, identity, err)
\t}
''', "identity reader assertion")
extra = r'''

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
	if err := validateFFUCLIReviewBinding(binding); err != nil { t.Fatal(err) }
	first, err := json.Marshal(binding); if err != nil { t.Fatal(err) }
	firstDigest := sha256.Sum256(first)
	second, err := json.Marshal(binding); if err != nil { t.Fatal(err) }
	secondDigest := sha256.Sum256(second)
	if firstDigest != secondDigest { t.Fatal("review binding digest is nondeterministic") }
	changed := binding
	changed.SourceIdentity.Inode++
	changedBytes, err := json.Marshal(changed); if err != nil { t.Fatal(err) }
	changedDigest := sha256.Sum256(changedBytes)
	if firstDigest == changedDigest { t.Fatal("source substitution did not change review binding") }
}

func TestRequireExpectedFFUCLIReviewBinding(t *testing.T) {
	valid := strings.Repeat("a", 64)
	if err := requireExpectedFFUCLIReviewBinding(valid, valid); err != nil { t.Fatal(err) }
	for _, candidate := range []string{"", strings.Repeat("A", 64), strings.Repeat("b", 64)} {
		if err := requireExpectedFFUCLIReviewBinding(candidate, valid); err == nil { t.Fatalf("invalid or substituted review binding %q was accepted", candidate) }
	}
}
'''
text = replace_once(text, "\nfunc TestRunRecognizesFFUCommand", extra + "\nfunc TestRunRecognizesFFUCommand", "binding tests")
text = replace_once(text, '''\t"context"
\t"errors"
''', '''\t"context"
\t"crypto/sha256"
\t"encoding/json"
\t"errors"
''', "binding test imports")
text = replace_once(text, '''\t"testing"
)
''', '''\t"testing"

\t"github.com/geocausa/RufusArm64/internal/sourcefile"
)
''', "sourcefile test import")
text = replace_once(text, '''\t\t"ctx.Err()",
''', '''\t\t"ctx.Err()",
\t\t"requireExpectedFFUCLIReviewBinding",
\t\t"ReviewBindingSHA256",
\t\t"readStrictFFUCLIJSONWithIdentity",
''', "binding source contract")
tests.write_text(text)


doc = Path("docs/ffu-experimental-cli-provider.md")
text = doc.read_text()
text = replace_once(text, '''## Single-process capability chain
''', '''## Stable reviewed-input binding

Every successful review now emits a lowercase SHA-256 binding over the stable
source snapshot, explicit trust-store generation, trust bundle, both policy-file
identities, exact target snapshot and exact phrase. Evaluation-time-dependent
plan identifiers are deliberately excluded so the binding can be reproduced by a
later privileged process without weakening expiry checks.

`ffu restore` requires the exact value through `--expected-review-binding`. The
privileged command rereads every input, reactivates trust, reauthenticates the
source and rediscovers the target before comparing the binding in constant time.
Any source replacement, policy replacement, trust-generation change, target
reconnection/substitution, capacity or sector change is refused before target
acquisition.

## Single-process capability chain
''', "review binding documentation")
doc.write_text(text)
