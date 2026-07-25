#!/usr/bin/env python3
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label} anchor count is {count}, expected 1")
    return text.replace(old, new, 1)


source = Path("cmd/rufus-linux/ffu_linux.go")
text = source.read_text()
text = replace_once(
    text,
    '''\tconfirmationPhrase     string\n\texperimental           bool\n''',
    '''\tconfirmationPhrase     string\n\texpectedReviewBinding  string\n\texperimental           bool\n''',
    "option review binding",
)
text = replace_once(
    text,
    '''\tTrustActivationSHA256   string                           `json:"trust_activation_sha256"`\n\tSourcePath              string                           `json:"source_path"`\n''',
    '''\tTrustActivationSHA256   string                           `json:"trust_activation_sha256"`\n\tTrustStoreRoot           string                           `json:"trust_store_root"`\n\tTrustGeneration          string                           `json:"trust_generation"`\n\tTrustSequence            uint64                           `json:"trust_sequence"`\n\tTrustBundleSHA256        string                           `json:"trust_bundle_sha256"`\n\tTrustMetadataPolicyPath  string                           `json:"trust_metadata_policy_path"`\n\tTrustMetadataIdentity    sourcefile.Identity              `json:"trust_metadata_policy_identity"`\n\tPublisherPolicyPath      string                           `json:"publisher_policy_path"`\n\tPublisherPolicyIdentity  sourcefile.Identity              `json:"publisher_policy_identity"`\n\tReviewBindingSHA256      string                           `json:"review_binding_sha256"`\n\tSourcePath              string                           `json:"source_path"`\n''',
    "review stable fields",
)
text = replace_once(
    text,
    '''\tprepared, err := prepareFFUCLIReview(ctx, options)\n\tif err != nil {\n\t\treturn err\n\t}\n\tprepared.review.ExecutionAttempted = true\n''',
    '''\tprepared, err := prepareFFUCLIReview(ctx, options)\n\tif err != nil {\n\t\treturn err\n\t}\n\tif err := requireExpectedFFUCLIReviewBinding(options.expectedReviewBinding, prepared.review.ReviewBindingSHA256); err != nil {\n\t\tcloseErr := prepared.file.Close()\n\t\treturn errors.Join(err, closeErr)\n\t}\n\tprepared.review.ExecutionAttempted = true\n''',
    "restore binding gate",
)
text = replace_once(
    text,
    '''\tif requireConfirmation {\n\t\tflags.StringVar(&options.confirmationPhrase, "confirm", "", "exact destructive target-and-capacity phrase")\n\t}\n''',
    '''\tif requireConfirmation {\n\t\tflags.StringVar(&options.confirmationPhrase, "confirm", "", "exact destructive target-and-capacity phrase")\n\t\tflags.StringVar(&options.expectedReviewBinding, "expected-review-binding", "", "exact reviewed source, trust-policy, and target binding SHA-256")\n\t}\n''',
    "restore binding flag",
)
text = replace_once(
    text,
    '''\tif requireConfirmation && options.confirmationPhrase == "" {\n\t\treturn ffuCLIOptions{}, errors.New("--confirm is required")\n\t}\n''',
    '''\tif requireConfirmation && options.confirmationPhrase == "" {\n\t\treturn ffuCLIOptions{}, errors.New("--confirm is required")\n\t}\n\tif requireConfirmation && options.expectedReviewBinding == "" {\n\t\treturn ffuCLIOptions{}, errors.New("--expected-review-binding is required")\n\t}\n\tif requireConfirmation && !isCanonicalFFUCLISHA256(options.expectedReviewBinding) {\n\t\treturn ffuCLIOptions{}, errors.New("--expected-review-binding must be one lowercase SHA-256")\n\t}\n''',
    "restore binding requirement",
)
text = replace_once(
    text,
    '''\tmetadataPolicy, err := readStrictFFUCLIJSON[ffu.TrustMetadataPolicy](options.trustMetadataPolicy)\n\tif err != nil {\n\t\treturn preparedFFUCLIReview{}, fmt.Errorf("read FFU trust metadata policy: %w", err)\n\t}\n\tpublisherPolicy, err := readStrictFFUCLIJSON[ffu.CatalogPublisherPolicy](options.publisherPolicy)\n\tif err != nil {\n\t\treturn preparedFFUCLIReview{}, fmt.Errorf("read FFU publisher policy: %w", err)\n\t}\n''',
    '''\tmetadataPolicy, metadataPolicyPath, metadataPolicyIdentity, err := readStrictFFUCLIJSONWithIdentity[ffu.TrustMetadataPolicy](options.trustMetadataPolicy)\n\tif err != nil {\n\t\treturn preparedFFUCLIReview{}, fmt.Errorf("read FFU trust metadata policy: %w", err)\n\t}\n\tpublisherPolicy, publisherPolicyPath, publisherPolicyIdentity, err := readStrictFFUCLIJSONWithIdentity[ffu.CatalogPublisherPolicy](options.publisherPolicy)\n\tif err != nil {\n\t\treturn preparedFFUCLIReview{}, fmt.Errorf("read FFU publisher policy: %w", err)\n\t}\n''',
    "policy identity reads",
)
text = replace_once(
    text,
    '''\tif err := sourcefile.Verify(file, identity); err != nil {\n\t\treturn preparedFFUCLIReview{}, err\n\t}\n\treview := ffuCLIReview{\n''',
    '''\tif err := sourcefile.Verify(file, identity); err != nil {\n\t\treturn preparedFFUCLIReview{}, err\n\t}\n\t_, reviewBindingSHA256, err := buildFFUCLIReviewBinding(\n\t\tresolved, identity, descriptor, targetPlan, preflight, activation,\n\t\tmetadataPolicyPath, metadataPolicyIdentity, publisherPolicyPath, publisherPolicyIdentity, phrase,\n\t)\n\tif err != nil {\n\t\treturn preparedFFUCLIReview{}, err\n\t}\n\treview := ffuCLIReview{\n''',
    "build review binding",
)
text = replace_once(
    text,
    '''\t\tEvaluationTime:          evaluationTime.Format(time.RFC3339),\n\t\tTrustActivationSHA256:   activation.ActivationSHA256,\n\t\tSourcePath:              resolved,\n''',
    '''\t\tEvaluationTime:          evaluationTime.Format(time.RFC3339),\n\t\tTrustActivationSHA256:   activation.ActivationSHA256,\n\t\tTrustStoreRoot:          activation.Root,\n\t\tTrustGeneration:         activation.Generation,\n\t\tTrustSequence:           activation.Sequence,\n\t\tTrustBundleSHA256:       activation.BundleSHA256,\n\t\tTrustMetadataPolicyPath: metadataPolicyPath,\n\t\tTrustMetadataIdentity:   metadataPolicyIdentity,\n\t\tPublisherPolicyPath:     publisherPolicyPath,\n\t\tPublisherPolicyIdentity: publisherPolicyIdentity,\n\t\tReviewBindingSHA256:     reviewBindingSHA256,\n\t\tSourcePath:              resolved,\n''',
    "review binding evidence",
)
text = replace_once(
    text,
    '''func readStrictFFUCLIJSON[T any](path string) (T, error) {\n\tvar zero T\n\tresolved, identity, err := sourcefile.Inspect(path)\n''',
    '''func readStrictFFUCLIJSON[T any](path string) (T, error) {\n\tvalue, _, _, err := readStrictFFUCLIJSONWithIdentity[T](path)\n\treturn value, err\n}\n\nfunc readStrictFFUCLIJSONWithIdentity[T any](path string) (T, string, sourcefile.Identity, error) {\n\tvar zero T\n\tresolved, identity, err := sourcefile.Inspect(path)\n''',
    "identity policy reader",
)
text = replace_once(
    text,
    '''\tif err != nil {\n\t\treturn zero, err\n\t}\n\tfile, err := sourcefile.OpenRegular(resolved, identity)\n''',
    '''\tif err != nil {\n\t\treturn zero, "", sourcefile.Identity{}, err\n\t}\n\tfile, err := sourcefile.OpenRegular(resolved, identity)\n''',
    "policy inspect return",
)
# Update every return in the new identity reader region without touching later emitters.
start = text.index("func readStrictFFUCLIJSONWithIdentity")
end = text.index("\nfunc emitFFUCLIReview", start)
region = text[start:end]
region = region.replace("return zero, err", 'return zero, "", sourcefile.Identity{}, err')
region = region.replace("return zero, fmt.Errorf", 'return zero, "", sourcefile.Identity{}, fmt.Errorf')
region = region.replace("return zero, errors.New", 'return zero, "", sourcefile.Identity{}, errors.New')
region = region.replace("return value, nil", "return value, resolved, identity, nil")
text = text[:start] + region + text[end:]
text = replace_once(
    text,
    '''\tfmt.Printf("Target identity: %s\\n", review.TargetPreflight.ExpectedTargetIdentity)\n\tfmt.Printf("Mutation bytes: %d\\n", review.TargetPreflight.MutationBytes)\n''',
    '''\tfmt.Printf("Target identity: %s\\n", review.TargetPreflight.ExpectedTargetIdentity)\n\tfmt.Printf("Reviewed-input binding: %s\\n", review.ReviewBindingSHA256)\n\tfmt.Printf("Trust generation: %s (sequence %d, bundle %s)\\n", review.TrustGeneration, review.TrustSequence, review.TrustBundleSHA256)\n\tfmt.Printf("Mutation bytes: %d\\n", review.TargetPreflight.MutationBytes)\n''',
    "plain binding output",
)
source.write_text(text)


tests = Path("cmd/rufus-linux/ffu_linux_test.go")
text = tests.read_text()
text = replace_once(
    text,
    '''\targs = append(args, "--confirm", "RESTORE AUTHENTICATED FFU TO /dev/test SIZE 32768 BYTES")\n''',
    '''\targs = append(args,\n\t\t"--confirm", "RESTORE AUTHENTICATED FFU TO /dev/test SIZE 32768 BYTES",\n\t\t"--expected-review-binding", strings.Repeat("b", 64),\n\t)\n''',
    "restore option fixture",
)
text = replace_once(
    text,
    '''\tif options.confirmationPhrase == "" {\n\t\tt.Fatal("restore confirmation phrase was not parsed")\n\t}\n''',
    '''\tif options.confirmationPhrase == "" || options.expectedReviewBinding == "" {\n\t\tt.Fatal("restore confirmation phrase or review binding was not parsed")\n\t}\n''',
    "restore parsed assertion",
)
text = text.replace(
    'args := append(validFFUCLIArgumentFixture(t), "--confirm", "exact phrase")',
    'args := append(validFFUCLIArgumentFixture(t), "--confirm", "exact phrase", "--expected-review-binding", strings.Repeat("b", 64))',
)
text = replace_once(
    text,
    '''\tvalue, err := readStrictFFUCLIJSON[policy](validPath)\n\tif err != nil || value.Version != 1 {\n\t\tt.Fatalf("valid policy=%#v error=%v", value, err)\n\t}\n''',
    '''\tvalue, err := readStrictFFUCLIJSON[policy](validPath)\n\tif err != nil || value.Version != 1 {\n\t\tt.Fatalf("valid policy=%#v error=%v", value, err)\n\t}\n\tboundValue, resolved, identity, err := readStrictFFUCLIJSONWithIdentity[policy](validPath)\n\tif err != nil || boundValue != value || resolved != validPath || identity.Size <= 0 {\n\t\tt.Fatalf("identity-bound policy=%#v path=%q identity=%#v error=%v", boundValue, resolved, identity, err)\n\t}\n''',
    "identity reader assertion",
)
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
'''
text = replace_once(text, "\nfunc TestRunRecognizesFFUCommand", extra + "\nfunc TestRunRecognizesFFUCommand", "binding tests")
text = replace_once(
    text,
    '''\t"context"\n\t"errors"\n''',
    '''\t"context"\n\t"crypto/sha256"\n\t"encoding/json"\n\t"errors"\n''',
    "binding test imports",
)
text = replace_once(
    text,
    '''\t"testing"\n)\n''',
    '''\t"testing"\n\n\t"github.com/geocausa/RufusArm64/internal/sourcefile"\n)\n''',
    "sourcefile test import",
)
text = replace_once(
    text,
    '''\t\t"ctx.Err()",\n''',
    '''\t\t"ctx.Err()",\n\t\t"requireExpectedFFUCLIReviewBinding",\n\t\t"ReviewBindingSHA256",\n\t\t"readStrictFFUCLIJSONWithIdentity",\n''',
    "binding source contract",
)
tests.write_text(text)


doc = Path("docs/ffu-experimental-cli-provider.md")
text = doc.read_text()
text = replace_once(
    text,
    '''## Destructive restore\n''',
    '''## Stable reviewed-input binding\n\nEvery successful review now emits a lowercase SHA-256 binding over the stable\nsource snapshot, explicit trust-store generation, trust bundle, both policy-file\nidentities, exact target snapshot and exact phrase. Evaluation-time-dependent\nplan identifiers are deliberately excluded so the binding can be reproduced by a\nlater privileged process without weakening expiry checks.\n\n`ffu restore` requires the exact value through `--expected-review-binding`. The\nprivileged command rereads every input, reactivates trust, reauthenticates the\nsource and rediscovers the target before comparing the binding in constant time.\nAny source replacement, policy replacement, trust-generation change, target\nreconnection/substitution, capacity or sector change is refused before target\nacquisition.\n\n## Destructive restore\n''',
    "review binding documentation",
)
doc.write_text(text)
