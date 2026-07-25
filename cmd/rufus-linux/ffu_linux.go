//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/geocausa/RufusArm64/internal/ffu"
	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

const maxFFUCLIPolicyBytes = 1 << 20

var (
	ffuCLIGeteuid = os.Geteuid
	ffuCLINow     = time.Now
	ffuCLIContext = func() (context.Context, context.CancelFunc) {
		return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	}
)

func newFFUCLIContext() (context.Context, context.CancelFunc, error) {
	ctx, stop := ffuCLIContext()
	if ctx == nil || stop == nil {
		if stop != nil {
			stop()
		}
		return nil, nil, errors.New("FFU signal context factory returned an invalid context")
	}
	return ctx, stop, nil
}

type ffuCLIOptions struct {
	imagePath              string
	devicePath             string
	expectedTargetIdentity string
	targetSizeBytes        uint64
	logicalSectorBytes     uint64
	physicalSectorBytes    uint64
	trustStoreRoot         string
	trustMetadataPolicy    string
	publisherPolicy        string
	confirmationPhrase     string
	experimental           bool
	jsonOutput             bool
}

type ffuCLIReview struct {
	EvaluationTime          string                           `json:"evaluation_time"`
	TrustActivationSHA256   string                           `json:"trust_activation_sha256"`
	SourcePath              string                           `json:"source_path"`
	SourceIdentity          sourcefile.Identity              `json:"source_identity"`
	DescriptorPlanSHA256    string                           `json:"descriptor_plan_sha256"`
	TargetPlan              ffu.RestoreTargetPlan            `json:"target_plan"`
	FullFlashPlan           ffu.FullFlashValidationPlan      `json:"full_flash_plan"`
	TargetPreflight         ffu.FullFlashTargetPreflightPlan `json:"target_preflight"`
	ExactConfirmationPhrase string                           `json:"exact_confirmation_phrase"`
	ExecutionAttempted      bool                             `json:"execution_attempted"`
}

type ffuCLIRestoreOutput struct {
	Review                ffuCLIReview                               `json:"review"`
	SourceLease           ffu.FullFlashSourceLeaseEvidence           `json:"source_lease"`
	TargetSession         ffu.FullFlashTargetSessionEvidence         `json:"target_session"`
	Confirmation          ffu.FullFlashConfirmationEvidence          `json:"confirmation"`
	MutationAuthorization ffu.FullFlashMutationAuthorizationEvidence `json:"mutation_authorization"`
	Execution             ffu.FullFlashExecutionResult               `json:"execution"`
}

type preparedFFUCLIReview struct {
	review          ffuCLIReview
	file            *os.File
	identity        sourcefile.Identity
	activation      ffu.TrustBundleActivation
	publisherPolicy ffu.CatalogPublisherPolicy
	evaluationTime  time.Time
	descriptor      ffu.DescriptorPlan
	targetPlan      ffu.RestoreTargetPlan
	fullPlan        ffu.FullFlashValidationPlan
	preflight       ffu.FullFlashTargetPreflightPlan
	request         ffu.RestoreTargetRequest
}

func runFFU(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: rufusarm64-cli ffu <review|restore> [options]")
	}
	switch args[0] {
	case "review":
		return runFFUReview(args[1:])
	case "restore":
		return runFFURestore(args[1:])
	default:
		return fmt.Errorf("unknown FFU command %q", args[0])
	}
}

func runFFUReview(args []string) error {
	options, err := parseFFUCLIOptions("review", args, false)
	if err != nil {
		return err
	}
	ctx, stop, err := newFFUCLIContext()
	if err != nil {
		return err
	}
	defer stop()
	prepared, err := prepareFFUCLIReview(ctx, options)
	if err != nil {
		return err
	}
	closeErr := prepared.file.Close()
	prepared.file = nil
	if emitErr := emitFFUCLIReview(options.jsonOutput, prepared.review); emitErr != nil {
		return errors.Join(closeErr, emitErr)
	}
	return closeErr
}

func runFFURestore(args []string) error {
	options, err := parseFFUCLIOptions("restore", args, true)
	if err != nil {
		return err
	}
	if ffuCLIGeteuid() != 0 {
		return errors.New("FFU restore requires administrator privileges")
	}
	ctx, stop, err := newFFUCLIContext()
	if err != nil {
		return err
	}
	defer stop()
	prepared, err := prepareFFUCLIReview(ctx, options)
	if err != nil {
		return err
	}
	prepared.review.ExecutionAttempted = true
	if prepared.preflight.UnmountRequired || len(prepared.preflight.MountedTargets) != 0 {
		closeErr := prepared.file.Close()
		return errors.Join(errors.New("FFU target must be fully unmounted before restore"), closeErr)
	}
	sourceLease, err := ffu.AcquireAuthenticatedFullFlashSourceLease(
		ctx,
		prepared.file,
		prepared.identity,
		prepared.activation,
		prepared.evaluationTime,
		prepared.publisherPolicy,
		prepared.request,
		prepared.preflight,
	)
	if err != nil {
		closeErr := prepared.file.Close()
		return errors.Join(err, closeErr)
	}
	targetSession, err := ffu.AcquireExclusiveFullFlashTarget(ctx, sourceLease, prepared.preflight)
	if err != nil {
		return errors.Join(err, sourceLease.Close(), prepared.file.Close())
	}
	confirmation, err := ffu.ConfirmExclusiveFullFlashTarget(ctx, targetSession, options.confirmationPhrase)
	if err != nil {
		return errors.Join(err, targetSession.Close(), sourceLease.Close(), prepared.file.Close())
	}
	authorization, err := ffu.AuthorizeSinglePhaseFullFlashMutation(
		ctx, confirmation, prepared.descriptor, prepared.targetPlan, prepared.fullPlan,
	)
	if err != nil {
		return errors.Join(err, targetSession.Close(), sourceLease.Close(), prepared.file.Close())
	}

	sourceEvidence, sourceEvidenceErr := sourceLease.Evidence()
	targetEvidence, targetEvidenceErr := targetSession.Evidence()
	confirmationEvidence, confirmationEvidenceErr := confirmation.Evidence()
	authorizationEvidence, authorizationEvidenceErr := authorization.Evidence()
	if evidenceErr := errors.Join(sourceEvidenceErr, targetEvidenceErr, confirmationEvidenceErr, authorizationEvidenceErr); evidenceErr != nil {
		return errors.Join(evidenceErr, targetSession.Close(), sourceLease.Close(), prepared.file.Close())
	}

	execution, executionErr := ffu.ExecuteAuthorizedSinglePhaseFullFlash(ctx, authorization)
	output := ffuCLIRestoreOutput{
		Review:                prepared.review,
		SourceLease:           sourceEvidence,
		TargetSession:         targetEvidence,
		Confirmation:          confirmationEvidence,
		MutationAuthorization: authorizationEvidence,
		Execution:             execution,
	}
	emitErr := emitFFUCLIRestore(options.jsonOutput, output)
	cleanupErr := errors.Join(targetSession.Close(), sourceLease.Close(), prepared.file.Close())
	return errors.Join(executionErr, emitErr, cleanupErr)
}

func parseFFUCLIOptions(command string, args []string, requireConfirmation bool) (ffuCLIOptions, error) {
	var options ffuCLIOptions
	flags := flag.NewFlagSet("ffu "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&options.imagePath, "image", "", "authenticated single-store-v1 FFU source")
	flags.StringVar(&options.devicePath, "device", "", "exact removable whole-disk target")
	flags.StringVar(&options.expectedTargetIdentity, "expected-identity", "", "exact reviewed target identity token")
	flags.Uint64Var(&options.targetSizeBytes, "target-size", 0, "exact reviewed target capacity in bytes")
	flags.Uint64Var(&options.logicalSectorBytes, "logical-sector-size", 0, "exact reviewed logical sector size")
	flags.Uint64Var(&options.physicalSectorBytes, "physical-sector-size", 0, "exact reviewed physical sector size")
	flags.StringVar(&options.trustStoreRoot, "trust-store", "", "durably authenticated FFU trust-store root")
	flags.StringVar(&options.trustMetadataPolicy, "trust-metadata-policy", "", "caller-provisioned trust metadata public-key policy JSON")
	flags.StringVar(&options.publisherPolicy, "publisher-policy", "", "explicit catalog publisher policy JSON")
	if requireConfirmation {
		flags.StringVar(&options.confirmationPhrase, "confirm", "", "exact destructive target-and-capacity phrase")
	}
	flags.BoolVar(&options.experimental, "experimental-ffu", false, "acknowledge the Stage 3 experimental FFU boundary")
	flags.BoolVar(&options.jsonOutput, "json", false, "emit JSON evidence")
	if err := flags.Parse(args); err != nil {
		return ffuCLIOptions{}, err
	}
	if flags.NArg() != 0 {
		return ffuCLIOptions{}, errors.New("unexpected FFU command arguments")
	}
	if !options.experimental {
		return ffuCLIOptions{}, errors.New("--experimental-ffu is required")
	}
	for name, value := range map[string]string{
		"--image":                 options.imagePath,
		"--device":                options.devicePath,
		"--expected-identity":     options.expectedTargetIdentity,
		"--trust-store":           options.trustStoreRoot,
		"--trust-metadata-policy": options.trustMetadataPolicy,
		"--publisher-policy":      options.publisherPolicy,
	} {
		if strings.TrimSpace(value) == "" {
			return ffuCLIOptions{}, fmt.Errorf("%s is required", name)
		}
	}
	if options.targetSizeBytes == 0 || options.logicalSectorBytes == 0 || options.physicalSectorBytes == 0 {
		return ffuCLIOptions{}, errors.New("--target-size, --logical-sector-size, and --physical-sector-size must be non-zero")
	}
	if requireConfirmation && options.confirmationPhrase == "" {
		return ffuCLIOptions{}, errors.New("--confirm is required")
	}
	return options, nil
}

func prepareFFUCLIReview(ctx context.Context, options ffuCLIOptions) (preparedFFUCLIReview, error) {
	if ctx == nil {
		return preparedFFUCLIReview{}, errors.New("FFU CLI context is nil")
	}
	if err := ctx.Err(); err != nil {
		return preparedFFUCLIReview{}, err
	}
	metadataPolicy, err := readStrictFFUCLIJSON[ffu.TrustMetadataPolicy](options.trustMetadataPolicy)
	if err != nil {
		return preparedFFUCLIReview{}, fmt.Errorf("read FFU trust metadata policy: %w", err)
	}
	publisherPolicy, err := readStrictFFUCLIJSON[ffu.CatalogPublisherPolicy](options.publisherPolicy)
	if err != nil {
		return preparedFFUCLIReview{}, fmt.Errorf("read FFU publisher policy: %w", err)
	}
	evaluationTime := ffuCLINow().UTC()
	activation, err := ffu.ActivateAuthenticatedTrustBundle(ctx, options.trustStoreRoot, metadataPolicy, evaluationTime, ffu.TrustActivationOptions{})
	if err != nil {
		return preparedFFUCLIReview{}, fmt.Errorf("activate authenticated FFU trust bundle: %w", err)
	}
	resolved, identity, err := sourcefile.Inspect(options.imagePath)
	if err != nil {
		return preparedFFUCLIReview{}, err
	}
	file, err := sourcefile.OpenRegular(resolved, identity)
	if err != nil {
		return preparedFFUCLIReview{}, err
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = file.Close()
		}
	}()
	_, descriptor, err := ffu.PlanSingleStoreV1(file, uint64(identity.Size))
	if err != nil {
		return preparedFFUCLIReview{}, err
	}
	request := ffu.RestoreTargetRequest{
		DevicePath:              options.devicePath,
		ExpectedTargetIdentity:  options.expectedTargetIdentity,
		TargetSizeBytes:         options.targetSizeBytes,
		LogicalSectorSizeBytes:  options.logicalSectorBytes,
		PhysicalSectorSizeBytes: options.physicalSectorBytes,
	}
	targetPlan, fullPlan, err := ffu.ResolveAuthenticatedSingleStoreV1FullFlash(
		ctx, file, uint64(identity.Size), activation, evaluationTime, publisherPolicy, request,
	)
	if err != nil {
		return preparedFFUCLIReview{}, err
	}
	preflight, err := ffu.DiscoverFullFlashTargetPreflight(ctx, fullPlan)
	if err != nil {
		return preparedFFUCLIReview{}, err
	}
	phrase, err := ffu.RestoreTargetConfirmationPhrase(targetPlan)
	if err != nil {
		return preparedFFUCLIReview{}, err
	}
	if phrase != fullPlan.ConfirmationPhrase {
		return preparedFFUCLIReview{}, errors.New("FFU target and full-flash plans disagree on the exact confirmation phrase")
	}
	if err := sourcefile.Verify(file, identity); err != nil {
		return preparedFFUCLIReview{}, err
	}
	review := ffuCLIReview{
		EvaluationTime:          evaluationTime.Format(time.RFC3339),
		TrustActivationSHA256:   activation.ActivationSHA256,
		SourcePath:              resolved,
		SourceIdentity:          identity,
		DescriptorPlanSHA256:    descriptor.PlanSHA256,
		TargetPlan:              targetPlan,
		FullFlashPlan:           fullPlan,
		TargetPreflight:         preflight,
		ExactConfirmationPhrase: phrase,
		ExecutionAttempted:      false,
	}
	closeOnError = false
	return preparedFFUCLIReview{
		review: review, file: file, identity: identity, activation: activation,
		publisherPolicy: publisherPolicy, evaluationTime: evaluationTime,
		descriptor: descriptor, targetPlan: targetPlan, fullPlan: fullPlan,
		preflight: preflight, request: request,
	}, nil
}

func readStrictFFUCLIJSON[T any](path string) (T, error) {
	var zero T
	resolved, identity, err := sourcefile.Inspect(path)
	if err != nil {
		return zero, err
	}
	file, err := sourcefile.OpenRegular(resolved, identity)
	if err != nil {
		return zero, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxFFUCLIPolicyBytes+1))
	if err != nil {
		return zero, err
	}
	if len(data) == 0 || len(data) > maxFFUCLIPolicyBytes {
		return zero, fmt.Errorf("policy file size is outside the 1..%d byte range", maxFFUCLIPolicyBytes)
	}
	if err := sourcefile.Verify(file, identity); err != nil {
		return zero, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var value T
	if err := decoder.Decode(&value); err != nil {
		return zero, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return zero, errors.New("policy file contains multiple JSON values")
		}
		return zero, err
	}
	return value, nil
}

func emitFFUCLIReview(jsonOutput bool, review ffuCLIReview) error {
	if jsonOutput {
		return json.NewEncoder(os.Stdout).Encode(review)
	}
	fmt.Printf("FFU source: %s\n", review.SourcePath)
	fmt.Printf("Target: %s (%d bytes)\n", review.TargetPreflight.DevicePath, review.TargetPreflight.TargetSizeBytes)
	fmt.Printf("Target identity: %s\n", review.TargetPreflight.ExpectedTargetIdentity)
	fmt.Printf("Mutation bytes: %d\n", review.TargetPreflight.MutationBytes)
	fmt.Printf("Unmount required: %t\n", review.TargetPreflight.UnmountRequired)
	fmt.Printf("Exact confirmation: %s\n", review.ExactConfirmationPhrase)
	return nil
}

func emitFFUCLIRestore(jsonOutput bool, output ffuCLIRestoreOutput) error {
	if jsonOutput {
		return json.NewEncoder(os.Stdout).Encode(output)
	}
	fmt.Printf("FFU result: %s\n", output.Execution.Status)
	fmt.Printf("Operations: %d/%d\n", output.Execution.OperationCountCompleted, output.Execution.OperationCountPlanned)
	fmt.Printf("Bytes written: %d/%d\n", output.Execution.MutationBytesWritten, output.Execution.MutationBytesPlanned)
	fmt.Printf("Target may be partially modified: %t\n", output.Execution.TargetMayBePartiallyModified)
	fmt.Printf("Result SHA-256: %s\n", output.Execution.ResultSHA256)
	return nil
}
