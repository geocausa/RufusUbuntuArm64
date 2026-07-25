//go:build linux

package ffu

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

func TestExecuteAuthorizedSinglePhaseFullFlash(t *testing.T) {
	fixture := newSinglePhaseMutationAuthorizationFixture(t)
	defer closeSinglePhaseExecutionFixture(t, &fixture)
	authorization := authorizeSinglePhaseExecutionFixture(t, &fixture)
	expected := expectedSinglePhaseExecutionTarget(t, &fixture, authorization.writeOrder)

	result, err := ExecuteAuthorizedSinglePhaseFullFlash(context.Background(), authorization)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != fullFlashExecutionStatusVerified || !result.AuthorizationConsumed || !result.SourceLeaseRevalidated || !result.TargetSessionRevalidated || !result.MutationStarted || !result.WriteCompleted || !result.SyncCompleted || !result.ReadbackCompleted || result.CancellationObserved || result.TargetMayBePartiallyModified || !result.ExecutionSucceeded || result.ErrorObserved {
		t.Fatalf("successful execution crossed or missed a boundary: %#v", result)
	}
	if result.OperationCountCompleted != result.OperationCountPlanned || result.MutationBytesWritten != result.MutationBytesPlanned || result.ResultSHA256 != fullFlashExecutionResultDigest(result) {
		t.Fatalf("successful execution accounting is inconsistent: %#v", result)
	}
	actual, err := os.ReadFile(fixture.targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatal("verified execution did not produce the exact declaration-order target bytes")
	}
	if err := authorization.Check(); err == nil || !strings.Contains(err.Error(), "consumed") {
		t.Fatalf("consumed authorization remained reusable: %v", err)
	}
	second, secondErr := ExecuteAuthorizedSinglePhaseFullFlash(context.Background(), authorization)
	if secondErr == nil || !strings.Contains(secondErr.Error(), "consumed") || second.MutationStarted || !second.AuthorizationConsumed || second.ExecutionSucceeded {
		t.Fatalf("second execution result=%#v error=%v", second, secondErr)
	}
}

func TestExecuteAuthorizedSinglePhaseFullFlashCancellationBeforeMutation(t *testing.T) {
	fixture := newSinglePhaseMutationAuthorizationFixture(t)
	defer fixture.close(t)
	authorization := authorizeSinglePhaseExecutionFixture(t, &fixture)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := ExecuteAuthorizedSinglePhaseFullFlash(ctx, authorization)
	if !errors.Is(err, context.Canceled) || result.MutationStarted || result.AuthorizationConsumed || !result.CancellationObserved || !result.CancelledBeforeMutation || result.CancelledAfterMutation || result.TargetMayBePartiallyModified {
		t.Fatalf("pre-mutation cancellation result=%#v error=%v", result, err)
	}
	if err := authorization.Check(); err != nil {
		t.Fatalf("pre-mutation cancellation consumed authorization: %v", err)
	}
}

func TestExecuteAuthorizedSinglePhaseFullFlashCancellationAfterMutation(t *testing.T) {
	fixture := newSinglePhaseMutationAuthorizationFixture(t)
	defer closeSinglePhaseExecutionFixture(t, &fixture)
	authorization := authorizeSinglePhaseExecutionFixture(t, &fixture)
	ctx, cancel := context.WithCancel(context.Background())
	ops := defaultFullFlashExecutionOps()
	ops.chunkSize = 4096
	ops.afterWriteChunk = func(uint64) { cancel() }
	result, err := executeAuthorizedSinglePhaseFullFlashWithOps(ctx, authorization, ops)
	if !errors.Is(err, context.Canceled) || !result.AuthorizationConsumed || !result.MutationStarted || !result.CancellationObserved || result.CancelledBeforeMutation || !result.CancelledAfterMutation || !result.TargetMayBePartiallyModified || result.ExecutionSucceeded {
		t.Fatalf("post-mutation cancellation result=%#v error=%v", result, err)
	}
	if result.MutationBytesWritten == 0 || result.MutationBytesWritten >= result.MutationBytesPlanned {
		t.Fatalf("post-mutation cancellation byte accounting is not partial: %#v", result)
	}
}

func TestExecuteAuthorizedSinglePhaseFullFlashWriteFailure(t *testing.T) {
	fixture := newSinglePhaseMutationAuthorizationFixture(t)
	defer closeSinglePhaseExecutionFixture(t, &fixture)
	authorization := authorizeSinglePhaseExecutionFixture(t, &fixture)
	ops := defaultFullFlashExecutionOps()
	ops.chunkSize = 4096
	failed := false
	ops.writeTarget = func(file *os.File, buffer []byte, offset int64) (int, error) {
		if failed {
			return 0, errors.New("injected target write failure")
		}
		failed = true
		n := len(buffer) / 2
		written, err := file.WriteAt(buffer[:n], offset)
		if err != nil {
			return written, err
		}
		return written, errors.New("injected target write failure")
	}
	result, err := executeAuthorizedSinglePhaseFullFlashWithOps(context.Background(), authorization, ops)
	if err == nil || !strings.Contains(err.Error(), "injected target write failure") || result.ErrorStage != "target-write" || !result.MutationStarted || !result.TargetMayBePartiallyModified || result.MutationBytesWritten == 0 || result.ExecutionSucceeded {
		t.Fatalf("write failure result=%#v error=%v", result, err)
	}
}

func TestExecuteAuthorizedSinglePhaseFullFlashSyncFailure(t *testing.T) {
	fixture := newSinglePhaseMutationAuthorizationFixture(t)
	defer closeSinglePhaseExecutionFixture(t, &fixture)
	authorization := authorizeSinglePhaseExecutionFixture(t, &fixture)
	ops := defaultFullFlashExecutionOps()
	ops.syncTarget = func(*os.File) error { return errors.New("injected sync failure") }
	result, err := executeAuthorizedSinglePhaseFullFlashWithOps(context.Background(), authorization, ops)
	if err == nil || !strings.Contains(err.Error(), "injected sync failure") || result.ErrorStage != "target-sync" || !result.WriteCompleted || result.SyncCompleted || !result.TargetMayBePartiallyModified || result.ExecutionSucceeded {
		t.Fatalf("sync failure result=%#v error=%v", result, err)
	}
}

func TestExecuteAuthorizedSinglePhaseFullFlashReadbackMismatch(t *testing.T) {
	fixture := newSinglePhaseMutationAuthorizationFixture(t)
	defer closeSinglePhaseExecutionFixture(t, &fixture)
	authorization := authorizeSinglePhaseExecutionFixture(t, &fixture)
	ops := defaultFullFlashExecutionOps()
	corrupted := false
	ops.readTarget = func(file *os.File, buffer []byte, offset int64) (int, error) {
		n, err := file.ReadAt(buffer, offset)
		if n > 0 && !corrupted {
			buffer[0] ^= 0xff
			corrupted = true
		}
		return n, err
	}
	result, err := executeAuthorizedSinglePhaseFullFlashWithOps(context.Background(), authorization, ops)
	if err == nil || !strings.Contains(err.Error(), "readback does not match") || result.ErrorStage != "readback-mismatch" || !result.WriteCompleted || !result.SyncCompleted || result.ReadbackCompleted || result.Status != fullFlashExecutionStatusWrittenUnverified || !result.TargetMayBePartiallyModified || result.ExecutionSucceeded {
		t.Fatalf("readback mismatch result=%#v error=%v", result, err)
	}
}

func TestExecuteAuthorizedSinglePhaseFullFlashRejectsNilAndInvalidOperations(t *testing.T) {
	var nilContext context.Context
	result, err := ExecuteAuthorizedSinglePhaseFullFlash(nilContext, nil)
	if err == nil || !strings.Contains(err.Error(), "context is nil") || result.MutationStarted {
		t.Fatalf("nil context result=%#v error=%v", result, err)
	}
	fixture := newSinglePhaseMutationAuthorizationFixture(t)
	defer fixture.close(t)
	authorization := authorizeSinglePhaseExecutionFixture(t, &fixture)
	result, err = executeAuthorizedSinglePhaseFullFlashWithOps(context.Background(), authorization, fullFlashExecutionOps{})
	if err == nil || !strings.Contains(err.Error(), "operations are incomplete") || result.MutationStarted {
		t.Fatalf("invalid operations result=%#v error=%v", result, err)
	}
}

func TestValidateFullFlashExecutionResultRejectsTampering(t *testing.T) {
	fixture := newSinglePhaseMutationAuthorizationFixture(t)
	defer closeSinglePhaseExecutionFixture(t, &fixture)
	authorization := authorizeSinglePhaseExecutionFixture(t, &fixture)
	result, err := ExecuteAuthorizedSinglePhaseFullFlash(context.Background(), authorization)
	if err != nil {
		t.Fatal(err)
	}
	result.TargetMayBePartiallyModified = true
	if err := validateFullFlashExecutionResult(result); err == nil {
		t.Fatal("tampered successful execution result was accepted")
	}
}

func authorizeSinglePhaseExecutionFixture(t testing.TB, fixture *singlePhaseMutationAuthorizationFixture) *FullFlashMutationAuthorization {
	t.Helper()
	authorization, err := AuthorizeSinglePhaseFullFlashMutation(context.Background(), fixture.confirmation, fixture.descriptor, fixture.targetPlan, fixture.fullPlan)
	if err != nil {
		t.Fatal(err)
	}
	return authorization
}

func expectedSinglePhaseExecutionTarget(t testing.TB, fixture *singlePhaseMutationAuthorizationFixture, order FullFlashWriteOrderPlan) []byte {
	t.Helper()
	expected := append([]byte(nil), fixture.original...)
	for _, operation := range order.Operations {
		payload := make([]byte, operation.PayloadLength)
		if _, err := fixture.sourceFile.ReadAt(payload, int64(operation.PayloadOffset)); err != nil && !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
		copy(expected[operation.TargetOffset:operation.TargetOffset+operation.TargetLength], payload)
	}
	return expected
}

func closeSinglePhaseExecutionFixture(t testing.TB, fixture *singlePhaseMutationAuthorizationFixture) {
	t.Helper()
	if fixture.target != nil {
		if err := fixture.target.Close(); err != nil {
			t.Error(err)
		}
		fixture.target = nil
	}
	if fixture.source != nil {
		if err := fixture.source.Close(); err != nil {
			t.Error(err)
		}
		fixture.source = nil
	}
	if fixture.sourceFile != nil {
		if err := fixture.sourceFile.Close(); err != nil {
			t.Error(err)
		}
		fixture.sourceFile = nil
	}
}
