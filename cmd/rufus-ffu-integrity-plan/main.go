//go:build linux

// rufus-ffu-integrity-plan is a read-only development tool that binds the
// single-store-v1 descriptor plan to FFU source chunks matching the embedded
// hash table. It has no target argument and cannot write media.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/geocausa/RufusArm64/internal/ffu"
	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

type sourceConsistency struct {
	Mode                 string `json:"mode"`
	ReadLeaseHeld        bool   `json:"read_lease_held"`
	ConservativeSHA256   string `json:"conservative_sha256,omitempty"`
	SourceStable         bool   `json:"source_stable"`
	ReadLeaseUnavailable bool   `json:"read_lease_unavailable"`
	ReadLeaseConflict    bool   `json:"read_lease_conflict"`
}

type report struct {
	Path                    string                      `json:"path"`
	SourceIdentity          sourcefile.Identity         `json:"source_identity"`
	SourceConsistency       sourceConsistency           `json:"source_consistency"`
	Inspection              ffu.Inspection              `json:"inspection"`
	DescriptorPlan          ffu.DescriptorPlan          `json:"descriptor_plan"`
	HashTablePlan           ffu.HashTablePlan           `json:"hash_table_plan"`
	ContentVerification     ffu.ContentVerification     `json:"content_verification"`
	IntegrityDescriptorPlan ffu.IntegrityDescriptorPlan `json:"integrity_descriptor_plan"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("rufus-ffu-integrity-plan", flag.ContinueOnError)
	imagePath := flags.String("image", "", "single-store-v1 FFU image to verify read-only")
	asJSON := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *imagePath == "" {
		return errors.New("--image is required")
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %v", flags.Args())
	}

	resolved, identity, err := sourcefile.Inspect(*imagePath)
	if err != nil {
		return err
	}
	file, err := sourcefile.OpenRegular(resolved, identity)
	if err != nil {
		return err
	}
	result, planErr := planOpenSource(context.Background(), resolved, identity, file)
	closeErr := file.Close()
	if planErr != nil {
		return planErr
	}
	if closeErr != nil {
		return fmt.Errorf("close FFU image: %w", closeErr)
	}

	if *asJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	}

	verification := result.ContentVerification
	integrated := result.IntegrityDescriptorPlan
	fmt.Printf("FFU image: %s\n", result.Path)
	fmt.Printf("Source size: %s\n", humanBytes(integrated.SourceFileSize))
	fmt.Printf("Source consistency: %s\n", result.SourceConsistency.Mode)
	fmt.Printf("Coverage: bytes [%d,%d), %s across %d chunks\n", verification.CoverageOffset, verification.CoverageEnd, humanBytes(verification.CoverageLength), verification.VerifiedChunkCount)
	if verification.FinalChunkZeroPaddingBytes != 0 {
		fmt.Printf("Final chunk: %s source data plus %s zero padding\n", humanBytes(verification.FinalChunkDataBytes), humanBytes(verification.FinalChunkZeroPaddingBytes))
	} else {
		fmt.Println("Final chunk: complete; no zero padding")
	}
	fmt.Printf("Embedded hash table: %d SHA-256 entries, all source chunks match\n", verification.HashEntryCount)
	fmt.Printf("Hash-table SHA-256: %s\n", verification.HashTableSHA256)
	fmt.Printf("Descriptor plan SHA-256: %s\n", result.DescriptorPlan.PlanSHA256)
	fmt.Printf("Integrity descriptor plan SHA-256: %s\n", integrated.PlanSHA256)
	fmt.Println("Catalog authentication: not attempted")
	fmt.Println("Publisher integrity authentication: false")
	fmt.Println("Target binding: not performed")
	fmt.Println("Execution: disabled — this command has no target argument")
	for _, limitation := range integrated.Limitations {
		fmt.Printf("- %s\n", limitation)
	}
	return nil
}

func planOpenSource(ctx context.Context, path string, identity sourcefile.Identity, file *os.File) (report, error) {
	result := report{Path: path, SourceIdentity: identity}
	lease, leaseErr := sourcefile.AcquireReadLease(ctx, file, identity)
	if leaseErr == nil {
		result.SourceConsistency = sourceConsistency{Mode: "linux-read-lease", ReadLeaseHeld: true}
		inspection, descriptor, hashPlan, verification, integrated, planErr := ffu.PlanVerifiedSingleStoreV1(lease.Context(), file, uint64(identity.Size))
		checkErr := lease.Check()
		pinnedErr := sourcefile.VerifyPinned(file, identity)
		closeErr := lease.Close()
		if planErr != nil {
			return result, planErr
		}
		if checkErr != nil {
			return result, checkErr
		}
		if pinnedErr != nil {
			return result, pinnedErr
		}
		if closeErr != nil {
			return result, closeErr
		}
		result.SourceConsistency.SourceStable = true
		result.Inspection = inspection
		result.DescriptorPlan = descriptor
		result.HashTablePlan = hashPlan
		result.ContentVerification = verification
		result.IntegrityDescriptorPlan = integrated
		return result, nil
	}

	unavailable := errors.Is(leaseErr, sourcefile.ErrReadLeaseUnavailable)
	conflict := errors.Is(leaseErr, sourcefile.ErrReadLeaseConflict)
	if !unavailable && !conflict {
		return result, leaseErr
	}
	result.SourceConsistency = sourceConsistency{
		Mode:                 "conservative-before-after-sha256",
		ReadLeaseUnavailable: unavailable,
		ReadLeaseConflict:    conflict,
	}
	firstDigest, err := sourcefile.SHA256Open(ctx, file, nil)
	if err != nil {
		return result, fmt.Errorf("hash FFU source before integrity planning: %w", err)
	}
	inspection, descriptor, hashPlan, verification, integrated, planErr := ffu.PlanVerifiedSingleStoreV1(ctx, file, uint64(identity.Size))
	if planErr != nil {
		return result, planErr
	}
	if err := sourcefile.VerifyPinned(file, identity); err != nil {
		return result, err
	}
	secondDigest, err := sourcefile.SHA256Open(ctx, file, nil)
	if err != nil {
		return result, fmt.Errorf("rehash FFU source after integrity planning: %w", err)
	}
	if firstDigest != secondDigest {
		return result, errors.New("the selected FFU changed while its integrity plan was being created")
	}
	result.SourceConsistency.ConservativeSHA256 = hex.EncodeToString(firstDigest[:])
	result.SourceConsistency.SourceStable = true
	result.Inspection = inspection
	result.DescriptorPlan = descriptor
	result.HashTablePlan = hashPlan
	result.ContentVerification = verification
	result.IntegrityDescriptorPlan = integrated
	return result, nil
}

func humanBytes(value uint64) string {
	const unit = uint64(1024)
	if value < unit {
		return fmt.Sprintf("%d B", value)
	}
	divisor, exponent := unit, 0
	for quotient := value / unit; quotient >= unit && exponent < 5; quotient /= unit {
		divisor *= unit
		exponent++
	}
	return fmt.Sprintf("%.1f %ciB", float64(value)/float64(divisor), "KMGTPE"[exponent])
}
