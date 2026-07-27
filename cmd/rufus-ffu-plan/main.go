//go:build linux

// rufus-ffu-plan is a read-only development tool for deterministic FFU
// single-store-v1 planning. It has no target argument and cannot write media.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/geocausa/RufusArm64/internal/ffu"
	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

type report struct {
	Path           string              `json:"path"`
	SourceIdentity sourcefile.Identity `json:"source_identity"`
	Inspection     ffu.Inspection      `json:"inspection"`
	Plan           ffu.DescriptorPlan  `json:"plan"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("rufus-ffu-plan", flag.ContinueOnError)
	imagePath := flags.String("image", "", "single-store FFU image to plan read-only")
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
	inspection, plan, planErr := ffu.PlanSingleStoreV1(file, uint64(identity.Size))
	closeErr := file.Close()
	if planErr != nil {
		return planErr
	}
	if closeErr != nil {
		return fmt.Errorf("close FFU image: %w", closeErr)
	}

	result := report{
		Path:           resolved,
		SourceIdentity: identity,
		Inspection:     inspection,
		Plan:           plan,
	}
	if *asJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	}

	fmt.Printf("FFU image: %s\n", result.Path)
	fmt.Printf("Source size: %s\n", humanBytes(plan.SourceFileSize))
	fmt.Printf("Store header: %d.%d (single-store v1 planner)\n", plan.StoreMajorVersion, plan.StoreMinorVersion)
	fmt.Printf("Chunk / block: %s / %s\n", humanBytes(plan.ChunkSizeBytes), humanBytes(plan.BlockSizeBytes))
	fmt.Printf("Validation descriptors: %d\n", len(plan.ValidationDescriptors))
	fmt.Printf("Write descriptors: %d\n", len(plan.WriteDescriptors))
	fmt.Printf("Payload: %s across %d blocks, starting at byte %d\n", humanBytes(plan.PayloadLength), plan.TotalPayloadBlocks, plan.PayloadOffset)
	fmt.Printf("Minimum target surface: %s (%d blocks)\n", humanBytes(plan.MinimumTargetBytes), plan.MinimumTargetBlocks)
	fmt.Printf("Plan SHA-256: %s\n", plan.PlanSHA256)
	if plan.HasDestinationOverlap {
		fmt.Printf("Same-anchor destination overlaps: %d (execution remains disabled)\n", len(plan.DestinationOverlaps))
	} else {
		fmt.Println("Same-anchor destination overlaps: none detected")
	}
	fmt.Println("Integrity authentication: not implemented")
	fmt.Println("Target binding: not performed")
	fmt.Println("Execution: disabled — this command has no target argument")
	for _, limitation := range plan.Limitations {
		fmt.Printf("- %s\n", limitation)
	}
	return nil
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
