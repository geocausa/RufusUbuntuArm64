//go:build linux

// rufus-ffu-hash-plan is a read-only development tool for FFU catalog and
// hash-table structural planning. It has no target argument and cannot write
// media.
package main

import (
	"context"
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
	HashTablePlan  ffu.HashTablePlan   `json:"hash_table_plan"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("rufus-ffu-hash-plan", flag.ContinueOnError)
	imagePath := flags.String("image", "", "FFU image to inspect read-only")
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
	inspection, plan, planErr := ffu.PlanHashTable(context.Background(), file, uint64(identity.Size))
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
		HashTablePlan:  plan,
	}
	if *asJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	}

	fmt.Printf("FFU image: %s\n", result.Path)
	fmt.Printf("Source size: %s\n", humanBytes(plan.SourceFileSize))
	fmt.Printf("Hash algorithm: %s (0x%08x, %d-byte digests)\n", plan.Algorithm, plan.AlgorithmID, plan.DigestSizeBytes)
	fmt.Printf("Catalog: %s at byte %d\n", humanBytes(plan.CatalogLength), plan.CatalogOffset)
	fmt.Printf("Catalog SHA-256: %s\n", plan.CatalogSHA256)
	fmt.Printf("Hash table: %s at byte %d (%d entries)\n", humanBytes(plan.HashTableLength), plan.HashTableOffset, plan.HashEntryCount)
	fmt.Printf("Hash-table SHA-256: %s\n", plan.HashTableSHA256)
	fmt.Printf("Plan SHA-256: %s\n", plan.PlanSHA256)
	fmt.Println("Catalog authentication: not attempted")
	fmt.Println("Source-content verification: not attempted")
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
