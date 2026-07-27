//go:build linux

// rufus-ffu-inspect is a read-only development tool for the FFU parser. It is
// intentionally separate from the privileged RufusArm64 writer and is not a
// restoration command.
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
	FFU            ffu.Inspection      `json:"ffu"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("rufus-ffu-inspect", flag.ContinueOnError)
	imagePath := flags.String("image", "", "FFU image to inspect read-only")
	asJSON := flags.Bool("json", false, "emit JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *imagePath == "" {
		return errors.New("--image is required")
	}
	resolved, identity, err := sourcefile.Inspect(*imagePath)
	if err != nil {
		return err
	}
	file, err := sourcefile.OpenRegular(resolved, identity)
	if err != nil {
		return err
	}
	inspection, inspectErr := ffu.Inspect(file, uint64(identity.Size))
	closeErr := file.Close()
	if inspectErr != nil {
		return inspectErr
	}
	if closeErr != nil {
		return fmt.Errorf("close FFU image: %w", closeErr)
	}

	result := report{Path: resolved, SourceIdentity: identity, FFU: inspection}
	if *asJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	}
	fmt.Printf("FFU image: %s\n", result.Path)
	fmt.Printf("Reported Full Flash version: %d.%d\n", inspection.Store.FullFlashMajorVersion, inspection.Store.FullFlashMinorVersion)
	if inspection.Store.PlatformID != "" {
		fmt.Printf("Platform ID: %s\n", inspection.Store.PlatformID)
	}
	fmt.Printf("Container size: %s\n", humanBytes(inspection.FileSize))
	fmt.Printf("Security chunk: %s\n", humanBytes(inspection.Security.ChunkSizeBytes))
	fmt.Printf("Store block: %s\n", humanBytes(uint64(inspection.Store.BlockSizeBytes)))
	fmt.Printf("Write descriptors: %d (%s declared table)\n", inspection.Store.WriteDescriptorCount, humanBytes(uint64(inspection.Store.WriteDescriptorLength)))
	fmt.Printf("Validation descriptors: %d (%s declared table)\n", inspection.Store.ValidateDescriptorCount, humanBytes(uint64(inspection.Store.ValidateDescriptorLength)))
	fmt.Printf("Common store prefix ends at byte: %d\n", inspection.StoreCommonEndOffset)
	fmt.Println("Descriptor and payload offsets: unresolved")
	fmt.Println("Restoration: disabled — read-only common-prefix inspection only")
	for _, limitation := range inspection.Limitations {
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
