package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

type digestAlgorithmFlags []sourcefile.DigestAlgorithm

func (values *digestAlgorithmFlags) String() string {
	parts := make([]string, len(*values))
	for index, value := range *values {
		parts[index] = string(value)
	}
	return strings.Join(parts, ",")
}

func (values *digestAlgorithmFlags) Set(value string) error {
	algorithm, err := sourcefile.ParseDigestAlgorithm(value)
	if err != nil {
		return err
	}
	for _, existing := range *values {
		if existing == algorithm {
			return fmt.Errorf("duplicate digest algorithm %q", algorithm)
		}
	}
	*values = append(*values, algorithm)
	return nil
}

type hashCommandOutput struct {
	Path    string                    `json:"path"`
	Size    uint64                    `json:"size"`
	Digests []sourcefile.DigestResult `json:"digests"`
}

func runHashCommand(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return runHashWithContext(ctx, args)
}

func runHashWithContext(ctx context.Context, args []string) error {
	if ctx == nil {
		return errors.New("hash context is nil")
	}
	flags := flag.NewFlagSet("hash", flag.ContinueOnError)
	var requested digestAlgorithmFlags
	flags.Var(&requested, "algorithm", "checksum algorithm: md5, sha1, sha256, or sha512; repeat to select more than one")
	all := flags.Bool("all", false, "compute MD5, SHA-1, SHA-256, and SHA-512")
	asJSON := flags.Bool("json", false, "output JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("hash requires exactly one file")
	}
	if *all && len(requested) != 0 {
		return errors.New("select either --all or one or more --algorithm values")
	}

	algorithms := []sourcefile.DigestAlgorithm(requested)
	if *all {
		algorithms = sourcefile.SupportedDigestAlgorithms()
	} else if len(algorithms) == 0 {
		algorithms = []sourcefile.DigestAlgorithm{sourcefile.DigestSHA256}
	}

	inputPath := flags.Arg(0)
	resolvedPath, identity, err := sourcefile.Inspect(inputPath)
	if err != nil {
		return err
	}
	file, err := sourcefile.OpenRegular(resolvedPath, identity)
	if err != nil {
		return err
	}
	results, digestErr := sourcefile.DigestsOpen(ctx, file, algorithms, nil)
	closeErr := file.Close()
	if digestErr != nil {
		return digestErr
	}
	if closeErr != nil {
		return fmt.Errorf("close image after hashing: %w", closeErr)
	}

	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(hashCommandOutput{
			Path:    resolvedPath,
			Size:    uint64(identity.Size),
			Digests: results,
		})
	}

	// Preserve the original sha256sum-compatible output for existing scripts.
	if !*all && len(requested) == 0 {
		fmt.Printf("%s  %s\n", results[0].Hex, inputPath)
		return nil
	}
	for _, result := range results {
		fmt.Printf("%s: %s  %s\n", digestDisplayName(result.Algorithm), result.Hex, inputPath)
	}
	return nil
}

func digestDisplayName(algorithm sourcefile.DigestAlgorithm) string {
	switch algorithm {
	case sourcefile.DigestMD5:
		return "MD5"
	case sourcefile.DigestSHA1:
		return "SHA-1"
	case sourcefile.DigestSHA256:
		return "SHA-256"
	case sourcefile.DigestSHA512:
		return "SHA-512"
	default:
		return strings.ToUpper(string(algorithm))
	}
}
