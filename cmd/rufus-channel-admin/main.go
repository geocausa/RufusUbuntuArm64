// rufus-channel-admin prepares and verifies public acquisition metadata.
// It deliberately has no private-key input or signing implementation.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/geocausa/RufusArm64/internal/acquisition"
)

const maxOperatorFileBytes = 2 * 1024 * 1024

type stringList []string

func (values *stringList) String() string { return strings.Join(*values, ",") }
func (values *stringList) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("value cannot be empty")
	}
	*values = append(*values, value)
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage(os.Stdout)
		return nil
	}
	switch args[0] {
	case "key-id":
		return runKeyID(args[1:])
	case "payload":
		return runPayload(args[1:])
	case "envelope":
		return runEnvelope(args[1:])
	case "verify":
		return runVerify(args[1:])
	case "channel-config":
		return runChannelConfig(args[1:])
	case "publish":
		return runPublish(args[1:])
	case "help", "--help", "-h":
		usage(os.Stdout)
		return nil
	default:
		usage(os.Stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage(output io.Writer) {
	fmt.Fprint(output, `RufusArm64 offline acquisition metadata administrator

This source-only tool handles public keys, canonical payloads, detached
signatures, and public channel configuration. Signing is performed externally.

Usage:
  rufus-channel-admin key-id --public-key FILE [--json]
  rufus-channel-admin payload root --input FILE --output FILE --manifest FILE [--now RFC3339]
  rufus-channel-admin payload catalog --root FILE [--root FILE...] --input FILE --output FILE --manifest FILE [--now RFC3339]
  rufus-channel-admin envelope assemble --payload FILE --signature KEYID=FILE [--signature KEYID=FILE...] [--root FILE...] --output FILE [--now RFC3339]
  rufus-channel-admin verify root --root FILE [--root FILE...] [--now RFC3339] [--json]
  rufus-channel-admin verify catalog --root FILE [--root FILE...] --catalog FILE [--now RFC3339] [--json]
  rufus-channel-admin channel-config --bootstrap-root FILE --root-url URL --catalog-url URL --host HOST [--host HOST...] --output FILE [--now RFC3339]
  rufus-channel-admin publish --root FILE [--root FILE...] --catalog FILE --config FILE --directory DIR [--now RFC3339]

Output files are created atomically with owner-only permissions. Existing files
are refused unless --force is supplied.
`)
}

func runKeyID(args []string) error {
	fs := flag.NewFlagSet("key-id", flag.ContinueOnError)
	publicKeyPath := fs.String("public-key", "", "Ed25519 public key file")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *publicKeyPath == "" {
		return errors.New("key-id requires --public-key and no positional arguments")
	}
	data, err := readOperatorFile(*publicKeyPath, 4096)
	if err != nil {
		return err
	}
	summary, err := acquisition.DescribePublicKey(data)
	if err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(summary)
	}
	fmt.Printf("Key ID: %s\nType: %s\nPublic key: %s\n", summary.KeyID, summary.Type, summary.PublicKey)
	return nil
}

func runPayload(args []string) error {
	if len(args) == 0 {
		return errors.New("payload requires root or catalog")
	}
	switch args[0] {
	case "root":
		return runRootPayload(args[1:])
	case "catalog":
		return runCatalogPayload(args[1:])
	default:
		return fmt.Errorf("unknown payload type %q", args[0])
	}
}

func runRootPayload(args []string) error {
	fs := flag.NewFlagSet("payload root", flag.ContinueOnError)
	input := fs.String("input", "", "unsigned root metadata draft")
	output := fs.String("output", "", "canonical payload output")
	manifestPath := fs.String("manifest", "", "signing manifest output")
	nowText := fs.String("now", "", "validation time in RFC3339")
	force := fs.Bool("force", false, "replace existing output files")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *input == "" || *output == "" || *manifestPath == "" {
		return errors.New("payload root requires --input, --output, and --manifest")
	}
	now, err := parseNow(*nowText)
	if err != nil {
		return err
	}
	data, err := readOperatorFile(*input, acquisition.MaxRootMetadataBytes)
	if err != nil {
		return err
	}
	payload, manifest, err := acquisition.CanonicalizeRootDraft(data, now)
	if err != nil {
		return err
	}
	return writePayloadAndManifest(*output, *manifestPath, payload, manifest, *force)
}

func runCatalogPayload(args []string) error {
	fs := flag.NewFlagSet("payload catalog", flag.ContinueOnError)
	input := fs.String("input", "", "unsigned catalog metadata draft")
	output := fs.String("output", "", "canonical payload output")
	manifestPath := fs.String("manifest", "", "signing manifest output")
	nowText := fs.String("now", "", "validation time in RFC3339")
	force := fs.Bool("force", false, "replace existing output files")
	var roots stringList
	fs.Var(&roots, "root", "signed root metadata file in sequential order")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || len(roots) == 0 || *input == "" || *output == "" || *manifestPath == "" {
		return errors.New("payload catalog requires at least one --root plus --input, --output, and --manifest")
	}
	now, err := parseNow(*nowText)
	if err != nil {
		return err
	}
	root, err := readAndVerifyRootChain(roots, now)
	if err != nil {
		return err
	}
	data, err := readOperatorFile(*input, acquisition.MaxChannelCatalogBytes)
	if err != nil {
		return err
	}
	payload, manifest, err := acquisition.CanonicalizeCatalogDraft(root, data, now)
	if err != nil {
		return err
	}
	return writePayloadAndManifest(*output, *manifestPath, payload, manifest, *force)
}

func runEnvelope(args []string) error {
	if len(args) == 0 || args[0] != "assemble" {
		return errors.New("envelope requires assemble")
	}
	fs := flag.NewFlagSet("envelope assemble", flag.ContinueOnError)
	payloadPath := fs.String("payload", "", "canonical payload file")
	output := fs.String("output", "", "signed envelope output")
	force := fs.Bool("force", false, "replace an existing output file")
	nowText := fs.String("now", "", "validation time in RFC3339")
	var signatureSpecs stringList
	var roots stringList
	fs.Var(&signatureSpecs, "signature", "detached signature as KEYID=FILE")
	fs.Var(&roots, "root", "previous signed root metadata file in sequential order")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || *payloadPath == "" || *output == "" || len(signatureSpecs) == 0 {
		return errors.New("envelope assemble requires --payload, at least one --signature, and --output")
	}
	now, err := parseNow(*nowText)
	if err != nil {
		return err
	}
	payload, err := readOperatorFile(*payloadPath, acquisition.MaxChannelCatalogBytes)
	if err != nil {
		return err
	}
	detached := make([]acquisition.DetachedMetadataSignature, 0, len(signatureSpecs))
	for _, spec := range signatureSpecs {
		keyID, path, ok := strings.Cut(spec, "=")
		if !ok || strings.TrimSpace(keyID) == "" || strings.TrimSpace(path) == "" {
			return fmt.Errorf("invalid --signature %q; expected KEYID=FILE", spec)
		}
		signature, err := readOperatorFile(path, 4096)
		if err != nil {
			return err
		}
		detached = append(detached, acquisition.DetachedMetadataSignature{KeyID: keyID, Signature: signature})
	}
	envelope, err := acquisition.AssembleMetadataEnvelope(payload, detached)
	if err != nil {
		return err
	}
	var current *acquisition.VerifiedRoot
	if len(roots) > 0 {
		current, err = readAndVerifyRootChain(roots, now)
		if err != nil {
			return err
		}
	}
	if _, err := acquisition.VerifyAdministrativeEnvelope(current, envelope, now); err != nil {
		return fmt.Errorf("authorize assembled envelope: %w", err)
	}
	return writeAtomicOutput(*output, envelope, *force)
}

func runVerify(args []string) error {
	if len(args) == 0 {
		return errors.New("verify requires root or catalog")
	}
	switch args[0] {
	case "root":
		return runVerifyRoot(args[1:])
	case "catalog":
		return runVerifyCatalog(args[1:])
	default:
		return fmt.Errorf("unknown verification type %q", args[0])
	}
}

func runVerifyRoot(args []string) error {
	fs := flag.NewFlagSet("verify root", flag.ContinueOnError)
	nowText := fs.String("now", "", "validation time in RFC3339")
	asJSON := fs.Bool("json", false, "output JSON")
	var roots stringList
	fs.Var(&roots, "root", "signed root metadata file in sequential order")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || len(roots) == 0 {
		return errors.New("verify root requires at least one --root")
	}
	now, err := parseNow(*nowText)
	if err != nil {
		return err
	}
	root, err := readAndVerifyRootChain(roots, now)
	if err != nil {
		return err
	}
	result := map[string]any{
		"version": root.Metadata.Version, "generated": root.Metadata.Generated,
		"expires": root.Metadata.Expires, "sha256": root.SHA256,
		"root_threshold":    root.Metadata.Roles.Root.Threshold,
		"catalog_threshold": root.Metadata.Roles.Catalog.Threshold,
	}
	return printResult(result, *asJSON)
}

func runVerifyCatalog(args []string) error {
	fs := flag.NewFlagSet("verify catalog", flag.ContinueOnError)
	catalogPath := fs.String("catalog", "", "signed catalog envelope")
	nowText := fs.String("now", "", "validation time in RFC3339")
	asJSON := fs.Bool("json", false, "output JSON")
	var roots stringList
	fs.Var(&roots, "root", "signed root metadata file in sequential order")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || len(roots) == 0 || *catalogPath == "" {
		return errors.New("verify catalog requires at least one --root and --catalog")
	}
	now, err := parseNow(*nowText)
	if err != nil {
		return err
	}
	root, err := readAndVerifyRootChain(roots, now)
	if err != nil {
		return err
	}
	catalogData, err := readOperatorFile(*catalogPath, acquisition.MaxChannelCatalogBytes)
	if err != nil {
		return err
	}
	catalog, err := acquisition.VerifyChannelCatalog(root, catalogData, now)
	if err != nil {
		return err
	}
	result := map[string]any{
		"root_version": root.Metadata.Version, "catalog_version": catalog.Metadata.Version,
		"generated": catalog.Metadata.Generated, "expires": catalog.Metadata.Expires,
		"sha256": catalog.SHA256, "signing_key_ids": catalog.SigningKeyIDs,
		"images": len(catalog.Metadata.Images),
	}
	return printResult(result, *asJSON)
}

func runChannelConfig(args []string) error {
	fs := flag.NewFlagSet("channel-config", flag.ContinueOnError)
	bootstrapRoot := fs.String("bootstrap-root", "", "signed bootstrap root envelope")
	rootURL := fs.String("root-url", "", "versioned root URL containing {version}")
	catalogURL := fs.String("catalog-url", "", "catalog metadata URL")
	output := fs.String("output", "", "channel configuration output")
	nowText := fs.String("now", "", "validation time in RFC3339")
	force := fs.Bool("force", false, "replace an existing output file")
	var hosts stringList
	fs.Var(&hosts, "host", "allowlisted distribution host")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *bootstrapRoot == "" || *rootURL == "" || *catalogURL == "" || *output == "" || len(hosts) == 0 {
		return errors.New("channel-config requires --bootstrap-root, --root-url, --catalog-url, at least one --host, and --output")
	}
	now, err := parseNow(*nowText)
	if err != nil {
		return err
	}
	rootData, err := readOperatorFile(*bootstrapRoot, acquisition.MaxRootMetadataBytes)
	if err != nil {
		return err
	}
	root, err := acquisition.VerifyBootstrapRoot(rootData, now)
	if err != nil {
		return fmt.Errorf("verify bootstrap root: %w", err)
	}
	if root.Metadata.Version != 1 {
		return fmt.Errorf("bootstrap root version must be 1, got %d", root.Metadata.Version)
	}
	config := acquisition.ChannelConfig{
		Schema: acquisition.ChannelConfigSchema, Enabled: true,
		BootstrapRoot: "1.root.json", RootURL: *rootURL,
		CatalogURL: *catalogURL, AllowedHosts: append([]string(nil), hosts...),
	}
	data, err := acquisition.CanonicalizeChannelConfig(config)
	if err != nil {
		return err
	}
	return writeAtomicOutput(*output, data, *force)
}

func runPublish(args []string) error {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	catalogPath := fs.String("catalog", "", "signed catalog envelope")
	configPath := fs.String("config", "", "enabled public channel configuration")
	directory := fs.String("directory", "", "new publication directory")
	nowText := fs.String("now", "", "validation time in RFC3339")
	var roots stringList
	fs.Var(&roots, "root", "signed root metadata file in sequential order")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || len(roots) == 0 || *catalogPath == "" || *configPath == "" || *directory == "" {
		return errors.New("publish requires at least one --root plus --catalog, --config, and --directory")
	}
	now, err := parseNow(*nowText)
	if err != nil {
		return err
	}
	rootData := make([][]byte, 0, len(roots))
	for _, path := range roots {
		data, err := readOperatorFile(path, acquisition.MaxRootMetadataBytes)
		if err != nil {
			return err
		}
		rootData = append(rootData, data)
	}
	sequence, err := acquisition.VerifyRootChainSequence(rootData, now)
	if err != nil {
		return err
	}
	if sequence[0].Metadata.Version != 1 {
		return fmt.Errorf("publication bootstrap root version must be 1, got %d", sequence[0].Metadata.Version)
	}
	catalogData, err := readOperatorFile(*catalogPath, acquisition.MaxChannelCatalogBytes)
	if err != nil {
		return err
	}
	catalog, err := acquisition.VerifyChannelCatalog(sequence[len(sequence)-1], catalogData, now)
	if err != nil {
		return err
	}
	configData, err := readOperatorFile(*configPath, acquisition.MaxChannelConfigBytes)
	if err != nil {
		return err
	}
	config, canonicalConfig, err := acquisition.CanonicalizeChannelConfigDraft(configData)
	if err != nil {
		return err
	}
	if config.BootstrapRoot != "1.root.json" {
		return fmt.Errorf("publication bootstrap_root must be %q", "1.root.json")
	}
	if err := validatePublicationURLNames(config); err != nil {
		return err
	}
	files := make(map[string][]byte, len(sequence)+3)
	for index, root := range sequence {
		canonical, err := acquisition.CanonicalizeSignedEnvelope(rootData[index])
		if err != nil {
			return fmt.Errorf("canonicalize root version %d: %w", root.Metadata.Version, err)
		}
		files[fmt.Sprintf("%d.root.json", root.Metadata.Version)] = canonical
	}
	canonicalCatalog, err := acquisition.CanonicalizeSignedEnvelope(catalogData)
	if err != nil {
		return fmt.Errorf("canonicalize catalog: %w", err)
	}
	files["catalog.json"] = canonicalCatalog
	files["channel.json"] = canonicalConfig
	summary := map[string]any{
		"schema": 1,
		"root_versions": func() []int {
			versions := make([]int, 0, len(sequence))
			for _, root := range sequence {
				versions = append(versions, root.Metadata.Version)
			}
			return versions
		}(),
		"final_root_sha256": sequence[len(sequence)-1].SHA256,
		"catalog_version":   catalog.Metadata.Version,
		"catalog_sha256":    catalog.SHA256,
		"catalog_images":    len(catalog.Metadata.Images),
	}
	summaryBytes, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	files["publication.json"] = append(summaryBytes, '\n')
	return writePublicationDirectory(*directory, files)
}

func validatePublicationURLNames(config acquisition.ChannelConfig) error {
	rootURL, err := url.Parse(config.RootURL)
	if err != nil {
		return err
	}
	if filepath.Base(rootURL.Path) != "{version}.root.json" {
		return errors.New("root_url path must end with {version}.root.json for the generated publication layout")
	}
	catalogURL, err := url.Parse(config.CatalogURL)
	if err != nil {
		return err
	}
	if filepath.Base(catalogURL.Path) != "catalog.json" {
		return errors.New("catalog_url path must end with catalog.json for the generated publication layout")
	}
	return nil
}

func writePublicationDirectory(path string, files map[string][]byte) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("publication directory is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(absolute); err == nil {
		return fmt.Errorf("publication directory %s already exists", absolute)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(absolute)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return err
	}
	cleanParent, err := filepath.Abs(parent)
	if err != nil {
		return err
	}
	if filepath.Clean(resolvedParent) != filepath.Clean(cleanParent) {
		return errors.New("publication parent directory must not contain symbolic links")
	}
	temporary, err := os.MkdirTemp(parent, ".rufus-channel-publication-*")
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(temporary)
		}
	}()
	names := make([]string, 0, len(files))
	for name := range files {
		if filepath.Base(name) != name || strings.ContainsAny(name, `/\\`) {
			return fmt.Errorf("invalid publication filename %q", name)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	checksumLines := make([]string, 0, len(names))
	for _, name := range names {
		data := files[name]
		filePath := filepath.Join(temporary, name)
		file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o644)
		if err != nil {
			return err
		}
		if _, err := file.Write(data); err != nil {
			file.Close()
			return err
		}
		if err := file.Chmod(0o644); err != nil {
			file.Close()
			return err
		}
		if err := file.Sync(); err != nil {
			file.Close()
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
		digest := sha256.Sum256(data)
		checksumLines = append(checksumLines, hex.EncodeToString(digest[:])+"  "+name)
	}
	checksums := []byte(strings.Join(checksumLines, "\n") + "\n")
	checksumPath := filepath.Join(temporary, "SHA256SUMS")
	checksumFile, err := os.OpenFile(checksumPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return err
	}
	if _, err := checksumFile.Write(checksums); err != nil {
		checksumFile.Close()
		return err
	}
	if err := checksumFile.Chmod(0o644); err != nil {
		checksumFile.Close()
		return err
	}
	if err := checksumFile.Sync(); err != nil {
		checksumFile.Close()
		return err
	}
	if err := checksumFile.Close(); err != nil {
		return err
	}
	if err := os.Chmod(temporary, 0o755); err != nil {
		return err
	}
	directoryFile, err := os.Open(temporary)
	if err != nil {
		return err
	}
	if err := directoryFile.Sync(); err != nil {
		directoryFile.Close()
		return err
	}
	if err := directoryFile.Close(); err != nil {
		return err
	}
	if err := renameNoReplace(temporary, absolute); err != nil {
		return err
	}
	cleanup = false
	parentFile, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer parentFile.Close()
	return parentFile.Sync()
}

func readAndVerifyRootChain(paths []string, now time.Time) (*acquisition.VerifiedRoot, error) {
	envelopes := make([][]byte, 0, len(paths))
	for _, path := range paths {
		data, err := readOperatorFile(path, acquisition.MaxRootMetadataBytes)
		if err != nil {
			return nil, err
		}
		envelopes = append(envelopes, data)
	}
	return acquisition.VerifyRootChain(envelopes, now)
}

func writePayloadAndManifest(payloadPath, manifestPath string, payload []byte, manifest acquisition.SigningManifest, force bool) error {
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := refuseSamePath(payloadPath, manifestPath); err != nil {
		return err
	}
	if err := writeAtomicOutput(payloadPath, payload, force); err != nil {
		return err
	}
	if err := writeAtomicOutput(manifestPath, manifestBytes, force); err != nil {
		return err
	}
	return nil
}

func printResult(value any, asJSON bool) error {
	if asJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(value)
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func parseNow(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Now().UTC(), nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse --now: %w", err)
	}
	return parsed.UTC(), nil
}

func readOperatorFile(path string, limit int) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("file path is required")
	}
	if limit <= 0 || limit > maxOperatorFileBytes {
		limit = maxOperatorFileBytes
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > int64(limit) {
		return nil, fmt.Errorf("%s must be a non-empty regular file no larger than %d bytes", path, limit)
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, limit)
	}
	return data, nil
}

func refuseSamePath(first, second string) error {
	firstAbs, err := filepath.Abs(first)
	if err != nil {
		return err
	}
	secondAbs, err := filepath.Abs(second)
	if err != nil {
		return err
	}
	if filepath.Clean(firstAbs) == filepath.Clean(secondAbs) {
		return errors.New("payload and manifest output paths must differ")
	}
	return nil
}

func writeAtomicOutput(path string, data []byte, force bool) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("output path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	directory := filepath.Dir(absolute)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	if info, err := os.Lstat(absolute); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("existing output is not a regular file")
		}
		if !force {
			return fmt.Errorf("output %s already exists; use --force to replace it", absolute)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".rufus-channel-admin-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	cleanup := true
	defer func() {
		_ = temporary.Close()
		if cleanup {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if !force {
		if _, err := os.Lstat(absolute); err == nil {
			return fmt.Errorf("output %s appeared while writing", absolute)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	var publishErr error
	if force {
		publishErr = os.Rename(temporaryPath, absolute)
	} else {
		publishErr = renameNoReplace(temporaryPath, absolute)
	}
	if publishErr != nil {
		return publishErr
	}
	cleanup = false
	directoryFile, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryFile.Close()
	return directoryFile.Sync()
}
