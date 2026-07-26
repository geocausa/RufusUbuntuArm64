//go:build linux

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/geocausa/RufusArm64/internal/device"
	"github.com/geocausa/RufusArm64/internal/drivebackup"
	"github.com/geocausa/RufusArm64/internal/isocapture"
	"github.com/geocausa/RufusArm64/internal/safety"
)

type isoBackupPlan struct {
	Device      device.BlockDevice               `json:"device"`
	Identity    string                           `json:"identity"`
	Destination drivebackup.DestinationInfo      `json:"destination"`
	Filesystem  isocapture.FilesystemCapturePlan `json:"filesystem_capture"`
	SourceNode  string                           `json:"source_node"`
}

func requestedISO(args []string) bool {
	for index, argument := range args {
		if strings.HasPrefix(argument, "--format=") {
			return strings.EqualFold(strings.TrimSpace(strings.TrimPrefix(argument, "--format=")), "iso")
		}
		if argument == "--format" && index+1 < len(args) {
			return strings.EqualFold(strings.TrimSpace(args[index+1]), "iso")
		}
	}
	return false
}

func newISOCaptureOptions(devicePath, sourceNode string, plan isocapture.FilesystemCapturePlan, progress isocapture.CaptureProgressFunc) isocapture.FilesystemCaptureOptions {
	return isocapture.FilesystemCaptureOptions{
		SourceDevicePath:      devicePath,
		SourceNode:            sourceNode,
		ExpectedBindingSHA256: plan.SourceBindingSHA256,
		ExpectedContentSHA256: plan.SourceContentSHA256,
		VolumeID:              plan.VolumeID,
		Progress:              progress,
	}
}

func validateISOPlanBindings(plan isocapture.FilesystemCapturePlan, expectedBinding, expectedContent string) error {
	if expectedBinding != "" && plan.SourceBindingSHA256 != expectedBinding {
		return fmt.Errorf("mounted ISO source binding changed: got %s, expected %s", plan.SourceBindingSHA256, expectedBinding)
	}
	if expectedContent != "" && plan.SourceContentSHA256 != expectedContent {
		return fmt.Errorf("mounted ISO source content changed: got %s, expected %s", plan.SourceContentSHA256, expectedContent)
	}
	return nil
}

func runISO(args []string) error {
	flags := flag.NewFlagSet("rufusarm64-device-backup", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	devicePath := flags.String("device", "", "whole source disk")
	outputPath := flags.String("output", "", "absolute path for the new ISO file")
	formatText := flags.String("format", "iso", "output format: iso")
	expectedIdentity := flags.String("expected-identity", "", "expected whole-device identity")
	expectedSourceNode := flags.String("expected-source-node", "", "expected mounted filesystem device node")
	expectedSourceMount := flags.String("expected-source-mount", "", "expected mounted filesystem path")
	expectedSourceBinding := flags.String("expected-source-binding-sha256", "", "expected reviewed filesystem binding SHA-256")
	expectedSourceContent := flags.String("expected-source-content-sha256", "", "expected reviewed filesystem content SHA-256")
	volumeID := flags.String("volume-id", "", "uppercase ISO volume identifier")
	yes := flags.Bool("yes", false, "skip interactive confirmation")
	allowFixed := flags.Bool("allow-fixed", false, "allow a non-removable source disk")
	noUnmount := flags.Bool("no-unmount", false, "not applicable to ISO filesystem capture")
	dryRun := flags.Bool("dry-run", false, "validate and display the plan without creating an ISO")
	asJSON := flags.Bool("json", false, "output one deterministic JSON plan or report")
	progressJSON := flags.Bool("progress-json", false, "emit JSON progress records to stderr; requires non-dry-run --json")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if !strings.EqualFold(strings.TrimSpace(*formatText), "iso") {
		return fmt.Errorf("isolated filesystem capture requires --format iso, not %q", *formatText)
	}
	if strings.TrimSpace(*devicePath) == "" {
		return errors.New("--device is required")
	}
	if strings.TrimSpace(*outputPath) == "" {
		return errors.New("--output is required")
	}
	if *noUnmount {
		return errors.New("--no-unmount is not applicable: ISO capture requires one mounted source filesystem")
	}
	identityArgument := strings.TrimSpace(*expectedIdentity)
	nodeArgument := strings.TrimSpace(*expectedSourceNode)
	mountArgument := strings.TrimSpace(*expectedSourceMount)
	bindingArgument := strings.ToLower(strings.TrimSpace(*expectedSourceBinding))
	contentArgument := strings.ToLower(strings.TrimSpace(*expectedSourceContent))
	if *yes && (identityArgument == "" || nodeArgument == "" || mountArgument == "" || bindingArgument == "" || contentArgument == "") {
		return errors.New("ISO --yes requires --expected-identity, --expected-source-node, --expected-source-mount, --expected-source-binding-sha256, and --expected-source-content-sha256")
	}
	if *allowFixed && identityArgument == "" {
		return errors.New("--allow-fixed requires --expected-identity")
	}
	if *asJSON && !*dryRun && !*yes {
		return errors.New("non-dry-run ISO --json requires --yes and all expected source bindings")
	}
	if *progressJSON && (!*asJSON || *dryRun) {
		return errors.New("--progress-json requires non-dry-run --json")
	}
	if strings.TrimSpace(os.Getenv("PKEXEC_UID")) != "" {
		if *dryRun || !*yes || !*asJSON || identityArgument == "" || nodeArgument == "" || mountArgument == "" || bindingArgument == "" || contentArgument == "" {
			return errors.New("graphical ISO capture requires --yes, --json, and all expected source bindings without --dry-run")
		}
		if *allowFixed {
			return errors.New("graphical ISO capture is limited to normal removable sources")
		}
	}

	setTrustedSystemPath()
	resolved, err := safety.ResolveDevice(*devicePath)
	if err != nil {
		return err
	}
	selected, err := device.Find(resolved)
	if err != nil {
		return err
	}
	identity := identityArgument
	if identity == "" {
		identity = selected.Identity
	}
	if err := safety.ValidateExpectedIdentity(selected, identity); err != nil {
		return err
	}
	if err := validateSource(resolved, selected, *allowFixed); err != nil {
		return err
	}
	sourceNode, sourceMount, err := selectISOSource(selected)
	if err != nil {
		return err
	}
	if nodeArgument != "" && sourceNode.Path != nodeArgument {
		return fmt.Errorf("mounted ISO source node changed: got %s, expected %s", sourceNode.Path, nodeArgument)
	}
	if mountArgument != "" && sourceMount != mountArgument {
		return fmt.Errorf("mounted ISO source path changed: got %s, expected %s", sourceMount, mountArgument)
	}
	plan, err := isocapture.InspectFilesystemCapture(context.Background(), sourceMount, *outputPath, resolved, *volumeID, isocapture.Limits{})
	if err != nil {
		return err
	}
	if err := validateISOPlanBindings(plan, bindingArgument, contentArgument); err != nil {
		return err
	}
	planned := isoBackupPlan{
		Device:   selected,
		Identity: identity,
		Destination: drivebackup.DestinationInfo{
			Path:           plan.Destination,
			Directory:      filepath.Dir(plan.Destination),
			Format:         drivebackup.Format("iso"),
			SourceBytes:    plan.SourceBytes,
			RequiredBytes:  plan.RequiredBytes,
			AvailableBytes: plan.AvailableBytes,
		},
		Filesystem: plan,
		SourceNode: sourceNode.Path,
	}
	if *dryRun {
		if *asJSON {
			return json.NewEncoder(os.Stdout).Encode(planned)
		}
		printISOPlan(planned)
		fmt.Println("Dry run complete; no private mount or destination file was created.")
		return nil
	}
	if err := safety.RequireRoot(); err != nil {
		return err
	}
	if !*asJSON {
		printISOPlan(planned)
	}
	if !*yes {
		if err := confirmISOCapture(resolved, sourceNode.Path, sourceMount, plan.Destination); err != nil {
			return err
		}
	}

	fresh, _, err := revalidateSource(resolved, identity, *allowFixed)
	if err != nil {
		return err
	}
	freshNode, freshMount, err := selectISOSource(fresh)
	if err != nil {
		return err
	}
	if freshNode.Path != sourceNode.Path || freshMount != sourceMount {
		return errors.New("the selected mounted filesystem changed after confirmation")
	}
	if nodeArgument != "" && freshNode.Path != nodeArgument {
		return errors.New("the selected mounted filesystem node no longer matches the reviewed plan")
	}
	if mountArgument != "" && freshMount != mountArgument {
		return errors.New("the selected mounted filesystem path no longer matches the reviewed plan")
	}

	signalCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	ctx, cancel := context.WithCancel(signalCtx)
	defer cancel()
	phaseStarted := time.Now()
	currentPhase := ""
	lastProgress := time.Time{}
	var progressErr error
	report, runErr := isocapture.CaptureFilesystem(ctx, sourceMount, plan.Destination, newISOCaptureOptions(
		resolved,
		freshNode.Path,
		plan,
		func(progress isocapture.CaptureProgress) {
			if progress.Phase != currentPhase {
				currentPhase = progress.Phase
				phaseStarted = time.Now()
				lastProgress = time.Time{}
			}
			if time.Since(lastProgress) < 200*time.Millisecond && (progress.Total == 0 || progress.Done != progress.Total) {
				return
			}
			lastProgress = time.Now()
			elapsed := time.Since(phaseStarted)
			if *progressJSON {
				if progressErr == nil {
					if err := writeISOJSONProgress(os.Stderr, progress, elapsed); err != nil {
						progressErr = err
						cancel()
					}
				}
				return
			}
			if *asJSON {
				return
			}
			printISOProgress(progress, elapsed)
		},
	))
	if !*asJSON && !lastProgress.IsZero() {
		fmt.Println()
	}
	if *asJSON && report.Schema != 0 {
		if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
			return err
		}
	} else if !*asJSON && report.Schema != 0 {
		printISOReport(report)
	}
	if progressErr != nil {
		return fmt.Errorf("write ISO JSON progress: %w", progressErr)
	}
	return runErr
}

func selectISOSource(selected device.BlockDevice) (device.BlockDevice, string, error) {
	if selected.Type != "disk" {
		return device.BlockDevice{}, "", errors.New("ISO capture requires a selected whole disk")
	}
	var sourceNodes []device.BlockDevice
	var mountpoints []string
	for _, node := range device.Flatten(selected) {
		for _, mountpoint := range node.Mountpoints {
			clean := filepath.Clean(strings.TrimSpace(mountpoint))
			if clean == "." || !filepath.IsAbs(clean) {
				return device.BlockDevice{}, "", fmt.Errorf("source node %s reports an invalid mountpoint %q", node.Path, mountpoint)
			}
			sourceNodes = append(sourceNodes, node)
			mountpoints = append(mountpoints, clean)
		}
	}
	if len(mountpoints) != 1 {
		return device.BlockDevice{}, "", fmt.Errorf("ISO capture requires exactly one mounted source filesystem; found %d mountpoints", len(mountpoints))
	}
	if sourceNodes[0].Type != "part" && sourceNodes[0].Type != "disk" {
		return device.BlockDevice{}, "", fmt.Errorf("mounted ISO source %s has unsupported device type %q", sourceNodes[0].Path, sourceNodes[0].Type)
	}
	return sourceNodes[0], mountpoints[0], nil
}

func printISOPlan(planned isoBackupPlan) {
	name := strings.TrimSpace(strings.Join([]string{planned.Device.Vendor, planned.Device.Model}, " "))
	if name == "" {
		name = planned.Device.Path
	}
	fmt.Printf("Source disk: %s (%s)\n", name, planned.Device.Path)
	fmt.Printf("Source filesystem: %s mounted at %s\n", planned.SourceNode, planned.Filesystem.SourceMount)
	fmt.Printf("Supported content: %d files, %d directories, %s\n", planned.Filesystem.Files, planned.Filesystem.Directories, humanBytes(planned.Filesystem.SourceBytes))
	fmt.Printf("Destination: %s (ISO9660/Joliet/UDF)\n", planned.Filesystem.Destination)
	fmt.Printf("Available: %s; conservative required: %s\n", humanBytes(planned.Filesystem.AvailableBytes), humanBytes(planned.Filesystem.RequiredBytes))
	for _, limitation := range planned.Filesystem.Limitations {
		fmt.Printf("Limitation: %s\n", limitation)
	}
}

func confirmISOCapture(devicePath, sourceNode, sourceMount, output string) error {
	fmt.Fprintf(os.Stderr, "The mounted filesystem %s at %s on %s will be remastered read-only.\n", sourceNode, sourceMount, devicePath)
	fmt.Fprintln(os.Stderr, "This does not capture partition tables, hidden sectors, boot records, or unallocated space.")
	phrase := isoConfirmationPhrase(devicePath, sourceNode, sourceMount, output)
	fmt.Fprintf(os.Stderr, "Type %s to continue: ", phrase)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return err
	}
	if strings.TrimSpace(line) != phrase {
		return errors.New("confirmation failed")
	}
	return nil
}

func isoConfirmationPhrase(devicePath, sourceNode, sourceMount, output string) string {
	return "SAVE FILESYSTEM " + sourceNode + " AT " + sourceMount + " ON " + devicePath + " TO " + output
}

func writeISOJSONProgress(writer io.Writer, progress isocapture.CaptureProgress, elapsed time.Duration) error {
	event := backupProgress{
		Schema:    2,
		Type:      "progress",
		Phase:     progress.Phase,
		Done:      progress.Done,
		Total:     progress.Total,
		ElapsedMS: elapsed.Milliseconds(),
	}
	if elapsed > 0 && progress.Done > 0 {
		rate := float64(progress.Done) / elapsed.Seconds()
		if rate > 0 {
			event.BytesPerSecond = uint64(rate)
		}
		if progress.Total > progress.Done {
			seconds := int64(math.Ceil(float64(progress.Total-progress.Done) / rate))
			event.ETASeconds = &seconds
		}
	}
	return json.NewEncoder(writer).Encode(event)
}

func printISOProgress(progress isocapture.CaptureProgress, elapsed time.Duration) {
	if progress.Total == 0 {
		fmt.Printf("\r%-20s %s", progress.Phase, progress.Message)
		return
	}
	percent := float64(progress.Done) * 100 / float64(progress.Total)
	rate := float64(0)
	if elapsed > 0 {
		rate = float64(progress.Done) / elapsed.Seconds()
	}
	eta := "--"
	if rate > 0 && progress.Done < progress.Total {
		eta = time.Duration(float64(progress.Total-progress.Done) / rate * float64(time.Second)).Round(time.Second).String()
	}
	fmt.Printf("\r%-20s %6.2f%%  %s / %s  %s/s  ETA %s", progress.Phase, percent, humanBytes(progress.Done), humanBytes(progress.Total), humanBytes(uint64(rate)), eta)
}

func printISOReport(report isocapture.FilesystemCaptureReport) {
	fmt.Printf("Status: %s\n", report.Status)
	fmt.Printf("Format: ISO9660/Joliet/UDF filesystem remaster\n")
	fmt.Printf("Source filesystem: %s at %s\n", report.SourceNode, report.SourceMount)
	fmt.Printf("Supported content: %d files, %d directories, %s\n", report.Files, report.Directories, humanBytes(report.SourceBytes))
	if report.SourceContentSHA256 != "" {
		fmt.Printf("Source content SHA-256: %s\n", report.SourceContentSHA256)
	}
	if report.OutputSHA256 != "" {
		fmt.Printf("Output SHA-256: %s\n", report.OutputSHA256)
		fmt.Printf("Output bytes: %s\n", humanBytes(report.OutputBytes))
		fmt.Printf("UDF validation: %t\n", report.UDFValidated)
		fmt.Printf("Content comparison: %s\n", report.ContentComparison)
		fmt.Printf("Image: %s\n", report.Destination)
	}
	if report.Failure != "" {
		fmt.Printf("Failure: %s: %s\n", report.FailureKind, report.Failure)
	}
}
