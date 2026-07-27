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
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/geocausa/RufusArm64/internal/device"
	"github.com/geocausa/RufusArm64/internal/freedos"
	"github.com/geocausa/RufusArm64/internal/safety"
)

var version = "development"

var sysClassBlockRoot = "/sys/class/block"

const freeDOSProgressPrefix = "RUFUSARM64_PROGRESS "

type freeDOSProgressRecord struct {
	Schema         int                    `json:"schema"`
	Type           string                 `json:"type"`
	Phase          freedos.ExecutionPhase `json:"phase"`
	Done           uint64                 `json:"done"`
	Total          uint64                 `json:"total"`
	OverallDone    uint64                 `json:"overall_done"`
	OverallTotal   uint64                 `json:"overall_total"`
	ElapsedMS      uint64                 `json:"elapsed_ms"`
	BytesPerSecond uint64                 `json:"bytes_per_second"`
	ETASeconds     *uint64                `json:"eta_seconds"`
}

type freeDOSProgressEmitter struct {
	writer      io.Writer
	writeTotal  uint64
	verifyTotal uint64
	started     time.Time
	lastPhase   freedos.ExecutionPhase
	lastPercent int
}

func newFreeDOSProgressEmitter(writer io.Writer, writeTotal, verifyTotal uint64) *freeDOSProgressEmitter {
	return &freeDOSProgressEmitter{
		writer: writer, writeTotal: writeTotal, verifyTotal: verifyTotal,
		started: time.Now(), lastPercent: -1,
	}
}

func (emitter *freeDOSProgressEmitter) Emit(progress freedos.ExecutionProgress) error {
	if emitter == nil || emitter.writer == nil || emitter.writeTotal == 0 || emitter.verifyTotal == 0 {
		return errors.New("FreeDOS progress emitter is not configured")
	}
	if emitter.writeTotal > ^uint64(0)-emitter.verifyTotal {
		return errors.New("FreeDOS progress byte accounting overflow")
	}
	overallTotal := emitter.writeTotal + emitter.verifyTotal
	var overallDone uint64
	switch progress.Phase {
	case freedos.ExecutionPhasePrepare:
		overallDone = 0
	case freedos.ExecutionPhaseWrite:
		if progress.Total != emitter.writeTotal {
			return errors.New("FreeDOS write progress total differs from the reviewed extent total")
		}
		overallDone = progress.Processed
	case freedos.ExecutionPhaseFlush:
		overallDone = emitter.writeTotal
	case freedos.ExecutionPhaseReadback:
		if progress.Total != emitter.verifyTotal {
			return errors.New("FreeDOS verification progress total differs from the reviewed extent total")
		}
		overallDone = emitter.writeTotal + progress.Processed
	case freedos.ExecutionPhaseFinish, freedos.ExecutionPhaseComplete:
		overallDone = overallTotal
	default:
		return fmt.Errorf("unsupported FreeDOS progress phase %q", progress.Phase)
	}
	if overallDone > overallTotal || (progress.Total != 0 && progress.Processed > progress.Total) {
		return errors.New("FreeDOS progress exceeds its reviewed byte totals")
	}
	percent := int(overallDone * 100 / overallTotal)
	if progress.Phase == emitter.lastPhase && percent == emitter.lastPercent {
		return nil
	}
	emitter.lastPhase = progress.Phase
	emitter.lastPercent = percent
	elapsed := time.Since(emitter.started)
	if elapsed < 0 {
		elapsed = 0
	}
	rate := uint64(0)
	if overallDone > 0 && elapsed > 0 {
		rate = uint64(float64(overallDone) / elapsed.Seconds())
	}
	var eta *uint64
	if rate > 0 && overallDone < overallTotal {
		remaining := (overallTotal - overallDone) / rate
		eta = &remaining
	}
	record := freeDOSProgressRecord{
		Schema:         1,
		Type:           "progress",
		Phase:          progress.Phase,
		Done:           progress.Processed,
		Total:          progress.Total,
		OverallDone:    overallDone,
		OverallTotal:   overallTotal,
		ElapsedMS:      uint64(elapsed / time.Millisecond),
		BytesPerSecond: rate,
		ETASeconds:     eta,
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(emitter.writer, "%s%s\n", freeDOSProgressPrefix, data)
	return err
}

type arguments struct {
	devicePath       string
	expectedIdentity string
	label            string
	cancelFile       string
	yes              bool
	noUnmount        bool
	dryRun           bool
	asJSON           bool
}

type plannedFormat struct {
	Device       device.BlockDevice `json:"device"`
	Identity     string             `json:"identity"`
	Plan         freedos.DevicePlan `json:"plan"`
	Confirmation string             `json:"confirmation"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(argv []string) error {
	if len(argv) > 0 {
		switch argv[0] {
		case "version", "--version", "-v":
			fmt.Println(version)
			return nil
		case "help", "--help", "-h":
			usage()
			return nil
		}
	}
	flags := flag.NewFlagSet("rufusarm64-freedos-format", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var opts arguments
	flags.StringVar(&opts.devicePath, "device", "", "whole removable target disk")
	flags.StringVar(&opts.expectedIdentity, "expected-identity", "", "expected device identity from rufusarm64-cli list --json")
	flags.StringVar(&opts.label, "label", "FREEDOS", "uppercase FAT volume label")
	flags.StringVar(&opts.cancelFile, "cancel-file", "", "owner-only GUI cancellation marker beneath /run/user/UID")
	flags.BoolVar(&opts.yes, "yes", false, "skip interactive confirmation")
	flags.BoolVar(&opts.noUnmount, "no-unmount", false, "refuse instead of unmounting mounted removable filesystems")
	flags.BoolVar(&opts.dryRun, "dry-run", false, "validate and display the exact plan without changing the device")
	flags.BoolVar(&opts.asJSON, "json", false, "output one deterministic JSON plan or report")
	if err := flags.Parse(argv); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	throughPkexec := strings.TrimSpace(os.Getenv("PKEXEC_UID")) != ""
	if err := validateArguments(opts, throughPkexec); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		setTrustedSystemPath()
	}

	resolved, err := safety.ResolveDevice(opts.devicePath)
	if err != nil {
		return err
	}
	selected, err := device.Find(resolved)
	if err != nil {
		return err
	}
	identity := strings.TrimSpace(opts.expectedIdentity)
	if identity == "" {
		identity = selected.Identity
	}
	if err := safety.ValidateExpectedIdentity(selected, identity); err != nil {
		return err
	}
	if err := safety.ValidateTarget(resolved, selected, false); err != nil {
		return err
	}
	sectorSize, err := logicalSectorSize(resolved)
	if err != nil {
		return err
	}
	plan, err := freedos.BuildDevicePlan(freedos.DeviceRequest{
		DevicePath:        resolved,
		ExpectedIdentity:  identity,
		DeviceSizeBytes:   selected.Size,
		LogicalSectorSize: sectorSize,
		Label:             opts.label,
	})
	if err != nil {
		return err
	}
	confirmation, err := freedos.DeviceConfirmationPhrase(plan)
	if err != nil {
		return err
	}
	if err := requireTools([]string{"blockdev", "sync"}); err != nil {
		return err
	}
	planned := plannedFormat{Device: selected, Identity: identity, Plan: plan, Confirmation: confirmation}
	if opts.dryRun {
		if opts.asJSON {
			return json.NewEncoder(os.Stdout).Encode(planned)
		}
		printPlan(planned)
		fmt.Println("Dry run complete; the device was not opened for writing.")
		return nil
	}
	if err := safety.RequireRoot(); err != nil {
		return err
	}
	if len(device.MountedDescendants(selected)) > 0 && opts.noUnmount {
		return errors.New("target has mounted filesystems")
	}
	if !opts.asJSON {
		printPlan(planned)
	}
	if !opts.yes {
		if err := confirmDestructive(confirmation); err != nil {
			return err
		}
	}

	selected, kernelDeviceID, err := safety.RevalidateTarget(resolved, identity, false)
	if err != nil {
		return err
	}
	if !opts.noUnmount {
		if err := safety.UnmountDescendants(selected); err != nil {
			return err
		}
	}
	if err := safety.EnsureNoMountedDescendants(resolved); err != nil {
		return err
	}

	signalCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	ctx, cleanupCancellation, err := safety.CancellationContext(signalCtx, opts.cancelFile)
	if err != nil {
		return err
	}
	defer cleanupCancellation()

	execution := freedos.ExecutionOptions{}
	if opts.asJSON {
		execution.PhaseProgress = newFreeDOSProgressEmitter(os.Stderr, plan.MutationBytes, plan.VerificationBytes).Emit
	}
	report, runErr := freedos.ExecuteLinuxDevice(ctx, plan, freedos.LinuxDeviceOptions{
		ExpectedDeviceID: kernelDeviceID,
		ExpectedSize:     selected.Size,
		Revalidate: func(open *os.File) error {
			fresh, currentID, err := safety.RevalidateOpenBoundTarget(resolved, kernelDeviceID, false)
			if err != nil {
				return err
			}
			if currentID != kernelDeviceID {
				return errors.New("the selected kernel device changed after confirmation")
			}
			if !opts.noUnmount {
				if err := safety.UnmountDescendants(fresh); err != nil {
					return err
				}
			}
			if err := safety.EnsureNoMountedDescendants(resolved); err != nil {
				return err
			}
			return safety.VerifyOpenDevice(open, kernelDeviceID, selected.Size)
		},
	}, execution)
	if opts.asJSON && report.Schema != 0 {
		if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
			return errors.Join(runErr, err)
		}
	} else if !opts.asJSON && report.Schema != 0 {
		printReport(report)
	}
	return runErr
}

func validateArguments(opts arguments, throughPkexec bool) error {
	if strings.TrimSpace(opts.devicePath) == "" {
		return errors.New("--device is required")
	}
	identity := strings.TrimSpace(opts.expectedIdentity)
	if opts.yes && identity == "" {
		return errors.New("--yes requires --expected-identity")
	}
	if opts.cancelFile != "" && opts.dryRun {
		return errors.New("--cancel-file is not accepted with --dry-run")
	}
	if opts.asJSON && !opts.dryRun && (!opts.yes || identity == "") {
		return errors.New("non-dry-run --json requires --yes and --expected-identity")
	}
	if throughPkexec {
		if opts.dryRun || !opts.yes || !opts.asJSON || identity == "" || opts.cancelFile == "" {
			return errors.New("graphical FreeDOS formatting requires --yes, --json, --expected-identity, and --cancel-file without --dry-run")
		}
		if opts.noUnmount {
			return errors.New("graphical FreeDOS formatting requires guarded unmounting")
		}
	}
	return nil
}

func logicalSectorSize(path string) (uint64, error) {
	name := filepath.Base(filepath.Clean(path))
	if name == "" || name == "." || name == string(filepath.Separator) {
		return 0, fmt.Errorf("read logical sector size: invalid device path %q", path)
	}
	sectorPath := filepath.Join(sysClassBlockRoot, name, "queue", "logical_block_size")
	data, err := os.ReadFile(sectorPath)
	if err != nil {
		return 0, fmt.Errorf("read logical sector size for %s from %s: %w", path, sectorPath, err)
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse logical sector size for %s from %s: %w", path, sectorPath, err)
	}
	if value != 512 {
		return 0, fmt.Errorf("FreeDOS media requires 512-byte logical sectors, not %d for %s", value, path)
	}
	return value, nil
}

func requireTools(names []string) error {
	seen := make(map[string]struct{})
	for _, name := range names {
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		if _, err := exec.LookPath(name); err != nil {
			return fmt.Errorf("required program %q is not installed", name)
		}
	}
	return nil
}

func confirmDestructive(phrase string) error {
	fmt.Fprintln(os.Stderr, "WARNING: this operation erases the complete selected drive and creates x86 BIOS/Legacy FreeDOS media.")
	fmt.Fprintln(os.Stderr, "The result will not boot ARM64 or UEFI-only computers, and software checks cannot prove a physical PC will boot it.")
	fmt.Fprintf(os.Stderr, "Type exactly: %s\n> ", phrase)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return err
	}
	if strings.TrimSpace(line) != phrase {
		return errors.New("confirmation did not match; nothing was changed")
	}
	return nil
}

func printPlan(planned plannedFormat) {
	fmt.Printf("Device: %s (%d bytes)\n", planned.Device.Path, planned.Device.Size)
	fmt.Printf("Identity: %s\n", planned.Identity)
	fmt.Printf("Media: %s, one active FAT32 partition, label %q\n", planned.Plan.Distribution, planned.Plan.Label)
	fmt.Printf("Partition: start %d bytes, size %d bytes\n", planned.Plan.PartitionStartBytes, planned.Plan.PartitionSizeBytes)
	fmt.Printf("Creation I/O: write %d required bytes, verify %d required bytes; %d free-data bytes remain untouched\n",
		planned.Plan.MutationBytes, planned.Plan.VerificationBytes, planned.Plan.UntouchedBytes)
	fmt.Printf("Target platform: %s; firmware: %s\n", planned.Plan.TargetCPU, planned.Plan.Firmware)
	for _, warning := range planned.Plan.Warnings {
		fmt.Printf("WARNING: %s\n", warning)
	}
	fmt.Printf("Confirmation: %s\n", planned.Confirmation)
}

func printReport(report freedos.ExecutionReport) {
	fmt.Printf("Status: %s; phase: %s\n", report.Status, report.Phase)
	fmt.Printf("Media changed: %t; verified: %t; reusable: %t\n", report.MediaChanged, report.Verified, report.Reusable)
	fmt.Printf("Bytes written: %d; bytes verified: %d; scope: %s\n", report.BytesWritten, report.BytesVerified, report.VerificationScope)
	if report.SHA256 != "" {
		fmt.Printf("Required-extents SHA-256: %s\n", report.SHA256)
	}
	if report.FailureReason != "" {
		fmt.Printf("Failure: %s\n", report.FailureReason)
	}
}

func setTrustedSystemPath() {
	_ = os.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
}

func usage() {
	fmt.Printf(`RufusArm64 FreeDOS formatter %s

Usage:
  rufusarm64-freedos-format --device /dev/DEVICE --dry-run [--json]
  sudo rufusarm64-freedos-format --device /dev/DEVICE [--label FREEDOS]

This dedicated command erases one removable whole drive and constructs verified
FreeDOS 1.4 media for x86 BIOS or UEFI Legacy/CSM systems. It writes and verifies
only the required boot and FAT32 filesystem extents; exhaustive device testing
remains a separate qualification workflow. It does not support fixed disks,
ARM64 boot, UEFI-only boot, or a claim that physical hardware will boot. Use
rufusarm64-cli list --json to obtain the exact path and identity token.
`, version)
}
