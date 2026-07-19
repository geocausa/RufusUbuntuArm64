package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/geocausa/RufusArm64/internal/device"
	"github.com/geocausa/RufusArm64/internal/drivebackup"
	"github.com/geocausa/RufusArm64/internal/safety"
)

var version = "development"

type backupPlan struct {
	Device      device.BlockDevice          `json:"device"`
	Identity    string                      `json:"identity"`
	Destination drivebackup.DestinationInfo `json:"destination"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "version", "--version", "-v":
			fmt.Println(version)
			return nil
		case "help", "--help", "-h":
			usage()
			return nil
		}
	}

	flags := flag.NewFlagSet("rufusarm64-device-backup", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	devicePath := flags.String("device", "", "whole source disk")
	outputPath := flags.String("output", "", "absolute path for the new image file")
	expectedIdentity := flags.String("expected-identity", "", "expected device identity from rufusarm64-cli list --json")
	yes := flags.Bool("yes", false, "skip interactive confirmation")
	allowFixed := flags.Bool("allow-fixed", false, "allow a non-removable source disk")
	noUnmount := flags.Bool("no-unmount", false, "refuse instead of unmounting mounted removable filesystems")
	dryRun := flags.Bool("dry-run", false, "validate and display the plan without opening the source device")
	asJSON := flags.Bool("json", false, "output one deterministic JSON plan or report")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if strings.TrimSpace(*devicePath) == "" {
		return errors.New("--device is required")
	}
	if strings.TrimSpace(*outputPath) == "" {
		return errors.New("--output is required")
	}
	identityArgument := strings.TrimSpace(*expectedIdentity)
	if *yes && identityArgument == "" {
		return errors.New("--yes requires --expected-identity")
	}
	if *allowFixed && identityArgument == "" {
		return errors.New("--allow-fixed requires --expected-identity")
	}
	if *asJSON && !*dryRun && !*yes {
		return errors.New("non-dry-run --json requires --yes and --expected-identity")
	}
	if strings.TrimSpace(os.Getenv("PKEXEC_UID")) != "" {
		if *dryRun || !*yes || !*asJSON || identityArgument == "" {
			return errors.New("graphical backup requires --yes, --json, and --expected-identity without --dry-run")
		}
		if *allowFixed || *noUnmount {
			return errors.New("graphical backup is limited to normal removable sources with guarded unmounting")
		}
	}

	// All device and filesystem discovery commands must resolve through package-
	// controlled system locations. This applies before the first probe because a
	// terminal caller may already be root and pkexec starts the process elevated.
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
	destination, err := drivebackup.InspectDestination(*outputPath, resolved, selected.Size)
	if err != nil {
		return err
	}
	planned := backupPlan{Device: selected, Identity: identity, Destination: destination}
	if *dryRun {
		if *asJSON {
			return json.NewEncoder(os.Stdout).Encode(planned)
		}
		printPlan(planned)
		fmt.Println("Dry run complete; the source device was not opened.")
		return nil
	}

	if err := safety.RequireRoot(); err != nil {
		return err
	}
	if len(device.MountedDescendants(selected)) > 0 && *noUnmount {
		return errors.New("source has mounted filesystems")
	}
	if !*asJSON {
		printPlan(planned)
	}
	if !*yes {
		if err := confirmCapture(resolved, destination.Path); err != nil {
			return err
		}
	}

	selected, kernelDeviceID, err := revalidateSource(resolved, identity, *allowFixed)
	if err != nil {
		return err
	}
	if !*noUnmount {
		if err := safety.UnmountDescendants(selected); err != nil {
			return err
		}
	}
	if err := safety.EnsureNoMountedDescendants(resolved); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	started := time.Now()
	lastProgress := time.Time{}
	report, runErr := drivebackup.CaptureDevice(ctx, resolved, destination.Path, drivebackup.DeviceOptions{
		ExpectedDeviceID: kernelDeviceID,
		ExpectedSize:     selected.Size,
		Progress: func(progress drivebackup.Progress) {
			if *asJSON {
				return
			}
			if time.Since(lastProgress) < 200*time.Millisecond && progress.Done != progress.Total {
				return
			}
			lastProgress = time.Now()
			printProgress(progress, time.Since(started))
		},
		BeforeRead: func(open *os.File) error {
			fresh, currentID, err := revalidateSource(resolved, identity, *allowFixed)
			if err != nil {
				return err
			}
			if currentID != kernelDeviceID {
				return errors.New("the selected kernel device changed after confirmation")
			}
			if !*noUnmount {
				if err := safety.UnmountDescendants(fresh); err != nil {
					return err
				}
			}
			if err := safety.EnsureNoMountedDescendants(resolved); err != nil {
				return err
			}
			return safety.VerifyOpenDevice(open, kernelDeviceID, selected.Size)
		},
	})
	if !*asJSON && !lastProgress.IsZero() {
		fmt.Println()
	}
	if *asJSON && report.Schema != 0 {
		if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
			return err
		}
	} else if !*asJSON && report.Schema != 0 {
		printReport(report, destination.Path)
	}
	return runErr
}

func validateSource(path string, selected device.BlockDevice, allowFixed bool) error {
	if err := validateSourceMetadata(path, selected, allowFixed); err != nil {
		return err
	}
	if _, err := safety.KernelDeviceID(path); err != nil {
		return err
	}
	rootDisks, err := safety.BackingDisksForPath("/")
	if err != nil {
		return fmt.Errorf("cannot safely identify the running root disk: %w", err)
	}
	for _, disk := range rootDisks {
		if disk == filepath.Base(path) {
			return fmt.Errorf("refusing to capture the disk that backs the running root filesystem: %s", path)
		}
	}
	return nil
}

func validateSourceMetadata(path string, selected device.BlockDevice, allowFixed bool) error {
	if selected.Path != path {
		return fmt.Errorf("device metadata path mismatch: selected=%s reported=%s", path, selected.Path)
	}
	if selected.Type != "disk" {
		return fmt.Errorf("refusing partition or non-disk source %s (lsblk type %q); select the whole disk", path, selected.Type)
	}
	if selected.Size == 0 || selected.Size > math.MaxInt64 {
		return fmt.Errorf("source %s reported an unsupported size", path)
	}
	if err := safety.ValidateNoProtectedMounts(selected); err != nil {
		return err
	}
	if !allowFixed && !device.IsNormalRemovableTarget(selected) {
		return fmt.Errorf("source %s is not marked removable or USB; fixed and internal disks require --allow-fixed", path)
	}
	return nil
}

func revalidateSource(path, identity string, allowFixed bool) (device.BlockDevice, uint64, error) {
	selected, err := device.Find(path)
	if err != nil {
		return device.BlockDevice{}, 0, err
	}
	if err := safety.ValidateExpectedIdentity(selected, identity); err != nil {
		return device.BlockDevice{}, 0, err
	}
	if err := validateSource(path, selected, allowFixed); err != nil {
		return device.BlockDevice{}, 0, err
	}
	kernelID, err := safety.KernelDeviceID(path)
	if err != nil {
		return device.BlockDevice{}, 0, err
	}
	return selected, kernelID, nil
}

func usage() {
	fmt.Printf(`RufusArm64 drive-image backup utility %s

Usage:
  sudo rufusarm64-device-backup --device /dev/DEVICE --output /path/drive.img
  rufusarm64-device-backup --device /dev/DEVICE --output /path/drive.img --dry-run [--json]

The source is opened read-only. Mounted removable filesystems are unmounted to
capture a coherent image. The destination must not exist and must be stored on a
different disk. Use rufusarm64-cli list --json to obtain the path and identity.
`, version)
}

func printPlan(planned backupPlan) {
	name := strings.TrimSpace(strings.Join([]string{planned.Device.Vendor, planned.Device.Model}, " "))
	if name == "" {
		name = planned.Device.Path
	}
	fmt.Printf("Source: %s (%s, %s)\n", name, planned.Device.Path, humanBytes(planned.Device.Size))
	fmt.Printf("Destination: %s\n", planned.Destination.Path)
	fmt.Printf("Available: %s; required: %s\n", humanBytes(planned.Destination.AvailableBytes), humanBytes(planned.Destination.RequiredBytes))
	fmt.Println("The source is read-only, but mounted filesystems must be unmounted for a coherent image.")
}

func printProgress(progress drivebackup.Progress, elapsed time.Duration) {
	percent := 0.0
	if progress.Total > 0 {
		percent = float64(progress.Done) * 100 / float64(progress.Total)
	}
	rate := float64(0)
	if elapsed > 0 {
		rate = float64(progress.Done) / elapsed.Seconds()
	}
	eta := "--"
	if rate > 0 && progress.Done < progress.Total {
		seconds := float64(progress.Total-progress.Done) / rate
		eta = time.Duration(seconds * float64(time.Second)).Round(time.Second).String()
	}
	fmt.Printf("\r%6.2f%%  %s / %s  %s/s  ETA %s", percent, humanBytes(progress.Done), humanBytes(progress.Total), humanBytes(uint64(rate)), eta)
}

func printReport(report drivebackup.Report, output string) {
	fmt.Printf("Status: %s\n", report.Status)
	fmt.Printf("Captured: %s\n", humanBytes(report.CompletedBytes))
	if report.SHA256 != "" {
		fmt.Printf("SHA-256: %s\n", report.SHA256)
		fmt.Printf("Image: %s\n", output)
	}
	if report.Failure != nil {
		fmt.Printf("Failure: %s: %s\n", report.Failure.Kind, report.Failure.Message)
	}
}

func confirmCapture(source, output string) error {
	fmt.Fprintf(os.Stderr, "The source %s will be read and its mounted filesystems may be unmounted.\n", source)
	fmt.Fprintf(os.Stderr, "Type SAVE %s TO %s to continue: ", source, output)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return err
	}
	if strings.TrimSpace(line) != "SAVE "+source+" TO "+output {
		return errors.New("confirmation failed")
	}
	return nil
}

func setTrustedSystemPath() {
	_ = os.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
}

func humanBytes(value uint64) string {
	const unit = 1024
	if value < unit {
		return fmt.Sprintf("%d B", value)
	}
	exponent := 0
	divisor := uint64(unit)
	for quotient := value / unit; quotient >= unit && exponent < 5; quotient /= unit {
		divisor *= unit
		exponent++
	}
	return fmt.Sprintf("%.1f %ciB", float64(value)/float64(divisor), "KMGTPE"[exponent])
}
