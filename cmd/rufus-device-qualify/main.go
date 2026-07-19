package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/geocausa/RufusArm64/internal/device"
	"github.com/geocausa/RufusArm64/internal/devicequal"
	"github.com/geocausa/RufusArm64/internal/persistence"
	"github.com/geocausa/RufusArm64/internal/safety"
)

var version = "development"

type qualificationPlan struct {
	Device   device.BlockDevice `json:"device"`
	Identity string             `json:"identity"`
	Plan     devicequal.Plan    `json:"plan"`
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

	flags := flag.NewFlagSet("rufusarm64-device-qualify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	devicePath := flags.String("device", "", "whole target disk")
	profileText := flags.String("profile", string(devicequal.ProfileQuick), "qualification profile: quick or full")
	regionSizeText := flags.String("region-size", "4M", "qualification region size in bytes or K/M/G units")
	expectedIdentity := flags.String("expected-identity", "", "expected device identity from rufusarm64-cli list --json")
	yes := flags.Bool("yes", false, "skip interactive confirmation")
	allowFixed := flags.Bool("allow-fixed", false, "allow a non-removable disk")
	noUnmount := flags.Bool("no-unmount", false, "refuse instead of unmounting mounted removable filesystems")
	dryRun := flags.Bool("dry-run", false, "validate and display the plan without opening the device for writing")
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
			return errors.New("graphical qualification requires --yes, --json, and --expected-identity without --dry-run")
		}
		if *allowFixed || *noUnmount {
			return errors.New("graphical qualification is limited to normal removable targets with guarded unmounting")
		}
	}

	profile, err := parseProfile(*profileText)
	if err != nil {
		return err
	}
	regionSize, err := persistence.ParseSize(*regionSizeText)
	if err != nil {
		return fmt.Errorf("parse --region-size: %w", err)
	}
	if regionSize == 0 {
		return errors.New("--region-size must be greater than zero")
	}
	if err := safety.RequireRoot(); err != nil && !*dryRun {
		return err
	}
	if os.Geteuid() == 0 {
		setTrustedSystemPath()
	}

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
	if err := safety.ValidateTarget(resolved, selected, *allowFixed); err != nil {
		return err
	}
	plan, err := devicequal.BuildPlan(selected.Size, regionSize, profile)
	if err != nil {
		return err
	}
	planned := qualificationPlan{Device: selected, Identity: identity, Plan: plan}
	if *dryRun {
		if *asJSON {
			return json.NewEncoder(os.Stdout).Encode(planned)
		}
		printPlan(planned)
		fmt.Println("Dry run complete; the device was not opened for writing.")
		return nil
	}

	if len(device.MountedDescendants(selected)) > 0 && *noUnmount {
		return errors.New("target has mounted filesystems")
	}
	if !*asJSON {
		printPlan(planned)
	}
	if !*yes {
		if err := confirmDestructive(resolved); err != nil {
			return err
		}
	}

	selected, kernelDeviceID, err := safety.RevalidateTarget(resolved, identity, *allowFixed)
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
	lastProgress := time.Time{}
	report, runErr := devicequal.RunDevice(ctx, resolved, devicequal.DeviceOptions{
		ExpectedDeviceID: kernelDeviceID,
		ExpectedSize:     selected.Size,
		Profile:          profile,
		RegionSize:       regionSize,
		Progress: func(progress devicequal.Progress) {
			if *asJSON {
				return
			}
			if time.Since(lastProgress) < 200*time.Millisecond && progress.Done != progress.Total {
				return
			}
			lastProgress = time.Now()
			percent := 0.0
			if progress.Total > 0 {
				percent = float64(progress.Done) * 100 / float64(progress.Total)
			}
			fmt.Printf("\r%-7s pass %d  %6.2f%%  %s / %s", progress.Stage, progress.Pass, percent, humanBytes(progress.Done), humanBytes(progress.Total))
		},
		BeforeWrite: func(open *os.File) error {
			fresh, currentID, err := safety.RevalidateOpenBoundTarget(resolved, kernelDeviceID, *allowFixed)
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
		printReport(report)
	}
	return runErr
}

func usage() {
	fmt.Printf(`RufusArm64 device qualification utility %s

Usage:
  sudo rufusarm64-device-qualify --device /dev/DEVICE [--profile quick|full]
  rufusarm64-device-qualify --device /dev/DEVICE --dry-run [--json]

The operation is destructive. It overwrites every tested region, does not preserve
existing data, and is intentionally separate from the normal Create USB workflow.
Use rufusarm64-cli list --json to obtain the device path and identity token.
`, version)
}

func parseProfile(value string) (devicequal.Profile, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(devicequal.ProfileQuick):
		return devicequal.ProfileQuick, nil
	case string(devicequal.ProfileFull):
		return devicequal.ProfileFull, nil
	default:
		return "", errors.New("--profile must be quick or full")
	}
}

func printPlan(planned qualificationPlan) {
	fmt.Printf("Device: %s (%s)\n", planned.Device.Path, humanBytes(planned.Device.Size))
	fmt.Printf("Profile: %s; regions: %d; region size: %s\n", planned.Plan.Profile, len(planned.Plan.Regions), humanBytes(planned.Plan.RegionSize))
	fmt.Printf("Bytes tested per pass: %s\n", humanBytes(planned.Plan.PlannedBytes))
	fmt.Println("This qualification operation overwrites the tested regions and does not preserve existing data.")
}

func printReport(report devicequal.Report) {
	fmt.Printf("Status: %s\n", report.Status)
	fmt.Printf("Completed I/O: %s; passes: %d\n", humanBytes(report.CompletedBytes), len(report.Passes))
	if report.AliasingDetected {
		fmt.Println("Aliasing or false-capacity behavior was detected.")
	}
	if report.Failure != nil {
		fmt.Printf("Failure: %s at byte %d: %s\n", report.Failure.Kind, report.Failure.ByteOffset, report.Failure.Message)
	}
}

func confirmDestructive(path string) error {
	fmt.Fprintf(os.Stderr, "WARNING: all tested regions on %s will be overwritten.\n", path)
	fmt.Fprintf(os.Stderr, "Type ERASE %s to continue: ", path)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return err
	}
	if strings.TrimSpace(line) != "ERASE "+path {
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
