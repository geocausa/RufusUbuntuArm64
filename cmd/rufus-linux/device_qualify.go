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
	"time"

	"github.com/geocausa/RufusArm64/internal/device"
	"github.com/geocausa/RufusArm64/internal/devicequal"
	"github.com/geocausa/RufusArm64/internal/persistence"
	"github.com/geocausa/RufusArm64/internal/safety"
)

type deviceQualificationPlan struct {
	Device   device.BlockDevice `json:"device"`
	Identity string             `json:"identity"`
	Plan     devicequal.Plan    `json:"plan"`
}

func runDevice(args []string) error {
	if len(args) == 0 {
		return errors.New("device requires qualify")
	}
	switch args[0] {
	case "qualify":
		return runDeviceQualify(args[1:])
	default:
		return fmt.Errorf("unknown device command %q", args[0])
	}
}

func runDeviceQualify(args []string) error {
	flags := flag.NewFlagSet("device qualify", flag.ContinueOnError)
	devicePath := flags.String("device", "", "whole target disk")
	profileText := flags.String("profile", string(devicequal.ProfileQuick), "qualification profile: quick or full")
	regionSizeText := flags.String("region-size", "4M", "qualification region size in bytes or K/M/G units")
	expectedIdentity := flags.String("expected-identity", "", "expected device identity from the list command")
	yes := flags.Bool("yes", false, "skip interactive confirmation")
	allowFixed := flags.Bool("allow-fixed", false, "allow a non-removable disk")
	noUnmount := flags.Bool("no-unmount", false, "refuse instead of unmounting mounted removable filesystems")
	dryRun := flags.Bool("dry-run", false, "validate and display the plan without opening the device for writing")
	asJSON := flags.Bool("json", false, "output one deterministic JSON plan or report")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("device qualify does not accept positional arguments")
	}
	if strings.TrimSpace(*devicePath) == "" {
		return errors.New("--device is required")
	}
	if os.Getenv("PKEXEC_UID") != "" {
		return errors.New("graphical device qualification is not implemented; run the command explicitly from a terminal")
	}

	profile, err := parseDeviceQualificationProfile(*profileText)
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
	identity := strings.TrimSpace(*expectedIdentity)
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
	planned := deviceQualificationPlan{Device: selected, Identity: identity, Plan: plan}
	if *dryRun {
		if *asJSON {
			return json.NewEncoder(os.Stdout).Encode(planned)
		}
		printDeviceQualificationPlan(planned)
		fmt.Println("Dry run complete; the device was not opened for writing.")
		return nil
	}

	mounted := device.MountedDescendants(selected)
	if len(mounted) > 0 && *noUnmount {
		return errors.New("target has mounted filesystems")
	}
	if !*asJSON {
		printDeviceQualificationPlan(planned)
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
	if !*asJSON && lastProgress != (time.Time{}) {
		fmt.Println()
	}
	if *asJSON && report.Schema != 0 {
		if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
			return err
		}
	} else if !*asJSON && report.Schema != 0 {
		printDeviceQualificationReport(report)
	}
	return runErr
}

func parseDeviceQualificationProfile(value string) (devicequal.Profile, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(devicequal.ProfileQuick):
		return devicequal.ProfileQuick, nil
	case string(devicequal.ProfileFull):
		return devicequal.ProfileFull, nil
	default:
		return "", errors.New("--profile must be quick or full")
	}
}

func printDeviceQualificationPlan(planned deviceQualificationPlan) {
	fmt.Printf("Device: %s (%s)\n", planned.Device.Path, humanBytes(planned.Device.Size))
	fmt.Printf("Profile: %s; regions: %d; region size: %s\n", planned.Plan.Profile, len(planned.Plan.Regions), humanBytes(planned.Plan.RegionSize))
	fmt.Printf("Bytes tested per pass: %s; patterns: determined by profile\n", humanBytes(planned.Plan.PlannedBytes))
	fmt.Println("This qualification operation overwrites the tested regions and does not preserve existing data.")
}

func printDeviceQualificationReport(report devicequal.Report) {
	fmt.Printf("Status: %s\n", report.Status)
	fmt.Printf("Completed I/O: %s; passes: %d\n", humanBytes(report.CompletedBytes), len(report.Passes))
	if report.AliasingDetected {
		fmt.Println("Aliasing or false-capacity behavior was detected.")
	}
	if report.Failure != nil {
		fmt.Printf("Failure: %s at byte %d: %s\n", report.Failure.Kind, report.Failure.ByteOffset, report.Failure.Message)
	}
}
