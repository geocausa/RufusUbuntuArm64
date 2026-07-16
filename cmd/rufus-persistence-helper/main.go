//go:build linux

// rufus-persistence-helper is the narrow privileged entry point used by the
// graphical persistent-live-media wizard. It accepts only the identity-bound
// source and target selected before authentication and delegates the actual
// destructive work to the existing hardened linuxmedia.CreatePersistent engine.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/geocausa/RufusArm64/internal/device"
	"github.com/geocausa/RufusArm64/internal/linuxmedia"
	"github.com/geocausa/RufusArm64/internal/persistence"
	"github.com/geocausa/RufusArm64/internal/qualification"
	"github.com/geocausa/RufusArm64/internal/safety"
	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

var version = "0.9.0"

type jsonEvent struct {
	Event   string  `json:"event"`
	Stage   string  `json:"stage,omitempty"`
	Message string  `json:"message,omitempty"`
	Done    uint64  `json:"done,omitempty"`
	Total   uint64  `json:"total,omitempty"`
	Rate    float64 `json:"rate,omitempty"`
	Hash    string  `json:"sha256,omitempty"`
}

type emitter struct{ json bool }

func (e emitter) event(value jsonEvent) {
	if e.json {
		data, _ := json.Marshal(value)
		fmt.Println(string(data))
		return
	}
	if value.Message != "" {
		fmt.Println(value.Message)
	}
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("rufus-persistence-helper", flag.ContinueOnError)
	imagePath := flags.String("image", "", "identity-bound plain Linux ISOHybrid image")
	expectedSourceText := flags.String("expected-source-identity", "", "source identity captured before authentication")
	devicePath := flags.String("device", "", "whole removable target disk")
	expectedTargetIdentity := flags.String("expected-identity", "", "target identity captured before authentication")
	persistenceSizeText := flags.String("persistence-size", "0", "persistent ext4 size; zero uses remaining capacity")
	volumeLabel := flags.String("volume-label", "RUFUS-LIVE", "FAT32 boot volume label")
	cancelFile := flags.String("cancel-file", "", "per-user cancellation marker")
	jsonProgress := flags.Bool("json-progress", false, "emit JSON lines")
	yes := flags.Bool("yes", false, "confirm the graphical application already obtained explicit erase consent")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("persistence helper does not accept positional arguments")
	}
	if strings.TrimSpace(*imagePath) == "" || strings.TrimSpace(*expectedSourceText) == "" || strings.TrimSpace(*devicePath) == "" || strings.TrimSpace(*expectedTargetIdentity) == "" {
		return errors.New("--image, --expected-source-identity, --device, and --expected-identity are required")
	}
	if !*jsonProgress || !*yes || strings.TrimSpace(*cancelFile) == "" {
		return errors.New("the graphical persistence helper requires --json-progress, --yes, and a trusted --cancel-file")
	}
	if os.Getenv("PKEXEC_UID") == "" {
		return errors.New("the graphical persistence helper must be launched through pkexec")
	}
	if err := safety.RequireRoot(); err != nil {
		return err
	}
	if err := os.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"); err != nil {
		return fmt.Errorf("set trusted system path: %w", err)
	}

	expectedSource, err := sourcefile.ParseIdentity(*expectedSourceText)
	if err != nil {
		return fmt.Errorf("parse --expected-source-identity: %w", err)
	}
	persistenceSize, err := persistence.ParseSize(*persistenceSizeText)
	if err != nil {
		return fmt.Errorf("parse --persistence-size: %w", err)
	}
	absoluteImage, err := filepath.Abs(*imagePath)
	if err != nil {
		return fmt.Errorf("make image path absolute: %w", err)
	}
	resolvedImage, err := filepath.EvalSymlinks(absoluteImage)
	if err != nil {
		return fmt.Errorf("resolve image path: %w", err)
	}
	selectedSource, err := sourcefile.OpenRegular(resolvedImage, expectedSource)
	if err != nil {
		return err
	}
	defer selectedSource.Close()

	resolvedTarget, err := safety.ResolveDevice(*devicePath)
	if err != nil {
		return err
	}
	target, err := device.Find(resolvedTarget)
	if err != nil {
		return err
	}
	if err := safety.ValidateExpectedIdentity(target, *expectedTargetIdentity); err != nil {
		return err
	}
	if err := safety.ValidateTarget(resolvedTarget, target, false); err != nil {
		return err
	}
	if err := safety.EnsureOpenFileNotOnTarget(selectedSource, target); err != nil {
		return err
	}

	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancelCleanup, err := safety.CancellationContext(signalCtx, *cancelFile)
	if err != nil {
		return err
	}
	defer cancelCleanup()

	// Refresh the target immediately before the destructive path and unmount only
	// conventional removable-media mounts. This catches unplug/replug and /dev
	// name reuse after the user confirmed the exact device.
	target, kernelDeviceID, err := safety.RevalidateTarget(resolvedTarget, *expectedTargetIdentity, false)
	if err != nil {
		return err
	}
	if err := safety.EnsureOpenFileNotOnTarget(selectedSource, target); err != nil {
		return err
	}
	if err := safety.UnmountDescendants(target); err != nil {
		return err
	}
	if err := safety.EnsureNoMountedDescendants(resolvedTarget); err != nil {
		return err
	}

	targetCheck := func(source *os.File) error {
		fresh, currentID, err := safety.RevalidateTarget(resolvedTarget, "", false)
		if err != nil {
			return err
		}
		if currentID != kernelDeviceID {
			return errors.New("the selected kernel device changed after confirmation")
		}
		if err := safety.EnsureOpenFileNotOnTarget(source, fresh); err != nil {
			return err
		}
		if err := safety.UnmountDescendants(fresh); err != nil {
			return err
		}
		return safety.EnsureNoMountedDescendants(resolvedTarget)
	}

	out := emitter{json: *jsonProgress}
	out.event(jsonEvent{Event: "preflight", Stage: "preflight", Message: fmt.Sprintf("Persistent live media: %s; target: %s", filepath.Base(resolvedImage), resolvedTarget)})
	result, err := linuxmedia.CreatePersistent(ctx, resolvedImage, resolvedTarget, linuxmedia.PersistentCreateOptions{
		TargetSize:        target.Size,
		ExpectedDeviceID:  kernelDeviceID,
		ExpectedSource:    expectedSource,
		Architecture:      runtime.GOARCH,
		PersistenceSize:   persistenceSize,
		VolumeLabel:       *volumeLabel,
		CreatorVersion:    "RufusArm64 " + version,
		BeforeDestructive: targetCheck,
	}, func(event linuxmedia.PersistentEvent) {
		eventName := "stage"
		if event.Done > 0 || event.Total > 0 {
			eventName = "progress"
		}
		if event.Stage == "log" {
			eventName = "log"
		}
		if event.Stage == "complete" {
			eventName = "complete"
		}
		message := event.Message
		if event.Path != "" {
			message = strings.TrimSpace(message + " " + event.Path)
		}
		out.event(jsonEvent{Event: eventName, Stage: event.Stage, Message: message, Done: event.Done, Total: event.Total})
	})
	if err != nil {
		return err
	}
	if err := safety.RereadPartitionTable(resolvedTarget); err != nil {
		out.event(jsonEvent{Event: "log", Stage: "warning", Message: fmt.Sprintf("Warning: %v", err)})
	}
	out.event(jsonEvent{
		Event:   "log",
		Stage:   "qualification",
		Message: fmt.Sprintf("Qualification record stored at .rufusarm64/%s", qualification.RecordFileName),
		Hash:    result.QualificationRecordSHA256,
	})
	out.event(jsonEvent{Event: "complete", Stage: "complete", Message: "Persistent live USB created and verified. Boot it, then complete the start/reboot/verify qualification procedure."})
	return nil
}
