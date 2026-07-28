//go:build linux

// rufus-iso-helper is the narrow package-owned entry point for Linux ISO Image
// mode. The analyze command accepts no target path and is read-only. The create
// command accepts only the source and removable-target identities captured by
// the unprivileged GTK application before authentication.
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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/geocausa/RufusArm64/internal/device"
	"github.com/geocausa/RufusArm64/internal/linuxmedia"
	"github.com/geocausa/RufusArm64/internal/safety"
	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

var version = "development"

type jsonEvent struct {
	Event   string  `json:"event"`
	Stage   string  `json:"stage,omitempty"`
	Message string  `json:"message,omitempty"`
	Done    uint64  `json:"done,omitempty"`
	Total   uint64  `json:"total,omitempty"`
	Rate    float64 `json:"rate,omitempty"`
	Hash    string  `json:"sha256,omitempty"`
}

type emitter struct {
	json bool
	mu   sync.Mutex
}

func (e *emitter) event(value jsonEvent) {
	e.mu.Lock()
	defer e.mu.Unlock()
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
	if len(args) == 0 {
		return errors.New("expected analyze or create")
	}
	switch args[0] {
	case "analyze":
		return runAnalyze(args[1:])
	case "create":
		return runCreate(args[1:])
	case "version", "--version", "-v":
		fmt.Println(version)
		return nil
	default:
		return fmt.Errorf("unknown ISO Image mode command %q", args[0])
	}
}

func requirePackagedPrivilege() error {
	if os.Getenv("PKEXEC_UID") == "" {
		return errors.New("the graphical ISO Image mode helper must be launched through pkexec")
	}
	if err := safety.RequireRoot(); err != nil {
		return err
	}
	if err := os.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"); err != nil {
		return fmt.Errorf("set trusted system path: %w", err)
	}
	return nil
}

func resolvedPinnedImage(path, identityText string) (string, sourcefile.Identity, error) {
	identity, err := sourcefile.ParseIdentity(identityText)
	if err != nil {
		return "", identity, fmt.Errorf("parse --expected-source-identity: %w", err)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", identity, fmt.Errorf("make image path absolute: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", identity, fmt.Errorf("resolve image path: %w", err)
	}
	file, err := sourcefile.OpenRegular(resolved, identity)
	if err != nil {
		return "", identity, err
	}
	if err := file.Close(); err != nil {
		return "", identity, fmt.Errorf("close selected image after identity check: %w", err)
	}
	return resolved, identity, nil
}

func runAnalyze(args []string) error {
	flags := flag.NewFlagSet("rufus-iso-helper analyze", flag.ContinueOnError)
	imagePath := flags.String("image", "", "identity-bound plain Linux ISOHybrid image")
	expectedSourceText := flags.String("expected-source-identity", "", "source identity captured before authentication")
	targetSizeText := flags.String("target-size", "", "selected removable target capacity in bytes")
	cancelFile := flags.String("cancel-file", "", "per-user cancellation marker")
	asJSON := flags.Bool("json", false, "emit one JSON result")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("ISO Image mode analysis does not accept positional arguments")
	}
	if strings.TrimSpace(*imagePath) == "" || strings.TrimSpace(*expectedSourceText) == "" || strings.TrimSpace(*targetSizeText) == "" || strings.TrimSpace(*cancelFile) == "" {
		return errors.New("--image, --expected-source-identity, --target-size, and --cancel-file are required")
	}
	if !*asJSON {
		return errors.New("the graphical ISO Image mode analyzer requires --json")
	}
	if err := requirePackagedPrivilege(); err != nil {
		return err
	}
	targetSize, err := strconv.ParseUint(strings.TrimSpace(*targetSizeText), 10, 64)
	if err != nil || targetSize == 0 {
		return errors.New("--target-size must be a positive byte count")
	}
	resolvedImage, expectedSource, err := resolvedPinnedImage(*imagePath, *expectedSourceText)
	if err != nil {
		return err
	}

	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancelCleanup, err := safety.CancellationContext(signalCtx, *cancelFile)
	if err != nil {
		return err
	}
	defer cancelCleanup()

	result, err := linuxmedia.AnalyzeISOImage(ctx, resolvedImage, linuxmedia.ISOImageAnalysisOptions{
		ExpectedSource: expectedSource,
		TargetSize:     targetSize,
		Architecture:   runtime.GOARCH,
	}, nil)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func runCreate(args []string) error {
	flags := flag.NewFlagSet("rufus-iso-helper create", flag.ContinueOnError)
	imagePath := flags.String("image", "", "identity-bound plain Linux ISOHybrid image")
	expectedSourceText := flags.String("expected-source-identity", "", "source identity captured before authentication")
	devicePath := flags.String("device", "", "whole removable target disk")
	expectedTargetIdentity := flags.String("expected-identity", "", "target identity captured before authentication")
	volumeLabel := flags.String("volume-label", "RUFUS-LIVE", "FAT32 volume label")
	cancelFile := flags.String("cancel-file", "", "per-user cancellation marker")
	jsonProgress := flags.Bool("json-progress", false, "emit JSON lines")
	yes := flags.Bool("yes", false, "confirm the graphical application already obtained explicit erase consent")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("ISO Image mode creator does not accept positional arguments")
	}
	if strings.TrimSpace(*imagePath) == "" || strings.TrimSpace(*expectedSourceText) == "" || strings.TrimSpace(*devicePath) == "" || strings.TrimSpace(*expectedTargetIdentity) == "" {
		return errors.New("--image, --expected-source-identity, --device, and --expected-identity are required")
	}
	if !*jsonProgress || !*yes || strings.TrimSpace(*cancelFile) == "" {
		return errors.New("the graphical ISO Image mode creator requires --json-progress, --yes, and a trusted --cancel-file")
	}
	if err := requirePackagedPrivilege(); err != nil {
		return err
	}
	resolvedImage, expectedSource, err := resolvedPinnedImage(*imagePath, *expectedSourceText)
	if err != nil {
		return err
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
		fresh, currentID, err := safety.RevalidateTarget(resolvedTarget, *expectedTargetIdentity, false)
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

	out := &emitter{json: true}
	preflightMessage := fmt.Sprintf("Linux ISO Image mode: %s; target: %s", filepath.Base(resolvedImage), resolvedTarget)
	out.event(jsonEvent{Event: "preflight", Stage: "preflight", Message: preflightMessage})

	heartbeatCtx, stopHeartbeat := context.WithCancel(ctx)
	defer stopHeartbeat()
	var heartbeatMu sync.Mutex
	heartbeat := linuxmedia.PersistentEvent{Stage: "preflight", Message: preflightMessage}
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case <-ticker.C:
				heartbeatMu.Lock()
				current := heartbeat
				heartbeatMu.Unlock()
				if current.Stage != "" && current.Total == 0 {
					out.event(jsonEvent{Event: "stage", Stage: current.Stage, Message: current.Message})
				}
			}
		}
	}()

	result, err := linuxmedia.CreateISOImage(ctx, resolvedImage, resolvedTarget, linuxmedia.ISOImageCreateOptions{
		TargetSize:        target.Size,
		ExpectedDeviceID:  kernelDeviceID,
		ExpectedSource:    expectedSource,
		Architecture:      runtime.GOARCH,
		VolumeLabel:       *volumeLabel,
		BeforeDestructive: targetCheck,
	}, func(event linuxmedia.PersistentEvent) {
		heartbeatMu.Lock()
		heartbeat = event
		if event.Stage == "complete" {
			heartbeat = linuxmedia.PersistentEvent{}
		}
		heartbeatMu.Unlock()

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
	stopHeartbeat()
	if err != nil {
		return err
	}
	if err := safety.RereadPartitionTable(resolvedTarget); err != nil {
		out.event(jsonEvent{Event: "log", Stage: "warning", Message: fmt.Sprintf("Warning: %v", err)})
	}
	out.event(jsonEvent{Event: "log", Stage: "verification", Message: fmt.Sprintf("Verified %d files from the ISO tree; source SHA-256 %s; UEFI fallback %s.", result.Manifest.Files, result.SourceSHA256, result.UEFIBootPath), Hash: result.SourceSHA256})
	out.event(jsonEvent{Event: "complete", Stage: "complete", Message: "Linux ISO Image mode USB created and verified."})
	return nil
}
