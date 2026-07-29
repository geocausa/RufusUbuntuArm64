//go:build linux

// rufus-persistence-helper is the narrow package-owned privileged entry point
// used by the graphical Linux-media workflows. It accepts only the
// identity-bound source and target selected before authentication and delegates
// destructive work to the hardened linuxmedia engines.
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
	"github.com/geocausa/RufusArm64/internal/persistence"
	"github.com/geocausa/RufusArm64/internal/qualification"
	"github.com/geocausa/RufusArm64/internal/safety"
	"github.com/geocausa/RufusArm64/internal/sourcefile"
)

var version = "development"

const (
	packagedRuntimeUEFILoaderPath       = "/usr/lib/rufusarm64/bootaa64-uefi-md5sum.efi"
	packagedRuntimeUEFILoaderSHA256     = "543615a8e97fed1cb5293bee7bdfe10f9feb6979f191b20ab32dafdcf097b502"
	packagedRuntimeUEFILoaderCommit     = "6195f2ef754c2ad390bda6590628708f410d55f6"
	packagedRuntimeUEFILoaderProvenance = "reproducible upstream uefi-md5sum v1.2 ARM64 build; unsigned"
)

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
	flags := flag.NewFlagSet("rufus-persistence-helper", flag.ContinueOnError)
	operation := flags.String("operation", "persistence", "Linux media operation: persistence or iso")
	imagePath := flags.String("image", "", "identity-bound plain Linux ISOHybrid image")
	expectedSourceText := flags.String("expected-source-identity", "", "source identity captured before authentication")
	devicePath := flags.String("device", "", "whole removable target disk")
	expectedTargetIdentity := flags.String("expected-identity", "", "target identity captured before authentication")
	persistenceSizeText := flags.String("persistence-size", "0", "persistent ext4 size; zero uses remaining capacity")
	volumeLabel := flags.String("volume-label", "RUFUS-LIVE", "ISO Image mode data-filesystem volume label")
	partitionScheme := flags.String("partition-scheme", "", "ISO Image mode partition scheme: mbr or gpt")
	filesystem := flags.String("filesystem", "", "ISO Image mode filesystem: auto, fat32, or ntfs")
	clusterSizeText := flags.String("cluster-size", "0", "ISO Image mode filesystem cluster size in bytes")
	cancelFile := flags.String("cancel-file", "", "per-user cancellation marker")
	jsonProgress := flags.Bool("json-progress", false, "emit JSON lines")
	yes := flags.Bool("yes", false, "confirm the graphical application already obtained explicit erase consent")
	runtimeUEFIValidation := flags.Bool("runtime-uefi-validation", false, "install the package-owned unsigned ARM64 boot-time media validator")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("linux media helper does not accept positional arguments")
	}
	selectedOperation := strings.ToLower(strings.TrimSpace(*operation))
	if selectedOperation != "persistence" && selectedOperation != "iso" {
		return errors.New("--operation must be persistence or iso")
	}
	if strings.TrimSpace(*imagePath) == "" || strings.TrimSpace(*expectedSourceText) == "" || strings.TrimSpace(*devicePath) == "" || strings.TrimSpace(*expectedTargetIdentity) == "" {
		return errors.New("--image, --expected-source-identity, --device, and --expected-identity are required")
	}
	if !*jsonProgress || !*yes || strings.TrimSpace(*cancelFile) == "" {
		return errors.New("the graphical Linux media helper requires --json-progress, --yes, and a trusted --cancel-file")
	}
	if os.Getenv("PKEXEC_UID") == "" {
		return errors.New("the graphical Linux media helper must be launched through pkexec")
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
	selectedPartitionScheme := strings.ToLower(strings.TrimSpace(*partitionScheme))
	selectedFilesystem := strings.ToLower(strings.TrimSpace(*filesystem))
	clusterSize, err := strconv.ParseUint(strings.TrimSpace(*clusterSizeText), 10, 64)
	if err != nil {
		return fmt.Errorf("parse --cluster-size: %w", err)
	}
	if selectedOperation == "iso" {
		if persistenceSize != 0 {
			return errors.New("ISO Image mode does not accept a persistence size")
		}
		if *runtimeUEFIValidation {
			return errors.New("ISO Image mode does not install the persistence runtime validator")
		}
		if selectedPartitionScheme == "" {
			selectedPartitionScheme = "mbr"
		}
		if selectedPartitionScheme != "mbr" && selectedPartitionScheme != "gpt" {
			return errors.New("--partition-scheme must be mbr or gpt for ISO Image mode")
		}
		// Preserve older graphical callers until they explicitly pass the new
		// selector. The updated GTK path uses Automatic by default.
		if selectedFilesystem == "" {
			selectedFilesystem = "fat32"
		}
		switch selectedFilesystem {
		case "auto", "fat32", "ntfs":
		default:
			return errors.New("--filesystem must be auto, fat32, or ntfs for ISO Image mode")
		}
		if clusterSize == 0 {
			clusterSize = 4096
		}
		switch clusterSize {
		case 4096, 8192, 16384, 32768:
		default:
			return errors.New("--cluster-size must be 4096, 8192, 16384, or 32768 for ISO Image mode")
		}
	} else if selectedPartitionScheme != "" || selectedFilesystem != "" || clusterSize != 0 {
		return errors.New("--partition-scheme, --filesystem, and --cluster-size are accepted only for ISO Image mode")
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

	// Keep both independently useful identities through every callback. The
	// package token deliberately excludes child partitions, so formatting the
	// selected disk does not invalidate it; a disconnect/reconnect or /dev name
	// reuse does.
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

	out := &emitter{json: *jsonProgress}
	operationLabel := "Persistent live media"
	if selectedOperation == "iso" {
		operationLabel = "ISO Image mode"
	}
	preflightMessage := fmt.Sprintf("%s: %s; target: %s", operationLabel, filepath.Base(resolvedImage), resolvedTarget)
	if selectedOperation == "iso" {
		filesystemLabel := strings.ToUpper(selectedFilesystem)
		if selectedFilesystem == "auto" {
			filesystemLabel = "AUTOMATIC (FAT32 preferred)"
		}
		preflightMessage = fmt.Sprintf("%s; layout: %s/UEFI/%s; cluster: %d bytes", preflightMessage, strings.ToUpper(selectedPartitionScheme), filesystemLabel, clusterSize)
	}
	out.event(jsonEvent{Event: "preflight", Stage: "preflight", Message: preflightMessage})

	// Byte-counted copy and hashing stages already emit frequent progress. For
	// commands such as formatting, filesystem checks, partition refreshes, sync,
	// and unmount, repeat the current stage periodically so the graphical progress
	// bar continues pulsing and the operation cannot look silently frozen.
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

	forwardEvent := func(event linuxmedia.PersistentEvent) {
		heartbeatMu.Lock()
		heartbeat = event
		if event.Stage == "qualification" {
			heartbeat = linuxmedia.PersistentEvent{
				Stage:   "sync",
				Message: "Finalizing files and flushing the persistent USB safely. This can take several minutes on slower drives…",
			}
		}
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
	}

	if selectedOperation == "iso" {
		result, err := linuxmedia.CreateExtractedSelected(ctx, resolvedImage, resolvedTarget, linuxmedia.ExtractedDispatchOptions{
			ExtractedCreateOptions: linuxmedia.ExtractedCreateOptions{
				TargetSize:        target.Size,
				ExpectedDeviceID:  kernelDeviceID,
				ExpectedSource:    expectedSource,
				Architecture:      runtime.GOARCH,
				VolumeLabel:       *volumeLabel,
				PartitionScheme:   selectedPartitionScheme,
				ClusterSize:       clusterSize,
				BeforeDestructive: targetCheck,
			},
			Filesystem: selectedFilesystem,
		}, forwardEvent)
		stopHeartbeat()
		if err != nil {
			return err
		}
		if err := safety.RereadPartitionTable(resolvedTarget); err != nil {
			out.event(jsonEvent{Event: "log", Stage: "warning", Message: fmt.Sprintf("Warning: %v", err)})
		}
		selected := strings.ToUpper(string(result.Selection.Selected))
		switch result.Selection.Selected {
		case linuxmedia.ExtractedFilesystemFAT32:
			if result.FAT32 == nil {
				return errors.New("ISO Image mode FAT32 dispatch returned no result")
			}
			out.event(jsonEvent{
				Event:   "log",
				Stage:   "verification",
				Message: fmt.Sprintf("ISO Image mode source SHA-256 %s; verified UEFI fallback %s; layout %s/UEFI/%s; cluster %d bytes.", result.FAT32.SourceSHA256, result.FAT32.UEFIBootPath, strings.ToUpper(result.FAT32.PartitionScheme), selected, result.FAT32.ClusterSize),
				Hash:    result.FAT32.SourceSHA256,
			})
		case linuxmedia.ExtractedFilesystemNTFS:
			if result.NTFS == nil {
				return errors.New("ISO Image mode NTFS dispatch returned no result")
			}
			out.event(jsonEvent{
				Event:   "log",
				Stage:   "verification",
				Message: fmt.Sprintf("ISO Image mode source SHA-256 %s; verified UEFI fallback %s; layout %s/UEFI/%s; cluster %d bytes; UEFI:NTFS SHA-256 %s.", result.NTFS.SourceSHA256, result.NTFS.UEFIBootPath, strings.ToUpper(result.NTFS.Plan.PartitionScheme), selected, result.NTFS.Plan.ClusterSize, result.NTFS.UEFINTFSSHA256),
				Hash:    result.NTFS.SourceSHA256,
			})
		default:
			return fmt.Errorf("unexpected ISO Image mode filesystem result %q", result.Selection.Selected)
		}
		out.event(jsonEvent{Event: "complete", Stage: "complete", Message: fmt.Sprintf("ISO Image mode USB created and verified (%s).", selected)})
		return nil
	}

	result, err := linuxmedia.CreatePersistent(ctx, resolvedImage, resolvedTarget, linuxmedia.PersistentCreateOptions{
		TargetSize:                      target.Size,
		ExpectedDeviceID:                kernelDeviceID,
		ExpectedSource:                  expectedSource,
		Architecture:                    runtime.GOARCH,
		PersistenceSize:                 persistenceSize,
		VolumeLabel:                     *volumeLabel,
		CreatorVersion:                  "RufusArm64 " + version,
		BeforeDestructive:               targetCheck,
		RuntimeUEFIValidation:           *runtimeUEFIValidation,
		RuntimeUEFILoaderPath:           packagedRuntimeUEFILoaderPath,
		RuntimeUEFILoaderSHA256:         packagedRuntimeUEFILoaderSHA256,
		RuntimeUEFILoaderSourceCommit:   packagedRuntimeUEFILoaderCommit,
		RuntimeUEFILoaderProvenance:     packagedRuntimeUEFILoaderProvenance,
		RuntimeUEFIUnsignedAcknowledged: *runtimeUEFIValidation,
	}, forwardEvent)
	stopHeartbeat()
	if err != nil {
		return err
	}
	if result.RuntimeIntegrity != nil {
		out.event(jsonEvent{
			Event:   "log",
			Stage:   "runtime_integrity",
			Message: fmt.Sprintf("Runtime UEFI media validation installed and verified; manifest SHA-256 %s. The loader is unsigned and is not Secure Boot compatible.", result.RuntimeIntegrity.ManifestSHA256),
			Hash:    result.RuntimeIntegrity.ManifestSHA256,
		})
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
