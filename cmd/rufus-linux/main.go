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
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/geocausa/RufusArm64/internal/acquisition"
	"github.com/geocausa/RufusArm64/internal/device"
	"github.com/geocausa/RufusArm64/internal/imaging"
	"github.com/geocausa/RufusArm64/internal/linuxmedia"
	"github.com/geocausa/RufusArm64/internal/persistence"
	"github.com/geocausa/RufusArm64/internal/qualification"
	"github.com/geocausa/RufusArm64/internal/safety"
	"github.com/geocausa/RufusArm64/internal/secureboot"
	"github.com/geocausa/RufusArm64/internal/sourcefile"
	"github.com/geocausa/RufusArm64/internal/windowsconfig"
	"github.com/geocausa/RufusArm64/internal/windowsmedia"
)

var version = "development"

const defaultAcquisitionChannelConfig = "/usr/share/rufusarm64/acquisition/channel.json"

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

func (e emitter) event(v jsonEvent) {
	if e.json {
		data, _ := json.Marshal(v)
		fmt.Println(string(data))
		return
	}
	if v.Message != "" {
		fmt.Println(v.Message)
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
		usage()
		return nil
	}
	switch args[0] {
	case "list":
		return runList(args[1:])
	case "inspect":
		return runInspect(args[1:])
	case "write":
		return runWrite(args[1:])
	case "verify":
		return runVerify(args[1:])
	case "hash":
		return runHash(args[1:])
	case "dbx":
		return runDBX(args[1:])
	case "uefi":
		return runUEFI(args[1:])
	case "acquire":
		return runAcquire(args[1:])
	case "persistence":
		return runPersistence(args[1:])
	case "qualify":
		return runQualify(args[1:])
	case "version", "--version", "-v":
		fmt.Println(version)
		return nil
	case "help", "--help", "-h":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage() {
	fmt.Printf(`RufusArm64 %s — bootable USB creator for Linux ARM64

Usage:
  rufusarm64-cli list [--all] [--json]
  rufusarm64-cli inspect --image FILE [--json]
  sudo rufusarm64-cli write --image FILE --device /dev/DEVICE [--verify]
  sudo rufusarm64-cli write --mode linux-persistent --experimental-persistence --image FILE --device /dev/DEVICE [--persistence-size SIZE]
  sudo rufusarm64-cli verify --image FILE --device /dev/DEVICE
  rufusarm64-cli hash FILE
  rufusarm64-cli uefi validate --directory DIR [--arch ARCH] [--dbx FILE | --firmware] [--sbat-level FILE] [--json]
  rufusarm64-cli dbx inspect (--file FILE | --firmware) [--json]
  rufusarm64-cli dbx update [--arch ARCH] [--output FILE] [--json]
  rufusarm64-cli dbx check --dbx FILE --efi FILE [--json]
  rufusarm64-cli dbx scan --dbx FILE --directory DIR [--json]
  rufusarm64-cli acquire verify --catalog FILE --signature FILE --public-key FILE [--json]
  rufusarm64-cli acquire list --catalog FILE --signature FILE --public-key FILE [--json]
  rufusarm64-cli acquire download --catalog FILE --signature FILE --public-key FILE --id ID [--output FILE]
  rufusarm64-cli acquire channel list [--offline] [--json]
  rufusarm64-cli acquire channel download --id ID [--output FILE] [--offline]
  rufusarm64-cli persistence plan --image FILE --media-root DIR --target-size SIZE [--size SIZE] [--json]
  sudo rufusarm64-cli persistence analyze --image FILE --expected-source-identity ID --target-size SIZE [--size SIZE] [--json]
  sudo rufusarm64-cli qualify start --record FILE --output FILE [--state-dir DIR] [--json]
  sudo rufusarm64-cli qualify verify --record FILE --output FILE [--state-dir DIR] [--json]

Acquisition catalogs are accepted only after detached Ed25519 signature, expiry, URL, size, filename, and SHA-256 validation.
The built-in channel additionally enforces threshold root/catalog signatures, key rotation, version rollback protection, and owner-only atomic trust state.
Persistence planning accepts mounted or extracted Ubuntu 20.04+ casper and Debian live-boot media trees.
Automatic analysis mounts the selected plain ISOHybrid image privately and read-only; it never opens a target device.
The experimental persistent writer is CLI-only, GPT/UEFI-only, and is never accepted by the graphical privileged path.
Qualification start records the first successful persistent boot; qualification verify requires a later reboot and surviving state.

The automatic mode writes Linux ISOHybrid/raw images directly and creates
standard Windows installation USBs using automatic FAT32/NTFS selection, WIM splitting, and UEFI:NTFS when required.
Writing is destructive and the running system disk is always refused.
`, version)
}

func runList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	all := fs.Bool("all", false, "include non-removable whole disks")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	devices, err := device.List()
	if err != nil {
		return err
	}
	disks := device.WholeDisks(devices)
	filtered := make([]device.BlockDevice, 0, len(disks))
	for _, d := range disks {
		if !*all && !device.IsNormalRemovableTarget(d) {
			continue
		}
		filtered = append(filtered, d)
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(filtered)
	}
	fmt.Printf("%-16s %-10s %-8s %-5s %-5s %s\n", "DEVICE", "SIZE", "TRAN", "RM", "RO", "MODEL")
	for _, d := range filtered {
		model := strings.TrimSpace(d.Vendor + " " + d.Model)
		fmt.Printf("%-16s %-10s %-8s %-5t %-5t %s\n", d.Path, humanBytes(d.Size), d.Transport, d.Removable, d.ReadOnly, model)
		for _, child := range d.Children {
			if len(child.Mountpoints) > 0 {
				fmt.Printf("  mounted: %-12s %s\n", child.Path, strings.Join(child.Mountpoints, ", "))
			}
		}
	}
	return nil
}

type inspectResult struct {
	Mode             string `json:"mode"`
	Recognized       bool   `json:"recognized"`
	PartitionScheme  string `json:"partition_scheme"`
	TargetSystem     string `json:"target_system"`
	FileSystem       string `json:"filesystem"`
	WindowsOptions   bool   `json:"windows_options"`
	Description      string `json:"description"`
	ContainerFormat  string `json:"container_format,omitempty"`
	NeedsPreparation bool   `json:"needs_preparation,omitempty"`
}

func runInspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	imagePath := fs.String("image", "", "image or ISO file")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *imagePath == "" {
		return errors.New("--image is required")
	}
	resolved, identity, err := sourcefile.Inspect(*imagePath)
	if err != nil {
		return err
	}
	file, err := sourcefile.OpenRegular(resolved, identity)
	if err != nil {
		return err
	}
	probe, probeErr := imaging.ProbeInput(resolved, file)
	if probeErr != nil {
		file.Close()
		return probeErr
	}
	result := inspectResult{
		ContainerFormat:  string(probe.Kind),
		NeedsPreparation: probe.NeedsPreparation,
	}
	var modeErr error
	if !probe.Supported {
		result.Description = probe.Description + "; this container cannot currently be restored safely on Linux"
		modeErr = errors.New(result.Description)
	} else if probe.NeedsPreparation {
		previewCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		preview, available, previewErr := imaging.PreviewInput(previewCtx, resolved, file, probe)
		cancel()
		if previewErr != nil {
			file.Close()
			return fmt.Errorf("preview image container: %w", previewErr)
		}
		result.Recognized = true
		if available && preview.Recognized() {
			selected, selectionErr := selectWriteMode("auto", preview, false)
			modeErr = selectionErr
			if selectionErr == nil && selected == "windows" {
				result.Mode = "windows"
				result.PartitionScheme = "GPT"
				result.TargetSystem = "UEFI"
				result.FileSystem = "Automatic (FAT32 preferred)"
				result.WindowsOptions = true
				result.Description = probe.Description + "; Windows installation media will be fully expanded and validated before the USB is erased"
			} else {
				result.Mode = "raw"
				result.PartitionScheme = "From image"
				result.TargetSystem = "From image"
				result.FileSystem = "From image"
				result.Description = probe.Description + "; its embedded disk layout will be preserved after preparation"
			}
		} else {
			result.Mode = "raw"
			result.PartitionScheme = "From image"
			result.TargetSystem = "From image"
			result.FileSystem = "From image"
			result.Description = probe.Description + "; it will be converted and fully validated before the USB is erased"
		}
	} else {
		inspection, inspectErr := imaging.InspectOpenFile(file)
		if inspectErr != nil {
			file.Close()
			return inspectErr
		}
		result.Recognized = inspection.Recognized()
		mode, err := selectWriteMode("auto", inspection, false)
		modeErr = err
		switch {
		case err != nil:
			result.Description = err.Error()
		case mode == "windows":
			result.Mode = "windows"
			result.PartitionScheme = "GPT"
			result.TargetSystem = "UEFI"
			result.FileSystem = "Automatic (FAT32 preferred)"
			result.WindowsOptions = true
			result.Description = "Standard Windows UEFI installation media"
		default:
			result.Mode = "raw"
			result.PartitionScheme = "From image"
			result.TargetSystem = "From image"
			result.FileSystem = "From image"
			result.Description = "Raw/ISOHybrid image; embedded layout will be preserved"
		}
	}
	if err := file.Close(); err != nil {
		return err
	}
	// Exit codes are consistent between the JSON and plain outputs so shell
	// scripts can rely on "inspect && write". The JSON document is always
	// emitted first; the graphical interface parses it even on failure.
	if *asJSON {
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			return err
		}
	} else {
		fmt.Printf("Mode: %s\nPartition scheme: %s\nTarget system: %s\nFile system: %s\n", result.Mode, result.PartitionScheme, result.TargetSystem, result.FileSystem)
		if result.ContainerFormat != "" && result.ContainerFormat != string(imaging.InputPlain) {
			fmt.Printf("Container: %s\n", result.ContainerFormat)
		}
		if result.Description != "" {
			fmt.Println(result.Description)
		}
	}
	if modeErr != nil {
		return fmt.Errorf("image is not usable: %w", modeErr)
	}
	if !result.Recognized {
		return errors.New("image is not recognized")
	}
	return nil
}

func runWrite(args []string) error {
	fs := flag.NewFlagSet("write", flag.ContinueOnError)
	imagePath := fs.String("image", "", "image or ISO file")
	devicePath := fs.String("device", "", "whole target disk")
	mode := fs.String("mode", "auto", "auto, raw, windows, or linux-persistent")
	verify := fs.Bool("verify", false, "verify data after writing")
	yes := fs.Bool("yes", false, "skip interactive confirmation")
	allowFixed := fs.Bool("allow-fixed", false, "allow a non-removable disk")
	noUnmount := fs.Bool("no-unmount", false, "do not unmount mounted filesystems")
	forceRaw := fs.Bool("force-raw", false, "force raw writing of a plain ISO")
	dryRun := fs.Bool("dry-run", false, "check only")
	jsonProgress := fs.Bool("json-progress", false, "emit JSON lines for the GUI")
	expectedIdentity := fs.String("expected-identity", "", "expected device identity from the list command")
	cancelFile := fs.String("cancel-file", "", "per-user cancellation marker used by the graphical app")
	allowForeignArchitecture := fs.Bool("allow-foreign-windows-architecture", false, "allow x86-64-only Windows media on an ARM64 host")
	volumeLabel := fs.String("volume-label", "RUFUSARM64", "volume label for extracted Windows or experimental Linux boot media")
	partitionScheme := fs.String("partition-scheme", "gpt", "Windows media partition scheme: gpt or mbr")
	targetSystem := fs.String("target-system", "uefi", "Windows target system: uefi or bios")
	filesystem := fs.String("filesystem", "auto", "Windows media filesystem: auto, fat32, or ntfs")
	clusterSizeText := fs.String("cluster-size", "auto", "cluster size: auto, 4096, 8192, 16384, or 32768")
	driverFolder := fs.String("driver-folder", "", "optional folder of Windows .inf drivers to copy to the USB")
	dbxFile := fs.String("dbx-file", "", "optional Secure Boot DBXUpdate.bin used to reject revoked EFI boot files")
	fullFormat := fs.Bool("full-format", false, "zero the Windows partition before formatting")
	badBlockCheck := fs.Bool("bad-block-check", false, "zero and read back the Windows partition before formatting")
	winBypassHardware := fs.Bool("win-bypass-hardware", false, "bypass Windows TPM, Secure Boot, and RAM checks")
	winBypassOnline := fs.Bool("win-bypass-online-account", false, "remove Windows online-account requirement")
	winLocalUser := fs.String("win-local-user", "", "create a local Windows administrator account")
	winPrivacy := fs.Bool("win-reduce-data-collection", false, "reduce Windows setup data collection and recommendations")
	winDisableBitLocker := fs.Bool("win-disable-bitlocker", false, "disable automatic Windows device encryption provisioning")
	winLocale := fs.String("win-locale", "", "apply a Windows regional locale, such as en-GB")
	winTimeZone := fs.String("win-timezone", "", "apply a Windows time-zone name")
	experimentalPersistence := fs.Bool("experimental-persistence", false, "enable the experimental CLI-only Linux persistence writer")
	persistenceSizeText := fs.String("persistence-size", "0", "persistent ext4 size in bytes or K/M/G/T units; zero uses remaining space")
	if err := fs.Parse(args); err != nil {
		return err
	}
	out := emitter{json: *jsonProgress}
	if *imagePath == "" || *devicePath == "" {
		return errors.New("--image and --device are required")
	}
	if *jsonProgress && *expectedIdentity == "" {
		return errors.New("the graphical writer requires an expected device identity; refresh the drive list and try again")
	}
	switch *mode {
	case "auto", "raw", "windows", "linux-persistent":
	default:
		return errors.New("--mode must be auto, raw, windows, or linux-persistent")
	}
	if os.Getenv("PKEXEC_UID") != "" {
		if !*jsonProgress || !*yes || *expectedIdentity == "" || *cancelFile == "" || *mode != "auto" || *allowFixed || *noUnmount || *forceRaw || *allowForeignArchitecture {
			return errors.New("unsafe or unsupported arguments were supplied to the graphical privileged writer")
		}
	}
	if err := safety.RequireRoot(); err != nil && !*dryRun {
		return err
	}
	if os.Geteuid() == 0 {
		setTrustedSystemPath()
	}
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancelCleanup, err := newWriterCancellationContext(signalCtx, *cancelFile)
	if err != nil {
		return err
	}
	defer cancelCleanup()

	resolvedImage, originalSourceIdentity, err := sourcefile.Inspect(*imagePath)
	if err != nil {
		return err
	}
	originalImagePath := resolvedImage

	// Validate and identity-bind the target before doing potentially large image
	// preparation. This is non-destructive and gives decompression/conversion a
	// hard output limit equal to the selected drive size.
	resolved, err := safety.ResolveDevice(*devicePath)
	if err != nil {
		return err
	}
	dev, err := device.Find(resolved)
	if err != nil {
		return err
	}
	selectedIdentity := *expectedIdentity
	if selectedIdentity == "" {
		selectedIdentity = dev.Identity
	}
	if err := safety.ValidateExpectedIdentity(dev, selectedIdentity); err != nil {
		return err
	}
	if err := safety.ValidateTarget(resolved, dev, *allowFixed); err != nil {
		return err
	}
	if err := safety.EnsureImageNotOnTarget(originalImagePath, resolved); err != nil {
		return err
	}

	var prepareLast time.Time
	prepared, err := imaging.PrepareInputWithOptions(ctx, resolvedImage, originalSourceIdentity, imaging.PrepareOptions{MaxPreparedSize: dev.Size}, func(p imaging.PrepareProgress) {
		if *jsonProgress {
			out.event(jsonEvent{Event: "progress", Stage: p.Stage, Message: p.Message, Done: p.Done, Total: p.Total})
			return
		}
		if p.Done > 0 && (time.Since(prepareLast) >= 200*time.Millisecond || (p.Total > 0 && p.Done == p.Total)) {
			printProgress("prepare", imaging.Progress{Done: p.Done, Total: p.Total})
			prepareLast = time.Now()
		} else if p.Message != "" && p.Done == 0 {
			fmt.Println(p.Message)
		}
	})
	if !*jsonProgress && prepareLast != (time.Time{}) {
		fmt.Println()
	}
	if err != nil {
		return err
	}
	defer prepared.Close()
	preparedImagePath := prepared.Path
	imagePath = &preparedImagePath
	sourceIdentity := prepared.Identity
	inspectionFile, err := sourcefile.OpenRegular(*imagePath, sourceIdentity)
	if err != nil {
		return err
	}
	inspection, inspectErr := imaging.InspectOpenFile(inspectionFile)
	closeErr := inspectionFile.Close()
	if inspectErr != nil {
		return inspectErr
	}
	if closeErr != nil {
		return fmt.Errorf("close image after inspection: %w", closeErr)
	}
	imageSize := uint64(sourceIdentity.Size)

	selectedMode, err := selectWriteMode(*mode, inspection, *forceRaw)
	if err != nil {
		return err
	}
	clusterSize, err := parseClusterSize(*clusterSizeText)
	if err != nil {
		return err
	}
	persistenceSize, err := persistence.ParseSize(*persistenceSizeText)
	if err != nil {
		return fmt.Errorf("parse --persistence-size: %w", err)
	}
	scheme := strings.ToLower(strings.TrimSpace(*partitionScheme))
	if scheme != "gpt" && scheme != "mbr" {
		return errors.New("--partition-scheme must be gpt or mbr")
	}
	targetSystemChoice := strings.ToLower(strings.TrimSpace(*targetSystem))
	switch targetSystemChoice {
	case "", "auto", "uefi":
		targetSystemChoice = "uefi"
	case "bios", "legacy", "legacy-bios", "bios-csm":
		targetSystemChoice = "bios"
	default:
		return errors.New("--target-system must be uefi or bios")
	}
	if targetSystemChoice == "bios" && scheme != "mbr" {
		return errors.New("--target-system bios requires --partition-scheme mbr")
	}
	filesystemChoice := strings.ToLower(strings.TrimSpace(*filesystem))
	if filesystemChoice == "" {
		filesystemChoice = "auto"
	}
	if filesystemChoice != "auto" && filesystemChoice != "fat32" && filesystemChoice != "ntfs" {
		return errors.New("--filesystem must be auto, fat32, or ntfs")
	}
	winOptions := windowsconfig.Options{
		BypassHardwareChecks: *winBypassHardware,
		BypassOnlineAccount:  *winBypassOnline,
		LocalAccount:         *winLocalUser,
		ReduceDataCollection: *winPrivacy,
		DisableBitLocker:     *winDisableBitLocker,
		Locale:               *winLocale,
		TimeZone:             *winTimeZone,
	}
	if selectedMode != "windows" && (winOptions.Enabled() || scheme != "gpt" || targetSystemChoice != "uefi" || filesystemChoice != "auto" || clusterSize != 0 || *driverFolder != "" || *dbxFile != "" || *fullFormat || *badBlockCheck) {
		return errors.New("windows partition and setup options can only be used with a supported Windows installation ISO")
	}
	if selectedMode == "linux-persistent" {
		if !*experimentalPersistence {
			return errors.New("experimental Linux persistence requires --experimental-persistence")
		}
		if !inspection.HasOpticalFilesystem() || !inspection.LooksLikeRawBootMedia() {
			return errors.New("experimental Linux persistence requires a recognized bootable Linux ISOHybrid image")
		}
		if *forceRaw || *allowForeignArchitecture {
			return errors.New("raw-image and foreign-Windows architecture overrides are incompatible with Linux persistence")
		}
		if scheme != "gpt" || targetSystemChoice != "uefi" || filesystemChoice != "auto" || clusterSize != 0 {
			return errors.New("experimental Linux persistence currently requires GPT, UEFI, and automatic filesystem settings")
		}
	} else if *experimentalPersistence || persistenceSize != 0 {
		return errors.New("--experimental-persistence and --persistence-size require --mode linux-persistent")
	}
	if err := windowsconfig.Validate(winOptions); err != nil {
		return err
	}

	if strings.TrimSpace(*driverFolder) != "" {
		if err := safety.EnsurePathNotOnTarget(*driverFolder, resolved); err != nil {
			return fmt.Errorf("windows driver folder is on the selected target: %w", err)
		}
	}
	if strings.TrimSpace(*dbxFile) != "" {
		if err := safety.EnsurePathNotOnTarget(*dbxFile, resolved); err != nil {
			return fmt.Errorf("secure boot DBX file is on the selected target: %w", err)
		}
	}
	if selectedMode == "raw" && imageSize > dev.Size {
		return fmt.Errorf("image is %s but target is only %s", humanBytes(imageSize), humanBytes(dev.Size))
	}

	containerNote := ""
	if prepared.Kind != imaging.InputPlain {
		containerNote = fmt.Sprintf(" [%s prepared as %s]", prepared.Kind, humanBytes(imageSize))
	}
	out.event(jsonEvent{Event: "preflight", Stage: "preflight", Message: fmt.Sprintf("Image: %s%s; target: %s (%s)", filepath.Base(originalImagePath), containerNote, resolved, humanBytes(dev.Size))})
	mounts := device.MountedDescendants(dev)
	if len(mounts) > 0 && *noUnmount {
		return errors.New("target has mounted filesystems")
	}
	if *dryRun {
		out.event(jsonEvent{Event: "complete", Message: "Basic non-destructive checks passed; no data was written."})
		return nil
	}
	if !*yes {
		if err := confirmDestructive(resolved); err != nil {
			return err
		}
	}

	// Refresh metadata after confirmation and immediately before opening the
	// destructive path. This catches unplug/replug and /dev name reuse.
	dev, kernelDeviceID, err := safety.RevalidateTarget(resolved, selectedIdentity, *allowFixed)
	if err != nil {
		return err
	}
	if !*noUnmount {
		if err := safety.UnmountDescendants(dev); err != nil {
			return err
		}
	}

	targetCheck := func(source *os.File, expectedIdentity string) error {
		fresh, currentID, err := safety.RevalidateTarget(resolved, expectedIdentity, *allowFixed)
		if err != nil {
			return err
		}
		if currentID != kernelDeviceID {
			return errors.New("the selected kernel device changed after confirmation")
		}
		if err := safety.EnsureOpenFileNotOnTarget(source, fresh); err != nil {
			return err
		}
		if !*noUnmount {
			if err := safety.UnmountDescendants(fresh); err != nil {
				return err
			}
		}
		return safety.EnsureNoMountedDescendants(resolved)
	}
	strictTargetCheck := func(source *os.File) error {
		return targetCheck(source, selectedIdentity)
	}
	postWriteTargetCheck := func(source *os.File) error {
		return targetCheck(source, selectedIdentity)
	}

	if selectedMode == "linux-persistent" {
		out.event(jsonEvent{Event: "stage", Stage: "linux_persistence", Message: "Creating experimental persistent Linux media…"})
		persistentResult, err := linuxmedia.CreatePersistent(ctx, *imagePath, resolved, linuxmedia.PersistentCreateOptions{
			TargetSize:        dev.Size,
			ExpectedDeviceID:  kernelDeviceID,
			ExpectedSource:    sourceIdentity,
			Architecture:      runtime.GOARCH,
			PersistenceSize:   persistenceSize,
			VolumeLabel:       *volumeLabel,
			CreatorVersion:    "RufusArm64 " + version,
			BeforeDestructive: postWriteTargetCheck,
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
		if err := safety.RereadPartitionTable(resolved); err != nil {
			out.event(jsonEvent{Event: "log", Stage: "warning", Message: fmt.Sprintf("Warning: %v", err)})
		}
		out.event(jsonEvent{
			Event:   "log",
			Stage:   "qualification",
			Message: fmt.Sprintf("Qualification record stored at .rufusarm64/%s", qualification.RecordFileName),
			Hash:    persistentResult.QualificationRecordSHA256,
		})
		out.event(jsonEvent{Event: "complete", Stage: "complete", Message: "Experimental persistent Linux USB created and verified."})
		return nil
	}

	if selectedMode == "windows" {
		out.event(jsonEvent{Event: "stage", Stage: "windows", Message: "Creating Windows installation media…"})
		err := windowsmedia.Create(ctx, *imagePath, resolved, windowsmedia.Options{
			TargetSize:        dev.Size,
			Verify:            *verify,
			ExpectedDeviceID:  kernelDeviceID,
			ExpectedSource:    sourceIdentity,
			RequireARM64:      runtime.GOARCH == "arm64" && !*allowForeignArchitecture && targetSystemChoice != "bios",
			VolumeLabel:       *volumeLabel,
			PartitionScheme:   scheme,
			TargetSystem:      targetSystemChoice,
			Filesystem:        filesystemChoice,
			ClusterSize:       clusterSize,
			DriverFolder:      *driverFolder,
			DBXPath:           *dbxFile,
			FullFormat:        *fullFormat,
			BadBlockCheck:     *badBlockCheck,
			Customizations:    winOptions,
			BeforeDestructive: postWriteTargetCheck,
		}, func(ev windowsmedia.Event) {
			eventName := "stage"
			if ev.Stage == "log" {
				eventName = "log"
			}
			if ev.Stage == "complete" {
				eventName = "complete"
			}
			out.event(jsonEvent{Event: eventName, Stage: ev.Stage, Message: ev.Message, Done: ev.Done, Total: ev.Total})
		})
		if err != nil {
			return err
		}
		if err := safety.RereadPartitionTable(resolved); err != nil {
			out.event(jsonEvent{Event: "log", Stage: "warning", Message: fmt.Sprintf("Warning: %v", err)})
		}
		out.event(jsonEvent{Event: "complete", Stage: "complete", Message: "Windows installation USB created successfully."})
		return nil
	}

	rawSource, err := sourcefile.OpenRegular(*imagePath, sourceIdentity)
	if err != nil {
		return err
	}
	rawSourceClosed := false
	defer func() {
		if !rawSourceClosed {
			_ = rawSource.Close()
		}
	}()
	if err := strictTargetCheck(rawSource); err != nil {
		return err
	}
	// Keep the exact selected source descriptor open from this point until the
	// write and optional verification finish. The writer opens the whole target
	// exclusively and clears stale signatures through that same descriptor.
	out.event(jsonEvent{Event: "stage", Stage: "write", Message: "Writing the image…"})
	var last time.Time
	written, err := imaging.WriteOpenImage(ctx, rawSource, resolved, imaging.WriteOptions{
		ExpectedDeviceID:     kernelDeviceID,
		ExpectedSource:       sourceIdentity,
		TargetSize:           dev.Size,
		ClearStaleSignatures: true,
		BeforeWrite: func(source *os.File) error {
			return strictTargetCheck(source)
		},
		SnapshotProgress: func(p imaging.Progress) {
			if *jsonProgress {
				out.event(jsonEvent{Event: "progress", Stage: "hash_source", Message: "Hashing the selected image before writing…", Done: p.Done, Total: p.Total, Rate: p.BytesPerSec})
			} else {
				printProgress("hash source", p)
			}
		},
		Progress: func(p imaging.Progress) {
			if !*jsonProgress && time.Since(last) < 200*time.Millisecond && p.Done != p.Total {
				return
			}
			last = time.Now()
			if *jsonProgress {
				out.event(jsonEvent{Event: "progress", Stage: "write", Done: p.Done, Total: p.Total, Rate: p.BytesPerSec})
			} else {
				printProgress("write", p)
			}
		},
	})
	if !*jsonProgress {
		fmt.Println()
	}
	if err != nil {
		return err
	}
	out.event(jsonEvent{Event: "stage", Stage: "sync", Message: fmt.Sprintf("Wrote %s successfully.", humanBytes(written))})
	if err := postWriteTargetCheck(rawSource); err != nil {
		return err
	}
	if err := safety.FlushBuffers(ctx, resolved); err != nil {
		return fmt.Errorf("flush USB write buffers: %w", err)
	}
	completionMessage := "Bootable USB created successfully."
	completionHash := ""
	if *verify {
		out.event(jsonEvent{Event: "stage", Stage: "verify", Message: "Verifying the USB from the physical device…"})
		hash, err := imaging.VerifyOpenImageWithOptions(ctx, rawSource, resolved, imaging.VerifyOptions{ExpectedDeviceID: kernelDeviceID, ExpectedDeviceSize: dev.Size, ExpectedSource: sourceIdentity}, func(p imaging.Progress) {
			if *jsonProgress {
				out.event(jsonEvent{Event: "progress", Stage: "verify", Done: p.Done, Total: p.Total, Rate: p.BytesPerSec})
			} else {
				printProgress("verify", p)
			}
		})
		if !*jsonProgress {
			fmt.Println()
		}
		if err != nil {
			return err
		}
		completionMessage = "USB created and verified successfully."
		completionHash = hash
	}
	if err := safety.RereadPartitionTable(resolved); err != nil {
		out.event(jsonEvent{Event: "log", Stage: "warning", Message: fmt.Sprintf("Warning: %v", err)})
	}
	if err := rawSource.Close(); err != nil {
		return fmt.Errorf("close image after writing: %w", err)
	}
	rawSourceClosed = true
	out.event(jsonEvent{Event: "complete", Stage: "complete", Message: completionMessage, Hash: completionHash})
	return nil
}

func selectWriteMode(requested string, inspection imaging.ImageInfo, forceRaw bool) (string, error) {
	if requested != "auto" && requested != "raw" && requested != "windows" && requested != "linux-persistent" {
		return "", errors.New("mode must be auto, raw, windows, or linux-persistent")
	}
	if !inspection.Recognized() && !forceRaw {
		return "", errors.New("the selected file is not a recognized ISOHybrid, GPT, or MBR disk image; refusing to write an arbitrary or damaged file")
	}
	selected := requested
	if selected == "auto" && forceRaw {
		selected = "raw"
	} else if selected == "auto" {
		if inspection.HasOpticalFilesystem() && !inspection.LooksLikeRawBootMedia() {
			selected = "windows"
		} else {
			selected = "raw"
		}
	}
	if selected == "raw" && inspection.HasOpticalFilesystem() && !inspection.LooksLikeRawBootMedia() && !forceRaw {
		return "", errors.New("this optical ISO is not raw-bootable; use automatic Windows mode or select a bootable disk image")
	}
	return selected, nil
}

type persistencePlanOutput struct {
	Detection  persistence.Detection `json:"detection"`
	Plan       persistence.Plan      `json:"plan"`
	ImageSize  uint64                `json:"image_size"`
	TargetSize uint64                `json:"target_size"`
}

func runPersistence(args []string) error {
	if len(args) == 0 {
		return errors.New("persistence requires plan or analyze")
	}
	switch args[0] {
	case "plan":
		return runPersistencePlan(args[1:])
	case "analyze":
		return runPersistenceAnalyze(args[1:])
	default:
		return fmt.Errorf("unknown persistence command %q", args[0])
	}
}

func runPersistencePlan(args []string) error {
	fsFlags := flag.NewFlagSet("persistence plan", flag.ContinueOnError)
	imagePath := fsFlags.String("image", "", "plain ISOHybrid image")
	mediaRoot := fsFlags.String("media-root", "", "read-only mounted or extracted media root")
	targetSizeText := fsFlags.String("target-size", "", "planned target size in bytes or K/M/G/T units")
	requestedSizeText := fsFlags.String("size", "0", "requested persistence size; zero uses all available space")
	asJSON := fsFlags.Bool("json", false, "output JSON")
	if err := fsFlags.Parse(args); err != nil {
		return err
	}
	if *imagePath == "" || *mediaRoot == "" || *targetSizeText == "" {
		return errors.New("--image, --media-root, and --target-size are required")
	}
	targetSize, err := persistence.ParseSize(*targetSizeText)
	if err != nil || targetSize == 0 {
		if err == nil {
			err = errors.New("target size must be greater than zero")
		}
		return fmt.Errorf("parse --target-size: %w", err)
	}
	requestedSize, err := persistence.ParseSize(*requestedSizeText)
	if err != nil {
		return fmt.Errorf("parse --size: %w", err)
	}
	resolvedImage, identity, err := sourcefile.Inspect(*imagePath)
	if err != nil {
		return err
	}
	image, err := sourcefile.OpenRegular(resolvedImage, identity)
	if err != nil {
		return err
	}
	defer image.Close()
	probe, err := imaging.ProbeInput(resolvedImage, image)
	if err != nil {
		return err
	}
	if probe.Kind != imaging.InputPlain {
		return errors.New("the initial persistence planner requires a plain ISOHybrid image; compressed and virtual-disk inputs are not yet accepted")
	}
	inspection, err := imaging.InspectOpenFile(image)
	if err != nil {
		return err
	}
	if !inspection.HasOpticalFilesystem() || !inspection.LooksLikeRawBootMedia() {
		return errors.New("persistence planning requires a recognized raw-bootable ISOHybrid image")
	}
	root, err := filepath.Abs(*mediaRoot)
	if err != nil {
		return fmt.Errorf("resolve media root: %w", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("resolve media root symlinks: %w", err)
	}
	rootInfo, err := os.Stat(root)
	if err != nil {
		return fmt.Errorf("stat media root: %w", err)
	}
	if !rootInfo.IsDir() {
		return errors.New("--media-root must be a directory")
	}
	detection, err := persistence.Detect(os.DirFS(root))
	if err != nil {
		return err
	}
	if !detection.Ready() {
		return fmt.Errorf("detected %s but its persistence contract is outside the initial supported scope", detection.DisplayName)
	}
	plan, err := persistence.BuildPlan(image, uint64(identity.Size), targetSize, requestedSize, detection)
	if err != nil {
		return err
	}
	result := persistencePlanOutput{Detection: detection, Plan: plan, ImageSize: uint64(identity.Size), TargetSize: targetSize}
	if *asJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	}
	fmt.Printf("Persistence plan for %s\n", detection.DisplayName)
	fmt.Printf("  Family: %s\n", detection.Family)
	fmt.Printf("  Partition: %s #%d, start %s, size %s\n", plan.PartitionTable, plan.PartitionNumber, humanBytes(plan.StartBytes), humanBytes(plan.SizeBytes))
	fmt.Printf("  Filesystem: %s, label %q\n", plan.Filesystem, plan.FilesystemLabel)
	fmt.Printf("  Boot parameter: %s\n", plan.BootParameter)
	if plan.RequiresGPTRelocation {
		fmt.Println("  GPT: backup header and entry table must be relocated to the target end")
	}
	if len(plan.PatchPaths) > 0 {
		fmt.Printf("  Boot configurations requiring an edit: %s\n", strings.Join(plan.PatchPaths, ", "))
	}
	return nil
}

func newWriterCancellationContext(parent context.Context, cancelFile string) (context.Context, context.CancelFunc, error) {
	return safety.CancellationContext(parent, cancelFile)
}

func newPersistenceAnalysisContext(parent context.Context, cancelFile string) (context.Context, context.CancelFunc, error) {
	timeoutCtx, timeoutCancel := context.WithTimeout(parent, 2*time.Minute)
	ctx, cancelCleanup, err := safety.CancellationContext(timeoutCtx, cancelFile)
	if err != nil {
		timeoutCancel()
		return nil, nil, err
	}
	cleanup := func() {
		cancelCleanup()
		timeoutCancel()
	}
	return ctx, cleanup, nil
}

func runPersistenceAnalyze(args []string) error {
	fsFlags := flag.NewFlagSet("persistence analyze", flag.ContinueOnError)
	imagePath := fsFlags.String("image", "", "plain ISOHybrid image")
	expectedSourceText := fsFlags.String("expected-source-identity", "", "identity recorded by the unprivileged graphical application")
	targetSizeText := fsFlags.String("target-size", "", "planned target size in bytes or K/M/G/T units")
	requestedSizeText := fsFlags.String("size", "0", "requested persistence size; zero uses all available space")
	cancelFile := fsFlags.String("cancel-file", "", "per-user cancellation marker used by the graphical app")
	asJSON := fsFlags.Bool("json", false, "output JSON")
	if err := fsFlags.Parse(args); err != nil {
		return err
	}
	if fsFlags.NArg() != 0 {
		return errors.New("persistence analyze does not accept positional arguments")
	}
	if *imagePath == "" || *expectedSourceText == "" || *targetSizeText == "" {
		return errors.New("--image, --expected-source-identity, and --target-size are required")
	}
	if os.Getenv("PKEXEC_UID") != "" && (!*asJSON || *cancelFile == "") {
		return errors.New("graphical automatic persistence analysis requires --json and a trusted --cancel-file")
	}
	targetSize, err := persistence.ParseSize(*targetSizeText)
	if err != nil || targetSize == 0 {
		if err == nil {
			err = errors.New("target size must be greater than zero")
		}
		return fmt.Errorf("parse --target-size: %w", err)
	}
	requestedSize, err := persistence.ParseSize(*requestedSizeText)
	if err != nil {
		return fmt.Errorf("parse --size: %w", err)
	}
	expectedSource, err := sourcefile.ParseIdentity(*expectedSourceText)
	if err != nil {
		return fmt.Errorf("parse --expected-source-identity: %w", err)
	}
	absoluteImage, err := filepath.Abs(*imagePath)
	if err != nil {
		return fmt.Errorf("make image path absolute: %w", err)
	}
	resolvedImage, err := filepath.EvalSymlinks(absoluteImage)
	if err != nil {
		return fmt.Errorf("resolve image path: %w", err)
	}
	if err := safety.RequireRoot(); err != nil {
		return err
	}
	setTrustedSystemPath()
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancelCleanup, err := newPersistenceAnalysisContext(signalCtx, *cancelFile)
	if err != nil {
		return err
	}
	defer cancelCleanup()
	result, err := linuxmedia.AnalyzePersistent(ctx, resolvedImage, linuxmedia.PersistentAnalysisOptions{
		ExpectedSource:  expectedSource,
		TargetSize:      targetSize,
		PersistenceSize: requestedSize,
	}, nil)
	if err != nil {
		return err
	}
	if *asJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	}
	fmt.Printf("Persistence analysis for %s\n", result.Detection.DisplayName)
	fmt.Printf("  Family: %s\n", result.Detection.Family)
	fmt.Printf("  Partition: %s #%d, start %s, size %s\n", result.Plan.PartitionTable, result.Plan.PartitionNumber, humanBytes(result.Plan.StartBytes), humanBytes(result.Plan.SizeBytes))
	fmt.Printf("  Filesystem: %s, label %q\n", result.Plan.Filesystem, result.Plan.FilesystemLabel)
	fmt.Printf("  Boot parameter: %s\n", result.Plan.BootParameter)
	if len(result.Plan.PatchPaths) > 0 {
		fmt.Printf("  Boot configurations requiring an edit: %s\n", strings.Join(result.Plan.PatchPaths, ", "))
	}
	fmt.Println("  Read-only analysis completed; no target device was opened.")
	return nil
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	image := fs.String("image", "", "image")
	target := fs.String("device", "", "device")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *image == "" || *target == "" {
		return errors.New("--image and --device are required")
	}
	resolved, err := safety.ResolveDevice(*target)
	if err != nil {
		return err
	}
	if err := safety.RequireRoot(); err != nil {
		return err
	}
	setTrustedSystemPath()
	kernelDeviceID, err := safety.KernelDeviceID(resolved)
	if err != nil {
		return err
	}
	verifyDevice, err := device.Find(resolved)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	resolvedImage, identity, err := sourcefile.Inspect(*image)
	if err != nil {
		return err
	}
	prepared, err := imaging.PrepareInputWithOptions(ctx, resolvedImage, identity, imaging.PrepareOptions{MaxPreparedSize: verifyDevice.Size}, func(p imaging.PrepareProgress) {
		if p.Done > 0 {
			printProgress("prepare", imaging.Progress{Done: p.Done, Total: p.Total})
		} else if p.Message != "" {
			fmt.Println(p.Message)
		}
	})
	fmt.Println()
	if err != nil {
		return err
	}
	defer prepared.Close()
	if uint64(prepared.Identity.Size) > verifyDevice.Size {
		return fmt.Errorf("prepared image is %s but target is only %s", humanBytes(uint64(prepared.Identity.Size)), humanBytes(verifyDevice.Size))
	}
	if err := safety.FlushBuffers(ctx, resolved); err != nil {
		return fmt.Errorf("flush target buffers before verification: %w", err)
	}
	hash, err := imaging.VerifyImageWithOptions(ctx, prepared.Path, resolved, imaging.VerifyOptions{ExpectedDeviceID: kernelDeviceID, ExpectedDeviceSize: verifyDevice.Size, ExpectedSource: prepared.Identity}, func(p imaging.Progress) { printProgress("verify", p) })
	fmt.Println()
	if err != nil {
		return err
	}
	fmt.Printf("Verification succeeded. SHA-256: %s\n", hash)
	return nil
}

func setTrustedSystemPath() {
	_ = os.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
}

func runUEFI(args []string) error {
	if len(args) == 0 {
		return errors.New("uefi requires validate")
	}
	switch args[0] {
	case "validate":
		return runUEFIValidate(args[1:])
	default:
		return fmt.Errorf("unknown uefi command %q", args[0])
	}
}

func resolveUEFIArchitecture(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value != "" && value != "native" {
		return value, nil
	}
	switch runtime.GOARCH {
	case "386", "amd64", "arm", "arm64", "riscv64":
		return runtime.GOARCH, nil
	case "loong64":
		return "loongarch64", nil
	default:
		return "", fmt.Errorf("the native architecture %q is not supported for UEFI validation", runtime.GOARCH)
	}
}

func runUEFIValidate(args []string) error {
	fs := flag.NewFlagSet("uefi validate", flag.ContinueOnError)
	directory := fs.String("directory", "", "mounted or extracted UEFI media root")
	architecture := fs.String("arch", "native", "native, 386, amd64, arm, arm64, riscv64, or loongarch64")
	maxFiles := fs.Int("max-files", 512, "maximum EFI executables to validate")
	requireFallback := fs.Bool("require-fallback", true, "require the architecture removable-media fallback loader")
	dbxPath := fs.String("dbx", "", "optional DBXUpdate.bin or raw DBX file")
	firmware := fs.Bool("firmware", false, "use the running firmware DBX variable")
	sbatLevelPath := fs.String("sbat-level", "", "optional trusted local shim-compatible SbatLevel CSV file")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("uefi validate does not accept positional arguments")
	}
	if strings.TrimSpace(*directory) == "" {
		return errors.New("--directory is required")
	}
	if *maxFiles <= 0 {
		return errors.New("--max-files must be greater than zero")
	}
	if *dbxPath != "" && *firmware {
		return errors.New("select at most one of --dbx or --firmware")
	}
	resolvedArchitecture, err := resolveUEFIArchitecture(*architecture)
	if err != nil {
		return err
	}
	var sbatLevel *secureboot.SBATLevel
	if strings.TrimSpace(*sbatLevelPath) != "" {
		sbatLevel, err = secureboot.LoadSBATLevelFile(*sbatLevelPath)
		if err != nil {
			return err
		}
	}
	var dbx *secureboot.Database
	if *dbxPath != "" || *firmware {
		dbx, err = loadDBX(*dbxPath, *firmware)
		if err != nil {
			return err
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	result, err := secureboot.ValidateUEFIMedia(ctx, *directory, secureboot.UEFIValidationOptions{
		Architecture:    resolvedArchitecture,
		MaxFiles:        *maxFiles,
		DBX:             dbx,
		SBATLevel:       sbatLevel,
		RequireFallback: *requireFallback,
	})
	if err != nil {
		return err
	}
	if *asJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(result); err != nil {
			return err
		}
	} else {
		printUEFIValidation(result)
	}
	if !result.Valid {
		return errors.New("UEFI media validation failed")
	}
	return nil
}

func printUEFIValidation(result secureboot.UEFIMediaValidation) {
	status := "VALID"
	if !result.Valid {
		status = "INVALID"
	}
	fmt.Printf("%s UEFI media for %s\n", status, result.Architecture)
	fmt.Printf("Root: %s\nFallback: %s (found: %t)\nDBX checked: %t\nSBAT level checked: %t\n", result.Root, result.FallbackPath, result.FallbackFound, result.DBXChecked, result.SBATLevelChecked)
	if result.SBATLevelChecked {
		fmt.Printf("SBAT level: %s (datestamp %s)\n", result.SBATLevelSource, result.SBATLevelDatestamp)
	}
	for _, file := range result.Files {
		fileStatus := "OK"
		switch {
		case file.DirectHashRevoked || file.X509CertificateRevoked || file.SBATRevoked:
			fileStatus = "REVOKED"
		case file.Error != "":
			fileStatus = "ERROR"
		case len(file.Warnings) > 0:
			fileStatus = "WARNING"
		}
		fmt.Printf("%-8s %s [%s; %s; SBAT records: %d]\n", fileStatus, file.Path, file.MachineName, file.SubsystemName, len(file.SBAT))
		for _, revocation := range file.SBATRevocations {
			fmt.Printf("  SBAT revoked: %s generation %d is below trusted minimum %d\n", revocation.Component, revocation.ImageGeneration, revocation.MinimumGeneration)
		}
		for _, warning := range file.Warnings {
			fmt.Printf("  warning: %s\n", warning)
		}
		if file.Error != "" {
			fmt.Printf("  error: %s\n", file.Error)
		}
	}
	for _, warning := range result.Warnings {
		fmt.Printf("Warning: %s\n", warning)
	}
	for _, validationError := range result.Errors {
		fmt.Printf("Error: %s\n", validationError)
	}
}

func runDBX(args []string) error {
	if len(args) == 0 {
		return errors.New("dbx requires inspect, update, check, or scan")
	}
	switch args[0] {
	case "inspect":
		return runDBXInspect(args[1:])
	case "update":
		return runDBXUpdate(args[1:])
	case "check":
		return runDBXCheck(args[1:])
	case "scan":
		return runDBXScan(args[1:])
	default:
		return fmt.Errorf("unknown dbx command %q", args[0])
	}
}

func runDBXInspect(args []string) error {
	fs := flag.NewFlagSet("dbx inspect", flag.ContinueOnError)
	path := fs.String("file", "", "DBXUpdate.bin or raw EFI signature-list file")
	firmware := fs.Bool("firmware", false, "inspect the running firmware DBX variable")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if (*path == "") == !*firmware {
		return errors.New("select exactly one of --file or --firmware")
	}
	db, err := loadDBX(*path, *firmware)
	if err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(db.Summary())
	}
	summary := db.Summary()
	fmt.Printf("Source: %s\nAuthenticated update format: %t\nSignature lists: %d\nSignatures: %d\nSHA-256 revocations: %d\nX.509 revocations: %d\nOther signatures: %d\nFile SHA-256: %s\n",
		summary.Source, summary.Authenticated, summary.SignatureLists, summary.Signatures, summary.SHA256Hashes, summary.X509Certificates, summary.OtherSignatures, summary.FileSHA256)
	if summary.Timestamp != "" {
		fmt.Printf("Update timestamp: %s\n", summary.Timestamp)
	}
	return nil
}

func runDBXUpdate(args []string) error {
	fs := flag.NewFlagSet("dbx update", flag.ContinueOnError)
	arch := fs.String("arch", "native", "x86, amd64, arm, arm64, or ia64")
	output := fs.String("output", "", "destination; default is the user cache")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	result, err := secureboot.DownloadMicrosoftDBX(ctx, *arch, *output)
	if err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	fmt.Printf("Downloaded Microsoft DBX to %s\nSource: %s\nSHA-256: %s\nEntries: %d hashes, %d certificates\n", result.Path, result.URL, result.SHA256, result.Summary.SHA256Hashes, result.Summary.X509Certificates)
	return nil
}

func runDBXCheck(args []string) error {
	fs := flag.NewFlagSet("dbx check", flag.ContinueOnError)
	dbxPath := fs.String("dbx", "", "DBXUpdate.bin or raw DBX file")
	firmware := fs.Bool("firmware", false, "use the running firmware DBX variable")
	efiPath := fs.String("efi", "", "EFI PE/COFF bootloader to check")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *efiPath == "" {
		return errors.New("--efi is required")
	}
	if (*dbxPath == "") == !*firmware {
		return errors.New("select exactly one of --dbx or --firmware")
	}
	db, err := loadDBX(*dbxPath, *firmware)
	if err != nil {
		return err
	}
	result := secureboot.CheckPEFile(*efiPath, db)
	if *asJSON {
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			return err
		}
	} else {
		fmt.Printf("EFI image: %s\nAuthenticode SHA-256: %s\nDirect image hash revoked: %t\nEmbedded certificates checked: %d\nRevoked embedded certificate: %t\n", result.Path, result.AuthenticodeSHA256, result.DirectHashRevoked, result.EmbeddedCertificates, result.X509CertificateRevoked)
		if result.Error != "" {
			fmt.Printf("Check warning: %s\n", result.Error)
		}
	}
	if result.DirectHashRevoked || result.X509CertificateRevoked {
		return errors.New("EFI image is revoked by the selected DBX")
	}
	if result.Error != "" {
		return errors.New(result.Error)
	}
	return nil
}

func runDBXScan(args []string) error {
	fs := flag.NewFlagSet("dbx scan", flag.ContinueOnError)
	dbxPath := fs.String("dbx", "", "DBXUpdate.bin or raw DBX file")
	firmware := fs.Bool("firmware", false, "use the running firmware DBX variable")
	directory := fs.String("directory", "", "mounted media directory to scan")
	maxFiles := fs.Int("max-files", 512, "maximum boot files to scan")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *directory == "" {
		return errors.New("--directory is required")
	}
	if (*dbxPath == "") == !*firmware {
		return errors.New("select exactly one of --dbx or --firmware")
	}
	db, err := loadDBX(*dbxPath, *firmware)
	if err != nil {
		return err
	}
	results, err := secureboot.ScanEFIDirectory(*directory, db, *maxFiles)
	if err != nil {
		return err
	}
	if *asJSON {
		if err := json.NewEncoder(os.Stdout).Encode(results); err != nil {
			return err
		}
	} else {
		for _, result := range results {
			status := "OK"
			if result.DirectHashRevoked || result.X509CertificateRevoked {
				status = "REVOKED"
			} else if result.Error != "" {
				status = "ERROR"
			}
			fmt.Printf("%-8s %s\n", status, result.Path)
		}
	}
	for _, result := range results {
		if result.DirectHashRevoked || result.X509CertificateRevoked {
			return errors.New("one or more EFI images are revoked by the selected DBX")
		}
		if result.Error != "" {
			return errors.New("one or more EFI images could not be checked")
		}
	}
	return nil
}

func loadDBX(path string, firmware bool) (*secureboot.Database, error) {
	if firmware {
		return secureboot.FirmwareDBX()
	}
	return secureboot.ParseFile(path)
}

type acquireCatalogSummary struct {
	Schema      int    `json:"schema"`
	Generated   string `json:"generated"`
	Expires     string `json:"expires"`
	Images      int    `json:"images"`
	CatalogHash string `json:"catalog_sha256"`
}

func runAcquire(args []string) error {
	if len(args) == 0 {
		return errors.New("acquire requires verify, list, download, or channel")
	}
	switch args[0] {
	case "verify":
		return runAcquireVerify(args[1:])
	case "list":
		return runAcquireList(args[1:])
	case "download":
		return runAcquireDownload(args[1:])
	case "channel":
		return runAcquireChannel(args[1:])
	default:
		return fmt.Errorf("unknown acquire command %q", args[0])
	}
}

func runAcquireChannel(args []string) error {
	if len(args) == 0 {
		return errors.New("acquire channel requires verify, list, or download")
	}
	switch args[0] {
	case "verify":
		return runAcquireChannelVerify(args[1:])
	case "list":
		return runAcquireChannelList(args[1:])
	case "download":
		return runAcquireChannelDownload(args[1:])
	default:
		return fmt.Errorf("unknown acquire channel command %q", args[0])
	}
}

func channelFlags(name string) (*flag.FlagSet, *string, *string, *bool) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	config := fs.String("config", defaultAcquisitionChannelConfig, "package-owned acquisition channel configuration")
	cacheDir := fs.String("cache-dir", "", "override owner-only acquisition metadata cache")
	offline := fs.Bool("offline", false, "use only already verified, unexpired cached metadata")
	return fs, config, cacheDir, offline
}

func refreshAcquireChannel(config, cacheDir string, offline bool) (*acquisition.ChannelResult, error) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return acquisition.RefreshChannel(ctx, config, acquisition.ChannelOptions{
		CacheDir:                  cacheDir,
		Offline:                   offline,
		AllowCachedOnNetworkError: true,
	})
}

func runAcquireChannelVerify(args []string) error {
	fs, config, cacheDir, offline := channelFlags("acquire channel verify")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("acquire channel verify does not accept positional arguments")
	}
	result, err := refreshAcquireChannel(*config, *cacheDir, *offline)
	if err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	fmt.Printf("Built-in channel verified\nRoot: version %d, expires %s\nCatalog: version %d, generated %s, expires %s\nImages: %d\nSource: %s\n", result.RootVersion, result.RootExpires, result.CatalogVersion, result.CatalogGenerated, result.CatalogExpires, len(result.Images), channelSource(result.FromCache))
	return nil
}

func runAcquireChannelList(args []string) error {
	fs, config, cacheDir, offline := channelFlags("acquire channel list")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("acquire channel list does not accept positional arguments")
	}
	result, err := refreshAcquireChannel(*config, *cacheDir, *offline)
	if err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	fmt.Printf("Verified catalog version %d (%s; expires %s)\n", result.CatalogVersion, channelSource(result.FromCache), result.CatalogExpires)
	fmt.Printf("%-28s %-10s %-10s %-12s %s\n", "ID", "ARCH", "VERSION", "SIZE", "NAME")
	for _, image := range result.Images {
		fmt.Printf("%-28s %-10s %-10s %-12s %s\n", image.ID, image.Architecture, image.Version, humanBytes(image.Size), image.Name)
	}
	return nil
}

func runAcquireChannelDownload(args []string) error {
	fs, config, cacheDir, offline := channelFlags("acquire channel download")
	imageID := fs.String("id", "", "built-in catalog image id")
	output := fs.String("output", "", "destination file or existing directory")
	replace := fs.Bool("replace", false, "replace an existing different regular file")
	asJSON := fs.Bool("json", false, "output final JSON result")
	jsonProgress := fs.Bool("json-progress", false, "stream progress events as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("acquire channel download does not accept positional arguments")
	}
	if strings.TrimSpace(*imageID) == "" {
		return errors.New("--id is required")
	}
	channel, err := refreshAcquireChannel(*config, *cacheDir, *offline)
	if err != nil {
		return err
	}
	image, err := channel.Find(*imageID)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	emit := emitter{json: *jsonProgress}
	result, err := acquisition.Download(ctx, image, acquisition.DownloadOptions{
		Destination: *output,
		Replace:     *replace,
		Progress: func(progress acquisition.Progress) {
			if *jsonProgress {
				emit.event(jsonEvent{Event: "progress", Stage: "download", Done: progress.Done, Total: progress.Total, Rate: progress.BytesPerSec})
				return
			}
			printProgress("download", imaging.Progress{Done: progress.Done, Total: progress.Total, BytesPerSec: progress.BytesPerSec})
		},
	})
	if !*jsonProgress {
		fmt.Println()
	}
	if err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	status := "Downloaded"
	if result.Reused {
		status = "Already verified"
	}
	fmt.Printf("%s: %s\nSource: %s\nSize: %s\nSHA-256: %s\n", status, result.Path, result.URL, humanBytes(result.Size), result.SHA256)
	return nil
}

func channelSource(fromCache bool) string {
	if fromCache {
		return "verified cache"
	}
	return "network refresh"
}

func runAcquireVerify(args []string) error {
	fs := flag.NewFlagSet("acquire verify", flag.ContinueOnError)
	catalogPath := fs.String("catalog", "", "signed acquisition catalog JSON")
	signaturePath := fs.String("signature", "", "detached Ed25519 signature")
	publicKeyPath := fs.String("public-key", "", "trusted Ed25519 public key")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	catalog, err := loadAcquireCatalog(*catalogPath, *signaturePath, *publicKeyPath)
	if err != nil {
		return err
	}
	summary := acquireCatalogSummary{Schema: catalog.Schema, Generated: catalog.GeneratedAt.Format(time.RFC3339), Expires: catalog.ExpiresAt.Format(time.RFC3339), Images: len(catalog.Images), CatalogHash: catalog.SHA256}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(summary)
	}
	fmt.Printf("Catalog signature valid\nSchema: %d\nGenerated: %s\nExpires: %s\nImages: %d\nCatalog SHA-256: %s\n", summary.Schema, summary.Generated, summary.Expires, summary.Images, summary.CatalogHash)
	return nil
}

func runAcquireList(args []string) error {
	fs := flag.NewFlagSet("acquire list", flag.ContinueOnError)
	catalogPath := fs.String("catalog", "", "signed acquisition catalog JSON")
	signaturePath := fs.String("signature", "", "detached Ed25519 signature")
	publicKeyPath := fs.String("public-key", "", "trusted Ed25519 public key")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	catalog, err := loadAcquireCatalog(*catalogPath, *signaturePath, *publicKeyPath)
	if err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(catalog.Images)
	}
	fmt.Printf("%-28s %-10s %-10s %-12s %s\n", "ID", "ARCH", "VERSION", "SIZE", "NAME")
	for _, image := range catalog.Images {
		fmt.Printf("%-28s %-10s %-10s %-12s %s\n", image.ID, image.Architecture, image.Version, humanBytes(image.Size), image.Name)
	}
	return nil
}

func runAcquireDownload(args []string) error {
	fs := flag.NewFlagSet("acquire download", flag.ContinueOnError)
	catalogPath := fs.String("catalog", "", "signed acquisition catalog JSON")
	signaturePath := fs.String("signature", "", "detached Ed25519 signature")
	publicKeyPath := fs.String("public-key", "", "trusted Ed25519 public key")
	imageID := fs.String("id", "", "catalog image id")
	output := fs.String("output", "", "destination file or existing directory")
	replace := fs.Bool("replace", false, "replace an existing different regular file")
	asJSON := fs.Bool("json", false, "output final JSON result")
	jsonProgress := fs.Bool("json-progress", false, "stream progress events as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*imageID) == "" {
		return errors.New("--id is required")
	}
	catalog, err := loadAcquireCatalog(*catalogPath, *signaturePath, *publicKeyPath)
	if err != nil {
		return err
	}
	image, err := catalog.Find(*imageID)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	emit := emitter{json: *jsonProgress}
	result, err := acquisition.Download(ctx, image, acquisition.DownloadOptions{
		Destination: *output,
		Replace:     *replace,
		Progress: func(progress acquisition.Progress) {
			if *jsonProgress {
				emit.event(jsonEvent{Event: "progress", Stage: "download", Done: progress.Done, Total: progress.Total, Rate: progress.BytesPerSec})
				return
			}
			printProgress("download", imaging.Progress{Done: progress.Done, Total: progress.Total, BytesPerSec: progress.BytesPerSec})
		},
	})
	if !*jsonProgress {
		fmt.Println()
	}
	if err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	status := "Downloaded"
	if result.Reused {
		status = "Already verified"
	}
	fmt.Printf("%s: %s\nSource: %s\nSize: %s\nSHA-256: %s\n", status, result.Path, result.URL, humanBytes(result.Size), result.SHA256)
	return nil
}

func loadAcquireCatalog(catalogPath, signaturePath, publicKeyPath string) (*acquisition.VerifiedCatalog, error) {
	if strings.TrimSpace(catalogPath) == "" || strings.TrimSpace(signaturePath) == "" || strings.TrimSpace(publicKeyPath) == "" {
		return nil, errors.New("--catalog, --signature, and --public-key are required")
	}
	catalogBytes, err := readLimitedRegularFile(catalogPath, acquisition.MaxCatalogBytes)
	if err != nil {
		return nil, fmt.Errorf("read acquisition catalog: %w", err)
	}
	signatureBytes, err := readLimitedRegularFile(signaturePath, 16*1024)
	if err != nil {
		return nil, fmt.Errorf("read catalog signature: %w", err)
	}
	publicKeyBytes, err := readLimitedRegularFile(publicKeyPath, 16*1024)
	if err != nil {
		return nil, fmt.Errorf("read catalog public key: %w", err)
	}
	return acquisition.VerifyCatalog(catalogBytes, signatureBytes, publicKeyBytes, time.Now())
}

func readLimitedRegularFile(path string, limit int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("input is not a regular file")
	}
	if info.Size() < 0 || info.Size() > int64(limit) {
		return nil, fmt.Errorf("input exceeds the %d-byte limit", limit)
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, fmt.Errorf("input exceeds the %d-byte limit", limit)
	}
	return data, nil
}

func runQualify(args []string) error {
	if len(args) == 0 {
		return errors.New("qualify requires start or verify")
	}
	switch args[0] {
	case "start", "verify":
		return runQualifyPhase(args[0], args[1:])
	default:
		return fmt.Errorf("unknown qualify command %q", args[0])
	}
}

func runQualifyPhase(phase string, args []string) error {
	flags := flag.NewFlagSet("qualify "+phase, flag.ContinueOnError)
	recordPath := flags.String("record", "", "qualification creation record on the persistent USB")
	outputPath := flags.String("output", "", "qualification evidence JSON output")
	stateDirectory := flags.String("state-dir", "", "private persistent state directory for the reboot marker")
	asJSON := flags.Bool("json", false, "output evidence as JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*recordPath) == "" || strings.TrimSpace(*outputPath) == "" {
		return errors.New("--record and --output are required")
	}
	options := qualification.ProbeOptions{StateDirectory: *stateDirectory}
	var (
		evidence qualification.Evidence
		err      error
	)
	switch phase {
	case "start":
		evidence, err = qualification.Start(*recordPath, options)
	case "verify":
		evidence, err = qualification.Verify(*recordPath, options)
	default:
		return fmt.Errorf("unknown qualification phase %q", phase)
	}
	if err != nil {
		return err
	}
	reportHash, err := qualification.WriteEvidence(*outputPath, evidence)
	if err != nil {
		return fmt.Errorf("write qualification evidence: %w", err)
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(struct {
			Evidence     qualification.Evidence `json:"evidence"`
			ReportPath   string                 `json:"report_path"`
			ReportSHA256 string                 `json:"report_sha256"`
		}{Evidence: evidence, ReportPath: *outputPath, ReportSHA256: reportHash})
	}
	fmt.Printf("Qualification evidence written to %s\n", *outputPath)
	fmt.Printf("  Report SHA-256: %s\n", reportHash)
	fmt.Printf("  Creation record SHA-256: %s\n", evidence.CreationRecordSHA256)
	fmt.Printf("  Media/runtime architecture: %s / %s\n", evidence.MediaArchitecture, evidence.RuntimeArchitecture)
	fmt.Printf("  UEFI boot: %t\n", evidence.UEFIBooted)
	fmt.Printf("  Persistence parameter: %t\n", evidence.PersistenceParameter)
	fmt.Printf("  Overlay root: %t (%s)\n", evidence.RootOverlay, evidence.RootFilesystem)
	if phase == "start" {
		fmt.Println("  Reboot survival: pending; reboot this same USB, then run qualify verify.")
	} else {
		fmt.Printf("  Reboot survival: %t\n", evidence.RebootSurvivalConfirmed)
		fmt.Println("  This confirms persistence across one reboot; it does not by itself qualify every ARM64 firmware or device.")
	}
	return nil
}

func runHash(args []string) error {
	if len(args) != 1 {
		return errors.New("hash requires exactly one file")
	}
	h, err := imaging.SHA256File(args[0])
	if err != nil {
		return err
	}
	fmt.Printf("%s  %s\n", h, args[0])
	return nil
}
func confirmDestructive(path string) error {
	fmt.Printf("\nALL DATA ON %s WILL BE DESTROYED.\nType exactly 'ERASE %s' to continue: ", path, path)
	s := bufio.NewScanner(os.Stdin)
	if !s.Scan() {
		return errors.New("confirmation cancelled")
	}
	if strings.TrimSpace(s.Text()) != "ERASE "+path {
		return errors.New("confirmation did not match; cancelled")
	}
	return nil
}
func printProgress(label string, p imaging.Progress) {
	percent := 0.0
	if p.Total > 0 {
		percent = float64(p.Done) * 100 / float64(p.Total)
	}
	fmt.Printf("\r%-6s %6.2f%%  %s / %s  %s/s", label, percent, humanBytes(p.Done), humanBytes(p.Total), humanBytes(uint64(p.BytesPerSec)))
}
func parseClusterSize(value string) (uint64, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "auto", "0":
		return 0, nil
	case "4096", "8192", "16384", "32768":
		parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		if err != nil {
			return 0, err
		}
		return parsed, nil
	default:
		return 0, errors.New("--cluster-size must be auto, 4096, 8192, 16384, or 32768")
	}
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit && exp < 5; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
