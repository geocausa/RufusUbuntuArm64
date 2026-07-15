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
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/geocausa/RufusArm64/internal/device"
	"github.com/geocausa/RufusArm64/internal/imaging"
	"github.com/geocausa/RufusArm64/internal/safety"
	"github.com/geocausa/RufusArm64/internal/sourcefile"
	"github.com/geocausa/RufusArm64/internal/windowsconfig"
	"github.com/geocausa/RufusArm64/internal/windowsmedia"
)

var version = "0.4.0-dev"

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
  rufusarm64-cli list [--json]
  rufusarm64-cli inspect --image FILE [--json]
  sudo rufusarm64-cli write --image FILE --device /dev/DEVICE [--verify]

The automatic mode writes Linux ISOHybrid/raw images directly and creates
standard Windows installation USBs using FAT32 and automatic WIM splitting.
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
	Mode            string `json:"mode"`
	Recognized      bool   `json:"recognized"`
	PartitionScheme string `json:"partition_scheme"`
	TargetSystem    string `json:"target_system"`
	FileSystem      string `json:"filesystem"`
	WindowsOptions  bool   `json:"windows_options"`
	Description     string `json:"description"`
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
	inspection, inspectErr := imaging.InspectOpenFile(file)
	closeErr := file.Close()
	if inspectErr != nil {
		return inspectErr
	}
	if closeErr != nil {
		return closeErr
	}
	result := inspectResult{Recognized: inspection.Recognized()}
	mode, err := selectWriteMode("auto", inspection, false)
	if err != nil {
		result.Description = err.Error()
	} else if mode == "windows" {
		result.Mode = "windows"
		result.PartitionScheme = "GPT"
		result.TargetSystem = "UEFI"
		result.FileSystem = "FAT32"
		result.WindowsOptions = true
		result.Description = "Standard Windows UEFI installation media"
	} else {
		result.Mode = "raw"
		result.PartitionScheme = "From image"
		result.TargetSystem = "From image"
		result.FileSystem = "From image"
		result.Description = "Raw/ISOHybrid image; embedded layout will be preserved"
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	fmt.Printf("Mode: %s\nPartition scheme: %s\nTarget system: %s\nFile system: %s\n", result.Mode, result.PartitionScheme, result.TargetSystem, result.FileSystem)
	if result.Description != "" {
		fmt.Println(result.Description)
	}
	if !result.Recognized {
		return errors.New("image is not recognized")
	}
	return err
}

func runWrite(args []string) error {
	fs := flag.NewFlagSet("write", flag.ContinueOnError)
	imagePath := fs.String("image", "", "image or ISO file")
	devicePath := fs.String("device", "", "whole target disk")
	mode := fs.String("mode", "auto", "auto, raw, or windows")
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
	volumeLabel := fs.String("volume-label", "RUFUSARM64", "FAT32 volume label for Windows media")
	winBypassHardware := fs.Bool("win-bypass-hardware", false, "bypass Windows TPM, Secure Boot, and RAM checks")
	winBypassOnline := fs.Bool("win-bypass-online-account", false, "remove Windows online-account requirement")
	winLocalUser := fs.String("win-local-user", "", "create a local Windows administrator account")
	winPrivacy := fs.Bool("win-reduce-data-collection", false, "reduce Windows setup data collection and recommendations")
	winDisableBitLocker := fs.Bool("win-disable-bitlocker", false, "disable automatic Windows device encryption provisioning")
	winLocale := fs.String("win-locale", "", "apply a Windows regional locale, such as en-GB")
	winTimeZone := fs.String("win-timezone", "", "apply a Windows time-zone name")
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
	case "auto", "raw", "windows":
	default:
		return errors.New("--mode must be auto, raw, or windows")
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
	resolvedImage, sourceIdentity, err := sourcefile.Inspect(*imagePath)
	if err != nil {
		return err
	}
	imagePath = &resolvedImage
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
	winOptions := windowsconfig.Options{
		BypassHardwareChecks: *winBypassHardware,
		BypassOnlineAccount:  *winBypassOnline,
		LocalAccount:         *winLocalUser,
		ReduceDataCollection: *winPrivacy,
		DisableBitLocker:     *winDisableBitLocker,
		Locale:               *winLocale,
		TimeZone:             *winTimeZone,
	}
	if selectedMode != "windows" && winOptions.Enabled() {
		return errors.New("Windows setup options can only be used with a supported Windows installation ISO")
	}
	if err := windowsconfig.Validate(winOptions); err != nil {
		return err
	}

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
	if err := safety.EnsureImageNotOnTarget(*imagePath, resolved); err != nil {
		return err
	}
	if selectedMode == "raw" && imageSize > dev.Size {
		return fmt.Errorf("image is %s but target is only %s", humanBytes(imageSize), humanBytes(dev.Size))
	}

	out.event(jsonEvent{Event: "preflight", Stage: "preflight", Message: fmt.Sprintf("Image: %s; target: %s (%s)", filepath.Base(*imagePath), resolved, humanBytes(dev.Size))})
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

	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancelCleanup, err := safety.CancellationContext(signalCtx, *cancelFile)
	if err != nil {
		return err
	}
	defer cancelCleanup()
	finalTargetCheck := func(source *os.File) error {
		fresh, currentID, err := safety.RevalidateTarget(resolved, selectedIdentity, *allowFixed)
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

	if selectedMode == "windows" {
		out.event(jsonEvent{Event: "stage", Stage: "windows", Message: "Creating Windows installation media…"})
		err := windowsmedia.Create(ctx, *imagePath, resolved, windowsmedia.Options{
			TargetSize:        dev.Size,
			Verify:            *verify,
			ExpectedDeviceID:  kernelDeviceID,
			ExpectedSource:    sourceIdentity,
			RequireARM64:      runtime.GOARCH == "arm64" && !*allowForeignArchitecture,
			VolumeLabel:       *volumeLabel,
			Customizations:    winOptions,
			BeforeDestructive: finalTargetCheck,
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
	if err := finalTargetCheck(rawSource); err != nil {
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
			return finalTargetCheck(source)
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
	if err := finalTargetCheck(rawSource); err != nil {
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
	if requested != "auto" && requested != "raw" && requested != "windows" {
		return "", errors.New("mode must be auto, raw, or windows")
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
	if err := safety.FlushBuffers(ctx, resolved); err != nil {
		return fmt.Errorf("flush target buffers before verification: %w", err)
	}
	hash, err := imaging.VerifyImageWithOptions(ctx, *image, resolved, imaging.VerifyOptions{ExpectedDeviceID: kernelDeviceID, ExpectedDeviceSize: verifyDevice.Size}, func(p imaging.Progress) { printProgress("verify", p) })
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
